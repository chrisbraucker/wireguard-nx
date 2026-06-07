#include "ipc_service.hpp"

#include "config_loader.hpp"
#include "logger.hpp"
#include "wgnx/platform/udp.hpp"
#include "wgnx/platform/work.hpp"
#include "wireguard/device.hpp"
#include "wireguard/handshake.hpp"
#include "wireguard/session.hpp"
#include "wireguard/timers.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <mutex>

namespace wgnx::sysmodule {

namespace {

using ServerManager = ams::sf::hipc::ServerManager<1>;

constinit ams::util::TypedStorage<ServerManager> g_server_manager_storage = {};
constinit ServerManager *g_server_manager = nullptr;
constinit ams::sf::UnmanagedServiceObject<wgnx::sysmodule::IControlService, wgnx::sysmodule::ControlService> g_control_service_object;

struct DaemonState {
    std::array<wgnx::PeerConfigEntry, wgnx::MaxPeers> configured_peers{};
    struct PeerConfigDerivedInfo {
        char derived_public_key[64]{};
        bool has_derived_public_key{false};
    };
    std::array<PeerConfigDerivedInfo, wgnx::MaxPeers> config_derived{};
    struct PeerRuntimeInfo {
        wgnx::PeerRuntimeState state{wgnx::PeerRuntimeState::Inactive};
        wgnx::PeerErrorStage error_stage{wgnx::PeerErrorStage::None};
        std::uint32_t last_error_code{0};
        std::uint16_t persistent_keepalive_interval{0};
        std::uint32_t state_ticks{0};
        std::uint32_t activation_generation{0};
        std::uint32_t handshake_send_attempts{0};
        std::int32_t last_handshake_seconds{-1};
        std::int32_t last_rx_seconds{-1};
        std::int32_t last_tx_seconds{-1};
        std::uint64_t rx_bytes{0};
        std::uint64_t tx_bytes{0};
        wgnx::platform::endpoint resolved_endpoint{};
        char resolved_endpoint_text[sizeof(wgnx::PeerInfo::resolved_endpoint)]{};
        bool established{false};
        bool has_resolved_endpoint{false};
        wgnx::platform::socket_handle socket{wgnx::platform::InvalidSocket};
    };
    std::array<PeerRuntimeInfo, wgnx::MaxPeers> runtime{};
    struct PeerProtocolInfo {
        wgnx::wireguard::wg_device device{};
        bool instantiated{false};
    };
    std::array<PeerProtocolInfo, wgnx::MaxPeers> protocol{};
    std::uint32_t peer_count{0};
    std::uint32_t next_activation_generation{1};
    std::int32_t active_peer_index{-1};
    std::int32_t auto_start_peer_index{-1};
    bool initialized{false};
};

struct ResolveRequest {
    bool pending{false};
    std::size_t peer_index{0};
    std::uint32_t activation_generation{0};
    char endpoint[sizeof(wgnx::PeerConfigEntry::endpoint)]{};
};

constinit DaemonState g_state = {};
ams::os::Mutex g_state_mutex(false);
ResolveRequest g_resolve_request = {};
struct ResolveDispatcher {
    wgnx::platform::work_struct work{};
};
constinit ResolveDispatcher g_resolve_dispatcher = {};
wgnx::platform::workqueue_struct *g_resolver_workqueue = nullptr;
struct ReceiveDispatcher {
    wgnx::platform::work_struct work{};
};
constinit ReceiveDispatcher g_receive_dispatcher = {};
wgnx::platform::workqueue_struct *g_receive_workqueue = nullptr;
struct TimerActionDispatcher {
    wgnx::wireguard::TimerHook hook{wgnx::wireguard::TimerHook::RetransmitHandshake};
    wgnx::platform::work_struct work{};
    wgnx::platform::timer_list timer{};
};
constinit TimerActionDispatcher g_retransmit_dispatcher = {
    .hook = wgnx::wireguard::TimerHook::RetransmitHandshake,
};
constinit TimerActionDispatcher g_keepalive_dispatcher = {
    .hook = wgnx::wireguard::TimerHook::SendKeepalive,
};
constinit TimerActionDispatcher g_rekey_dispatcher = {
    .hook = wgnx::wireguard::TimerHook::Rekey,
};
wgnx::platform::workqueue_struct *g_timer_action_workqueue = nullptr;

constexpr inline wgnx::platform::jiffies_t SimulatedHandshakeRetransmitJiffies = 5U * wgnx::platform::HZ;
constexpr inline wgnx::platform::jiffies_t SimulatedRekeyJiffies = 120U * wgnx::platform::HZ;
constexpr inline std::uint32_t MaxHandshakeSendAttempts = 5;
constexpr inline std::size_t ReceivePacketCapacity = 4096;

void CloseRuntimeSocket(DaemonState::PeerRuntimeInfo *runtime) {
    if (runtime == nullptr || runtime->socket == wgnx::platform::InvalidSocket) {
        return;
    }

    wgnx::platform::udp_close(runtime->socket);
    runtime->socket = wgnx::platform::InvalidSocket;
}

wgnx::PeerErrorCode MapSocketErrorToPeerErrorCode(wgnx::platform::socket_error error) {
    switch (error) {
        case wgnx::platform::socket_error::none:
            return wgnx::PeerErrorCode::None;
        case wgnx::platform::socket_error::transport_init_failed:
            return wgnx::PeerErrorCode::TransportInitFailed;
        case wgnx::platform::socket_error::open_failed:
            return wgnx::PeerErrorCode::TransportOpenFailed;
        case wgnx::platform::socket_error::send_failed:
            return wgnx::PeerErrorCode::TransportSendFailed;
        case wgnx::platform::socket_error::receive_failed:
            return wgnx::PeerErrorCode::TransportReceiveFailed;
        case wgnx::platform::socket_error::invalid_endpoint:
            return wgnx::PeerErrorCode::InternalFailure;
    }

    return wgnx::PeerErrorCode::InternalFailure;
}

void CancelAllTransportTimers();

void ResetProtocolPeer(std::size_t peer_index) {
    auto &protocol = g_state.protocol[peer_index];
    CancelAllTransportTimers();
    if (protocol.instantiated) {
        if (wgnx::wireguard::wg_peer *peer = wgnx::wireguard::wg_device_first_peer(std::addressof(protocol.device))) {
            wgnx::wireguard::wg_timers_cancel_all(std::addressof(peer->timers), peer->name);
        }
    }

    wgnx::wireguard::wg_device_reset(std::addressof(protocol.device));
    protocol.instantiated = false;
}

wgnx::wireguard::wg_peer *GetProtocolPeer(std::size_t peer_index) {
    auto &protocol = g_state.protocol[peer_index];
    if (!protocol.instantiated) {
        return nullptr;
    }

    return wgnx::wireguard::wg_device_first_peer(std::addressof(protocol.device));
}

wgnx::PeerErrorCode InstantiateProtocolPeer(std::size_t peer_index, std::uint32_t activation_generation) {
    auto &protocol = g_state.protocol[peer_index];
    if (!wgnx::wireguard::wg_device_init_from_config_entry(
            std::addressof(protocol.device),
            g_state.configured_peers[peer_index])) {
        logger::Log(
            "Failed to instantiate WG protocol peer for '%s'",
            g_state.configured_peers[peer_index].name);
        return wgnx::PeerErrorCode::KeyInvalid;
    }
    protocol.instantiated = true;

    if (wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index)) {
        const std::uint32_t local_index = wgnx::wireguard::wg_device_allocate_index(std::addressof(protocol.device));
        wgnx::wireguard::noise_handshake_set_local_index(std::addressof(peer->handshake), local_index);
        wgnx::wireguard::wg_device_register_handshake_index(std::addressof(protocol.device), local_index);
        logger::Log(
            "Instantiated WG protocol peer '%s' activation=%u local_index=0x%08x",
            peer->name,
            activation_generation,
            local_index);
    }

    return wgnx::PeerErrorCode::None;
}

wgnx::PeerErrorCode BindResolvedEndpointToProtocolPeer(std::size_t peer_index) {
    auto &runtime = g_state.runtime[peer_index];
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr || !runtime.has_resolved_endpoint) {
        return wgnx::PeerErrorCode::InternalFailure;
    }

    wgnx::wireguard::wg_peer_set_resolved_endpoint(
        peer,
        runtime.resolved_endpoint,
        runtime.resolved_endpoint_text);
    if (!wgnx::wireguard::noise_handshake_create_initiation(
            std::addressof(peer->last_initiation),
            peer)) {
        logger::Log(
            "Failed to create real WG handshake initiation for peer '%s'",
            peer->name);
        return wgnx::PeerErrorCode::HandshakeInitFailed;
    }
    return wgnx::PeerErrorCode::None;
}

wgnx::PeerErrorCode OpenRuntimeSocket(std::size_t peer_index) {
    auto &runtime = g_state.runtime[peer_index];
    CloseRuntimeSocket(std::addressof(runtime));

    logger::Log(
        "Opening UDP socket for peer %zu family=%s endpoint=%s",
        peer_index,
        wgnx::GetPeerResolvedFamilyName(
            static_cast<wgnx::PeerResolvedFamily>(runtime.resolved_endpoint.family)),
        runtime.resolved_endpoint_text);

    const auto open_error = wgnx::platform::udp_open(
        std::addressof(runtime.socket),
        runtime.resolved_endpoint.family);
    if (open_error != wgnx::platform::socket_error::none) {
        runtime.socket = wgnx::platform::InvalidSocket;
        logger::Log(
            "Failed to open UDP socket for peer %zu endpoint=%s err=%u",
            peer_index,
            runtime.resolved_endpoint_text,
            static_cast<unsigned int>(open_error));
        return MapSocketErrorToPeerErrorCode(open_error);
    }

    logger::Log(
        "Opened UDP socket for peer %zu family=%s endpoint=%s",
        peer_index,
        wgnx::GetPeerResolvedFamilyName(
            static_cast<wgnx::PeerResolvedFamily>(runtime.resolved_endpoint.family)),
        runtime.resolved_endpoint_text);
    return wgnx::PeerErrorCode::None;
}

wgnx::PeerErrorCode SendProtocolPeerInitiation(std::size_t peer_index) {
    auto &runtime = g_state.runtime[peer_index];
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr || !peer->has_last_initiation || !runtime.has_resolved_endpoint ||
        runtime.socket == wgnx::platform::InvalidSocket) {
        return wgnx::PeerErrorCode::InternalFailure;
    }

    wgnx::platform::static_packet_buffer<wgnx::wireguard::HandshakeInitiationSize> packet;
    if (wgnx::wireguard::SerializeHandshakeInitiation(
            std::addressof(packet.packet),
            peer->last_initiation) != wgnx::wireguard::ParseError::None) {
        return wgnx::PeerErrorCode::InternalFailure;
    }

    std::size_t sent = 0;
    const auto send_error = wgnx::platform::udp_send(
        runtime.socket,
        std::addressof(runtime.resolved_endpoint),
        packet.packet.data,
        packet.packet.len,
        std::addressof(sent));
    if (send_error != wgnx::platform::socket_error::none) {
        logger::Log(
            "Failed to send WG handshake initiation for peer %zu endpoint=%s err=%u",
            peer_index,
            runtime.resolved_endpoint_text,
            static_cast<unsigned int>(send_error));
        return MapSocketErrorToPeerErrorCode(send_error);
    }

    runtime.last_tx_seconds = 0;
    runtime.tx_bytes += sent;
    logger::Log(
        "Sent WG handshake initiation for peer %zu bytes=%zu endpoint=%s",
        peer_index,
        sent,
        runtime.resolved_endpoint_text);
    return wgnx::PeerErrorCode::None;
}

wgnx::PeerErrorCode SendProtocolPeerKeepalive(std::size_t peer_index) {
    auto &runtime = g_state.runtime[peer_index];
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr || !peer->current_keypair.valid || !runtime.has_resolved_endpoint ||
        runtime.socket == wgnx::platform::InvalidSocket) {
        return wgnx::PeerErrorCode::InternalFailure;
    }

    wgnx::platform::static_packet_buffer<
        wgnx::wireguard::TransportDataHeaderSize + wgnx::wireguard::NoiseMacSize>
        packet;
    if (!wgnx::wireguard::noise_create_keepalive_packet(
            std::addressof(packet.packet),
            peer->current_keypair)) {
        return wgnx::PeerErrorCode::InternalFailure;
    }

    ++peer->current_keypair.send_counter;

    std::size_t sent = 0;
    const auto send_error = wgnx::platform::udp_send(
        runtime.socket,
        std::addressof(runtime.resolved_endpoint),
        packet.packet.data,
        packet.packet.len,
        std::addressof(sent));
    if (send_error != wgnx::platform::socket_error::none) {
        logger::Log(
            "Failed to send WG keepalive for peer %zu endpoint=%s err=%u",
            peer_index,
            runtime.resolved_endpoint_text,
            static_cast<unsigned int>(send_error));
        return MapSocketErrorToPeerErrorCode(send_error);
    }

    runtime.last_tx_seconds = 0;
    runtime.tx_bytes += sent;
    logger::Log(
        "Sent WG keepalive for peer %zu bytes=%zu endpoint=%s",
        peer_index,
        sent,
        runtime.resolved_endpoint_text);
    return wgnx::PeerErrorCode::None;
}

TimerActionDispatcher *GetTimerDispatcher(wgnx::wireguard::TimerHook hook) {
    switch (hook) {
        case wgnx::wireguard::TimerHook::RetransmitHandshake:
            return std::addressof(g_retransmit_dispatcher);
        case wgnx::wireguard::TimerHook::SendKeepalive:
            return std::addressof(g_keepalive_dispatcher);
        case wgnx::wireguard::TimerHook::Rekey:
            return std::addressof(g_rekey_dispatcher);
        case wgnx::wireguard::TimerHook::ZeroKeyMaterial:
            break;
    }

    return nullptr;
}

void ScheduleProtocolTimer(std::size_t peer_index, wgnx::wireguard::TimerHook hook, wgnx::platform::jiffies_t expires) {
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr) {
        return;
    }

    wgnx::wireguard::wg_timers_cancel(
        std::addressof(peer->timers),
        hook,
        peer->name);
    wgnx::wireguard::wg_timers_schedule(
        std::addressof(peer->timers),
        hook,
        expires,
        peer->name);

    if (TimerActionDispatcher *dispatcher = GetTimerDispatcher(hook)) {
        static_cast<void>(wgnx::platform::mod_timer(std::addressof(dispatcher->timer), expires));
    }
}

void CancelProtocolTimer(std::size_t peer_index, wgnx::wireguard::TimerHook hook) {
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer != nullptr) {
        wgnx::wireguard::wg_timers_cancel(
            std::addressof(peer->timers),
            hook,
            peer->name);
    }

    if (TimerActionDispatcher *dispatcher = GetTimerDispatcher(hook)) {
        wgnx::platform::timer_delete(std::addressof(dispatcher->timer));
    }
}

void CancelAllTransportTimers() {
    if (g_state.active_peer_index < 0) {
        for (TimerActionDispatcher *dispatcher : {
                 std::addressof(g_retransmit_dispatcher),
                 std::addressof(g_keepalive_dispatcher),
                 std::addressof(g_rekey_dispatcher)}) {
            wgnx::platform::timer_delete(std::addressof(dispatcher->timer));
        }
        return;
    }

    const std::size_t peer_index = static_cast<std::size_t>(g_state.active_peer_index);
    CancelProtocolTimer(peer_index, wgnx::wireguard::TimerHook::RetransmitHandshake);
    CancelProtocolTimer(peer_index, wgnx::wireguard::TimerHook::SendKeepalive);
    CancelProtocolTimer(peer_index, wgnx::wireguard::TimerHook::Rekey);
}

void ScheduleProtocolSessionTimers(std::size_t peer_index, wgnx::wireguard::wg_peer *peer) {
    if (peer == nullptr) {
        return;
    }

    CancelProtocolTimer(peer_index, wgnx::wireguard::TimerHook::RetransmitHandshake);
    if (peer->persistent_keepalive_interval > 0) {
        ScheduleProtocolTimer(
            peer_index,
            wgnx::wireguard::TimerHook::SendKeepalive,
            wgnx::platform::get_jiffies_64() +
                static_cast<wgnx::platform::jiffies_t>(peer->persistent_keepalive_interval) * wgnx::platform::HZ);
    }
    ScheduleProtocolTimer(
        peer_index,
        wgnx::wireguard::TimerHook::Rekey,
        wgnx::platform::get_jiffies_64() + SimulatedRekeyJiffies);
}

bool PrepareRekeyInitiation(std::size_t peer_index) {
    auto &protocol = g_state.protocol[peer_index];
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr) {
        return false;
    }

    const std::uint32_t local_index = wgnx::wireguard::wg_device_allocate_index(std::addressof(protocol.device));
    if (local_index == 0) {
        return false;
    }

    wgnx::wireguard::noise_handshake_set_local_index(std::addressof(peer->handshake), local_index);
    wgnx::wireguard::noise_handshake_set_remote_index(std::addressof(peer->handshake), 0);
    wgnx::wireguard::wg_device_register_handshake_index(std::addressof(protocol.device), local_index);
    return wgnx::wireguard::noise_handshake_create_initiation(
        std::addressof(peer->last_initiation),
        peer);
}

wgnx::PeerErrorCode BeginProtocolPeerSession(std::size_t peer_index) {
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr) {
        return wgnx::PeerErrorCode::InternalFailure;
    }

    if (!peer->handshake_material.remote_ephemeral.valid ||
        !peer->handshake_material.chaining_key.valid) {
        return wgnx::PeerErrorCode::InternalFailure;
    }

    if (!wgnx::wireguard::noise_handshake_begin_session(std::addressof(g_state.protocol[peer_index].device), peer)) {
        return wgnx::PeerErrorCode::InternalFailure;
    }

    g_state.runtime[peer_index].handshake_send_attempts = 0;
    ScheduleProtocolSessionTimers(peer_index, peer);
    return wgnx::PeerErrorCode::None;
}

wgnx::PeerErrorCode RetryHandshakeSend(std::size_t peer_index, const char *reason) {
    auto &runtime = g_state.runtime[peer_index];
    if (runtime.handshake_send_attempts >= MaxHandshakeSendAttempts) {
        logger::Log(
            "WG handshake retry give-up for peer %zu endpoint=%s attempts=%u reason=%s",
            peer_index,
            runtime.resolved_endpoint_text,
            runtime.handshake_send_attempts,
            reason != nullptr ? reason : "none");
        if (runtime.state == wgnx::PeerRuntimeState::Handshaking) {
            return wgnx::PeerErrorCode::HandshakeTimedOut;
        }
        return wgnx::PeerErrorCode::None;
    }

    const wgnx::PeerErrorCode send_error = SendProtocolPeerInitiation(peer_index);
    if (send_error != wgnx::PeerErrorCode::None) {
        return send_error;
    }

    ++runtime.handshake_send_attempts;
    ScheduleProtocolTimer(
        peer_index,
        wgnx::wireguard::TimerHook::RetransmitHandshake,
        wgnx::platform::get_jiffies_64() + SimulatedHandshakeRetransmitJiffies);
    return wgnx::PeerErrorCode::None;
}

void FailProtocolPeer(std::size_t peer_index, const char *reason) {
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr) {
        return;
    }

    static_cast<void>(wgnx::wireguard::noise_handshake_transition(
        std::addressof(peer->handshake),
        wgnx::wireguard::HandshakeState::Failed,
        peer->name,
        reason));
    CancelAllTransportTimers();
    wgnx::wireguard::wg_timers_cancel_all(std::addressof(peer->timers), peer->name);
    wgnx::wireguard::wg_peer_scrub_transient_state(peer);
    wgnx::wireguard::wg_device_clear_index_registry(std::addressof(g_state.protocol[peer_index].device));
}

void ResetRuntimeMetrics(DaemonState::PeerRuntimeInfo *runtime) {
    if (runtime == nullptr) {
        return;
    }

    runtime->state_ticks = 0;
    runtime->handshake_send_attempts = 0;
    runtime->last_handshake_seconds = -1;
    runtime->last_rx_seconds = -1;
    runtime->last_tx_seconds = -1;
    runtime->rx_bytes = 0;
    runtime->tx_bytes = 0;
    runtime->established = false;
}

void ClearResolvedEndpoint(DaemonState::PeerRuntimeInfo *runtime) {
    if (runtime == nullptr) {
        return;
    }

    runtime->resolved_endpoint = {};
    runtime->resolved_endpoint_text[0] = '\0';
    runtime->has_resolved_endpoint = false;
}

void ClearRuntimeError(DaemonState::PeerRuntimeInfo *runtime) {
    if (runtime == nullptr) {
        return;
    }

    runtime->error_stage = wgnx::PeerErrorStage::None;
    runtime->last_error_code = static_cast<std::uint32_t>(wgnx::PeerErrorCode::None);
}

void SetResolvedEndpoint(DaemonState::PeerRuntimeInfo *runtime, const wgnx::platform::endpoint_resolution_result &resolved) {
    if (runtime == nullptr) {
        return;
    }

    runtime->resolved_endpoint = resolved.resolved;
    std::snprintf(runtime->resolved_endpoint_text, sizeof(runtime->resolved_endpoint_text), "%s", resolved.text);
    runtime->has_resolved_endpoint = true;
}

void RefreshDerivedPublicKey(std::size_t peer_index) {
    if (peer_index >= g_state.peer_count) {
        return;
    }

    auto &derived = g_state.config_derived[peer_index];
    derived = {};
    if (wgnx::wireguard::noise_derive_public_key_text(
            derived.derived_public_key,
            sizeof(derived.derived_public_key),
            g_state.configured_peers[peer_index].private_key)) {
        derived.has_derived_public_key = true;
    }
}

void SetPeerInactive(std::size_t peer_index) {
    const auto &config = g_state.configured_peers[peer_index];
    auto &runtime = g_state.runtime[peer_index];
    CloseRuntimeSocket(std::addressof(runtime));
    ResetProtocolPeer(peer_index);
    runtime = {};
    runtime.state = wgnx::PeerRuntimeState::Inactive;
    runtime.persistent_keepalive_interval = config.persistent_keepalive;
    ClearRuntimeError(&runtime);
    ResetRuntimeMetrics(&runtime);
    ClearResolvedEndpoint(&runtime);
}

std::uint32_t AllocateActivationGeneration() {
    const std::uint32_t generation = g_state.next_activation_generation++;
    if (g_state.next_activation_generation == 0) {
        g_state.next_activation_generation = 1;
    }
    return generation;
}

void SetPeerResolving(std::size_t peer_index, std::uint32_t activation_generation) {
    const auto &config = g_state.configured_peers[peer_index];
    auto &runtime = g_state.runtime[peer_index];
    runtime = {};
    runtime.state = wgnx::PeerRuntimeState::ResolvingEndpoint;
    runtime.persistent_keepalive_interval = config.persistent_keepalive;
    runtime.activation_generation = activation_generation;
    ClearRuntimeError(&runtime);
    ResetRuntimeMetrics(&runtime);
    ClearResolvedEndpoint(&runtime);
}

void SetPeerHandshaking(std::size_t peer_index) {
    auto &runtime = g_state.runtime[peer_index];
    runtime.state = wgnx::PeerRuntimeState::Handshaking;
    ClearRuntimeError(&runtime);
    runtime.state_ticks = 0;
    runtime.last_tx_seconds = 0;
}

void SetPeerActive(std::size_t peer_index) {
    auto &runtime = g_state.runtime[peer_index];
    runtime.state = wgnx::PeerRuntimeState::Active;
    ClearRuntimeError(&runtime);
    runtime.state_ticks = 0;
    runtime.established = true;
    runtime.last_handshake_seconds = 0;
    runtime.last_rx_seconds = 0;
}

void SetPeerError(std::size_t peer_index, wgnx::PeerErrorStage stage, wgnx::PeerErrorCode code) {
    auto &runtime = g_state.runtime[peer_index];
    CloseRuntimeSocket(std::addressof(runtime));
    runtime.state = wgnx::PeerRuntimeState::Error;
    runtime.error_stage = stage;
    runtime.last_error_code = static_cast<std::uint32_t>(code);
    runtime.state_ticks = 0;
    runtime.established = false;
    FailProtocolPeer(peer_index, wgnx::GetPeerErrorCodeName(code));
}

wgnx::PeerErrorCode ValidatePeerConfiguration(const wgnx::PeerConfigEntry &config) {
    if (config.private_key[0] == '\0' || config.public_key[0] == '\0' || config.allowed_ips[0] == '\0') {
        return wgnx::PeerErrorCode::ConfigInvalid;
    }
    if (!wgnx::wireguard::noise_is_valid_encoded_key(config.private_key) ||
        !wgnx::wireguard::noise_is_valid_encoded_key(config.public_key) ||
        !wgnx::wireguard::noise_is_valid_encoded_key(config.preshared_key, true)) {
        return wgnx::PeerErrorCode::KeyInvalid;
    }
    if (config.endpoint[0] == '\0') {
        return wgnx::PeerErrorCode::EndpointMissing;
    }

    return wgnx::PeerErrorCode::None;
}

void QueueEndpointResolve(std::size_t peer_index) {
    const auto &config = g_state.configured_peers[peer_index];
    const auto &runtime = g_state.runtime[peer_index];
    g_resolve_request = {};
    g_resolve_request.pending = true;
    g_resolve_request.peer_index = peer_index;
    g_resolve_request.activation_generation = runtime.activation_generation;
    std::snprintf(g_resolve_request.endpoint, sizeof(g_resolve_request.endpoint), "%s", config.endpoint);
    static_cast<void>(wgnx::platform::queue_work(g_resolver_workqueue, std::addressof(g_resolve_dispatcher.work)));
}

void QueueReceiveWork() {
    if (g_receive_workqueue == nullptr) {
        return;
    }

    static_cast<void>(wgnx::platform::queue_work(g_receive_workqueue, std::addressof(g_receive_dispatcher.work)));
}

void StartPeerRuntime(std::size_t peer_index) {
    const auto &config = g_state.configured_peers[peer_index];
    const wgnx::PeerErrorCode config_error = ValidatePeerConfiguration(config);
    if (config_error == wgnx::PeerErrorCode::ConfigInvalid) {
        SetPeerError(peer_index, wgnx::PeerErrorStage::Config, config_error);
        return;
    }
    if (config_error != wgnx::PeerErrorCode::None) {
        SetPeerError(peer_index, wgnx::PeerErrorStage::ResolveEndpoint, config_error);
        return;
    }

    const std::uint32_t activation_generation = AllocateActivationGeneration();
    SetPeerResolving(peer_index, activation_generation);
    const wgnx::PeerErrorCode instantiate_error = InstantiateProtocolPeer(peer_index, activation_generation);
    if (instantiate_error != wgnx::PeerErrorCode::None) {
        SetPeerError(peer_index, wgnx::PeerErrorStage::Config, instantiate_error);
        return;
    }
    QueueEndpointResolve(peer_index);
    logger::Log("Queued endpoint resolution for peer %zu activation=%u endpoint='%s'",
        peer_index, activation_generation, config.endpoint);
}

void AdvanceAges(DaemonState::PeerRuntimeInfo *runtime) {
    if (runtime == nullptr) {
        return;
    }

    if (runtime->last_handshake_seconds >= 0) {
        ++runtime->last_handshake_seconds;
    }
    if (runtime->last_rx_seconds >= 0) {
        ++runtime->last_rx_seconds;
    }
    if (runtime->last_tx_seconds >= 0) {
        ++runtime->last_tx_seconds;
    }
}

wgnx::PeerInfo BuildPeerInfo(std::size_t peer_index) {
    const auto &config = g_state.configured_peers[peer_index];
    const auto &runtime = g_state.runtime[peer_index];

    wgnx::PeerInfo peer = {};
    std::snprintf(peer.name, sizeof(peer.name), "%s", config.name);
    std::snprintf(peer.address, sizeof(peer.address), "%s", config.address);
    std::snprintf(peer.endpoint, sizeof(peer.endpoint), "%s", config.endpoint);
    std::snprintf(peer.resolved_endpoint, sizeof(peer.resolved_endpoint), "%s", runtime.resolved_endpoint_text);
    std::snprintf(
        peer.derived_public_key,
        sizeof(peer.derived_public_key),
        "%s",
        g_state.config_derived[peer_index].has_derived_public_key ? g_state.config_derived[peer_index].derived_public_key : "");
    peer.last_handshake_seconds = runtime.last_handshake_seconds;
    peer.last_rx_seconds = runtime.last_rx_seconds;
    peer.last_tx_seconds = runtime.last_tx_seconds;
    peer.last_error_code = runtime.last_error_code;
    peer.persistent_keepalive_interval = runtime.persistent_keepalive_interval;
    peer.runtime_state = static_cast<std::uint8_t>(runtime.state);
    peer.error_stage = static_cast<std::uint8_t>(runtime.error_stage);
    peer.resolved_family = static_cast<std::uint8_t>(runtime.resolved_endpoint.family);
    peer.rx_bytes = runtime.rx_bytes;
    peer.tx_bytes = runtime.tx_bytes;
    peer.flags = 0;

    if (static_cast<std::int32_t>(peer_index) == g_state.active_peer_index) {
        peer.flags |= wgnx::PeerFlag_Active;
    }
    if (static_cast<std::int32_t>(peer_index) == g_state.auto_start_peer_index) {
        peer.flags |= wgnx::PeerFlag_AutoStart;
    }
    if (runtime.established) {
        peer.flags |= wgnx::PeerFlag_Established;
    }
    if (runtime.state == wgnx::PeerRuntimeState::Error) {
        peer.flags |= wgnx::PeerFlag_HasError;
    }
    if (runtime.has_resolved_endpoint) {
        peer.flags |= wgnx::PeerFlag_HasResolvedEndpoint;
    }

    return peer;
}

bool HasRuntimeErrors() {
    for (std::size_t i = 0; i < g_state.peer_count; ++i) {
        if (g_state.runtime[i].state == wgnx::PeerRuntimeState::Error) {
            return true;
        }
    }
    return false;
}

void InitializeState() {
    if (g_state.initialized) {
        return;
    }

    char auto_start_name[sizeof(wgnx::PeerInfo::name)] = {};
    const bool has_auto_start_name = LoadAutoStartPeerName(auto_start_name, sizeof(auto_start_name));

    wgnx::PeerConfigSet config{};
    if (LoadPeerConfig(&config)) {
        g_state.peer_count = static_cast<std::uint32_t>(config.peer_count);

        for (std::size_t i = 0; i < config.peer_count; ++i) {
            const auto &entry = config.peers[i];
            g_state.configured_peers[i] = entry;
            RefreshDerivedPublicKey(i);
            SetPeerInactive(i);

            if (has_auto_start_name && std::strncmp(entry.name, auto_start_name, sizeof(entry.name)) == 0) {
                g_state.auto_start_peer_index = static_cast<std::int32_t>(i);
            }
        }
    } else {
        g_state.peer_count = 0;
        g_state.auto_start_peer_index = -1;
        g_state.config_derived = {};
    }

    g_state.initialized = true;
    logger::Log("Initialized peer state with %u configured peer(s)", g_state.peer_count);
}

bool IsValidPeerIndex(std::int32_t peer_index) {
    return peer_index >= -1 && peer_index < static_cast<std::int32_t>(g_state.peer_count);
}

void TickActivePeer() {
    if (g_state.active_peer_index < 0) {
        return;
    }

    auto &runtime = g_state.runtime[static_cast<std::size_t>(g_state.active_peer_index)];
    AdvanceAges(&runtime);
    ++runtime.state_ticks;

    switch (runtime.state) {
        case wgnx::PeerRuntimeState::Inactive:
            break;
        case wgnx::PeerRuntimeState::ResolvingEndpoint:
            break;
        case wgnx::PeerRuntimeState::Handshaking:
            break;
        case wgnx::PeerRuntimeState::Active:
            break;
        case wgnx::PeerRuntimeState::Error:
            break;
    }
}

bool DequeueResolveRequest(ResolveRequest *out_request) {
    std::scoped_lock lock(g_state_mutex);
    if (!g_resolve_request.pending || out_request == nullptr) {
        return false;
    }

    *out_request = g_resolve_request;
    g_resolve_request.pending = false;
    return true;
}

bool SnapshotReceiveRuntime(
    std::size_t *out_peer_index,
    std::uint32_t *out_activation_generation,
    wgnx::platform::socket_handle *out_socket) {
    if (out_peer_index == nullptr || out_activation_generation == nullptr || out_socket == nullptr) {
        return false;
    }

    std::scoped_lock lock(g_state_mutex);
    if (g_state.active_peer_index < 0) {
        return false;
    }

    const std::size_t peer_index = static_cast<std::size_t>(g_state.active_peer_index);
    const auto &runtime = g_state.runtime[peer_index];
    if ((runtime.state != wgnx::PeerRuntimeState::Handshaking &&
         runtime.state != wgnx::PeerRuntimeState::Active) ||
        runtime.socket == wgnx::platform::InvalidSocket) {
        return false;
    }

    *out_peer_index = peer_index;
    *out_activation_generation = runtime.activation_generation;
    *out_socket = runtime.socket;
    return true;
}

void CommitResolveResult(const ResolveRequest &request, const wgnx::platform::endpoint_resolution_result &result) {
    std::scoped_lock lock(g_state_mutex);
    if (request.peer_index >= g_state.peer_count) {
        return;
    }

    auto &runtime = g_state.runtime[request.peer_index];
    if (g_state.active_peer_index != static_cast<std::int32_t>(request.peer_index) ||
        runtime.activation_generation != request.activation_generation ||
        runtime.state != wgnx::PeerRuntimeState::ResolvingEndpoint) {
        return;
    }

    if (!result.success) {
        SetPeerError(request.peer_index, result.error_stage, result.error_code);
        logger::Log("Endpoint resolution failed for peer %zu activation=%u stage=%s code=%s",
            request.peer_index,
            request.activation_generation,
            wgnx::GetPeerErrorStageName(result.error_stage),
            wgnx::GetPeerErrorCodeName(result.error_code));
        return;
    }

    SetResolvedEndpoint(std::addressof(runtime), result);
    const wgnx::PeerErrorCode handshake_error = BindResolvedEndpointToProtocolPeer(request.peer_index);
    if (handshake_error != wgnx::PeerErrorCode::None) {
        SetPeerError(request.peer_index, wgnx::PeerErrorStage::Handshake, handshake_error);
        return;
    }
    const wgnx::PeerErrorCode socket_error = OpenRuntimeSocket(request.peer_index);
    if (socket_error != wgnx::PeerErrorCode::None) {
        SetPeerError(request.peer_index, wgnx::PeerErrorStage::Transport, socket_error);
        return;
    }
    const wgnx::PeerErrorCode send_error = SendProtocolPeerInitiation(request.peer_index);
    if (send_error != wgnx::PeerErrorCode::None) {
        SetPeerError(request.peer_index, wgnx::PeerErrorStage::Transport, send_error);
        return;
    }
    runtime.handshake_send_attempts = 1;
    ScheduleProtocolTimer(
        request.peer_index,
        wgnx::wireguard::TimerHook::RetransmitHandshake,
        wgnx::platform::get_jiffies_64() + SimulatedHandshakeRetransmitJiffies);
    SetPeerHandshaking(request.peer_index);
    QueueReceiveWork();
    logger::Log("Endpoint resolved for peer %zu activation=%u -> %s",
        request.peer_index,
        request.activation_generation,
        runtime.resolved_endpoint_text);
}

void CommitReceivedPacket(
    std::size_t peer_index,
    std::uint32_t activation_generation,
    wgnx::platform::socket_handle socket,
    const wgnx::platform::packet_buffer *packet,
    const wgnx::platform::endpoint &source) {
    std::scoped_lock lock(g_state_mutex);
    if (peer_index >= g_state.peer_count || g_state.active_peer_index != static_cast<std::int32_t>(peer_index)) {
        return;
    }

    auto &runtime = g_state.runtime[peer_index];
    if (runtime.activation_generation != activation_generation ||
        runtime.socket != socket ||
        (runtime.state != wgnx::PeerRuntimeState::Handshaking &&
         runtime.state != wgnx::PeerRuntimeState::Active)) {
        return;
    }

    runtime.rx_bytes += packet->len;
    runtime.last_rx_seconds = 0;

    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr) {
        SetPeerError(peer_index, wgnx::PeerErrorStage::Internal, wgnx::PeerErrorCode::InternalFailure);
        return;
    }

    const auto outcome = wgnx::wireguard::noise_handshake_consume_incoming_packet(
        packet,
        std::addressof(g_state.protocol[peer_index].device),
        peer);
    logger::Log(
        "Received UDP packet for peer %zu bytes=%zu source_family=%s outcome=%s",
        peer_index,
        packet->len,
        wgnx::GetPeerResolvedFamilyName(static_cast<wgnx::PeerResolvedFamily>(source.family)),
        wgnx::wireguard::GetHandshakePacketOutcomeName(outcome));

    switch (outcome) {
        case wgnx::wireguard::HandshakePacketOutcome::Invalid:
            return;
        case wgnx::wireguard::HandshakePacketOutcome::CookieReplyConsumed: {
            const wgnx::PeerErrorCode retry_error = RetryHandshakeSend(peer_index, "cookie reply");
            if (retry_error == wgnx::PeerErrorCode::None) {
                return;
            }
            SetPeerError(
                peer_index,
                retry_error == wgnx::PeerErrorCode::HandshakeTimedOut
                    ? wgnx::PeerErrorStage::Handshake
                    : wgnx::PeerErrorStage::Transport,
                retry_error);
            return;
        }
        case wgnx::wireguard::HandshakePacketOutcome::ResponseConsumed: {
            const wgnx::PeerErrorCode session_error = BeginProtocolPeerSession(peer_index);
            if (session_error != wgnx::PeerErrorCode::None) {
                SetPeerError(peer_index, wgnx::PeerErrorStage::Handshake, session_error);
                return;
            }
            SetPeerActive(peer_index);
            return;
        }
    }
}

void CommitReceiveFailure(
    std::size_t peer_index,
    std::uint32_t activation_generation,
    wgnx::platform::socket_handle socket,
    wgnx::platform::socket_error error) {
    std::scoped_lock lock(g_state_mutex);
    if (peer_index >= g_state.peer_count || g_state.active_peer_index != static_cast<std::int32_t>(peer_index)) {
        return;
    }

    auto &runtime = g_state.runtime[peer_index];
    if (runtime.activation_generation != activation_generation ||
        runtime.socket != socket ||
        (runtime.state != wgnx::PeerRuntimeState::Handshaking &&
         runtime.state != wgnx::PeerRuntimeState::Active)) {
        return;
    }

    logger::Log(
        "UDP receive failed for peer %zu endpoint=%s err=%u",
        peer_index,
        runtime.resolved_endpoint_text,
        static_cast<unsigned int>(error));
    SetPeerError(peer_index, wgnx::PeerErrorStage::Transport, MapSocketErrorToPeerErrorCode(error));
}

void ResolverWorkMain(wgnx::platform::work_struct *) {
    ResolveRequest request{};
    while (DequeueResolveRequest(std::addressof(request))) {
        const auto result = wgnx::platform::resolve_endpoint(request.endpoint);
        CommitResolveResult(request, result);
    }
}

void ReceiveWorkMain(wgnx::platform::work_struct *) {
    wgnx::platform::static_packet_buffer<ReceivePacketCapacity> packet;
    while (true) {
        std::size_t peer_index = 0;
        std::uint32_t activation_generation = 0;
        wgnx::platform::socket_handle socket = wgnx::platform::InvalidSocket;
        if (!SnapshotReceiveRuntime(
                std::addressof(peer_index),
                std::addressof(activation_generation),
                std::addressof(socket))) {
            return;
        }

        wgnx::platform::endpoint source{};
        std::size_t received = 0;
        const auto receive_error = wgnx::platform::udp_receive(
            socket,
            packet.storage.data(),
            packet.storage.size(),
            std::addressof(received),
            std::addressof(source));
        if (receive_error != wgnx::platform::socket_error::none) {
            CommitReceiveFailure(peer_index, activation_generation, socket, receive_error);
            return;
        }
        if (received == 0) {
            continue;
        }

        static_cast<void>(wgnx::platform::packet_set_len(std::addressof(packet.packet), received));
        CommitReceivedPacket(peer_index, activation_generation, socket, std::addressof(packet.packet), source);
        wgnx::platform::packet_clear(std::addressof(packet.packet));
    }
}

void RunTimerAction(wgnx::wireguard::TimerHook hook) {
    std::scoped_lock lock(g_state_mutex);
    if (g_state.active_peer_index < 0) {
        return;
    }

    const std::size_t peer_index = static_cast<std::size_t>(g_state.active_peer_index);
    auto &runtime = g_state.runtime[peer_index];
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr) {
        return;
    }

    logger::Log(
        "WG timer peer='%s' fire hook=%s",
        peer->name,
        wgnx::wireguard::GetTimerHookName(hook));

    switch (hook) {
        case wgnx::wireguard::TimerHook::RetransmitHandshake: {
            if ((runtime.state != wgnx::PeerRuntimeState::Handshaking &&
                 runtime.state != wgnx::PeerRuntimeState::Active) ||
                !peer->has_last_initiation) {
                return;
            }

            const wgnx::PeerErrorCode retry_error = RetryHandshakeSend(peer_index, "timer");
            if (retry_error == wgnx::PeerErrorCode::None) {
                if (runtime.state == wgnx::PeerRuntimeState::Active &&
                    runtime.handshake_send_attempts >= MaxHandshakeSendAttempts) {
                    CancelProtocolTimer(peer_index, hook);
                }
                return;
            }

            SetPeerError(
                peer_index,
                retry_error == wgnx::PeerErrorCode::HandshakeTimedOut
                    ? wgnx::PeerErrorStage::Handshake
                    : wgnx::PeerErrorStage::Transport,
                retry_error);
            return;
        }
        case wgnx::wireguard::TimerHook::SendKeepalive: {
            if (runtime.state != wgnx::PeerRuntimeState::Active || !peer->current_keypair.valid) {
                return;
            }

            const wgnx::PeerErrorCode keepalive_error = SendProtocolPeerKeepalive(peer_index);
            if (keepalive_error != wgnx::PeerErrorCode::None) {
                SetPeerError(peer_index, wgnx::PeerErrorStage::Transport, keepalive_error);
                return;
            }

            if (peer->persistent_keepalive_interval > 0) {
                ScheduleProtocolTimer(
                    peer_index,
                    hook,
                    wgnx::platform::get_jiffies_64() +
                        static_cast<wgnx::platform::jiffies_t>(peer->persistent_keepalive_interval) *
                            wgnx::platform::HZ);
            }
            return;
        }
        case wgnx::wireguard::TimerHook::Rekey: {
            if (runtime.state != wgnx::PeerRuntimeState::Active) {
                return;
            }

            if (!PrepareRekeyInitiation(peer_index)) {
                SetPeerError(peer_index, wgnx::PeerErrorStage::Handshake, wgnx::PeerErrorCode::HandshakeInitFailed);
                return;
            }

            runtime.handshake_send_attempts = 0;
            const wgnx::PeerErrorCode send_error = SendProtocolPeerInitiation(peer_index);
            if (send_error != wgnx::PeerErrorCode::None) {
                SetPeerError(peer_index, wgnx::PeerErrorStage::Transport, send_error);
                return;
            }

            runtime.handshake_send_attempts = 1;
            ScheduleProtocolTimer(
                peer_index,
                wgnx::wireguard::TimerHook::RetransmitHandshake,
                wgnx::platform::get_jiffies_64() + SimulatedHandshakeRetransmitJiffies);
            return;
        }
        case wgnx::wireguard::TimerHook::ZeroKeyMaterial:
            return;
    }
}

void RetransmitTimerCallback(wgnx::platform::timer_list *) {
    if (g_timer_action_workqueue != nullptr) {
        static_cast<void>(wgnx::platform::queue_work(
            g_timer_action_workqueue,
            std::addressof(g_retransmit_dispatcher.work)));
    }
}

void KeepaliveTimerCallback(wgnx::platform::timer_list *) {
    if (g_timer_action_workqueue != nullptr) {
        static_cast<void>(wgnx::platform::queue_work(
            g_timer_action_workqueue,
            std::addressof(g_keepalive_dispatcher.work)));
    }
}

void RekeyTimerCallback(wgnx::platform::timer_list *) {
    if (g_timer_action_workqueue != nullptr) {
        static_cast<void>(wgnx::platform::queue_work(
            g_timer_action_workqueue,
            std::addressof(g_rekey_dispatcher.work)));
    }
}

void TimerActionWorkMain(wgnx::platform::work_struct *work) {
    if (work == std::addressof(g_retransmit_dispatcher.work)) {
        RunTimerAction(wgnx::wireguard::TimerHook::RetransmitHandshake);
        return;
    }
    if (work == std::addressof(g_keepalive_dispatcher.work)) {
        RunTimerAction(wgnx::wireguard::TimerHook::SendKeepalive);
        return;
    }
    if (work == std::addressof(g_rekey_dispatcher.work)) {
        RunTimerAction(wgnx::wireguard::TimerHook::Rekey);
    }
}

void InitializeResolverWorker() {
    if (g_resolver_workqueue != nullptr) {
        return;
    }

    g_resolver_workqueue = wgnx::platform::alloc_ordered_workqueue("wgnx-resolve");
    AMS_ABORT_UNLESS(g_resolver_workqueue != nullptr);
    wgnx::platform::INIT_WORK(std::addressof(g_resolve_dispatcher.work), ResolverWorkMain);
    logger::Log("Started endpoint resolver worker");
}

void InitializeReceiveWorker() {
    if (g_receive_workqueue != nullptr) {
        return;
    }

    g_receive_workqueue = wgnx::platform::alloc_ordered_workqueue("wgnx-recv");
    AMS_ABORT_UNLESS(g_receive_workqueue != nullptr);
    wgnx::platform::INIT_WORK(std::addressof(g_receive_dispatcher.work), ReceiveWorkMain);
    logger::Log("Started UDP receive worker");
}

void InitializeTransportTimerExecutor() {
    if (g_timer_action_workqueue != nullptr) {
        return;
    }

    g_timer_action_workqueue = wgnx::platform::alloc_ordered_workqueue("wgnx-timer-act");
    AMS_ABORT_UNLESS(g_timer_action_workqueue != nullptr);
    wgnx::platform::INIT_WORK(std::addressof(g_retransmit_dispatcher.work), TimerActionWorkMain);
    wgnx::platform::INIT_WORK(std::addressof(g_keepalive_dispatcher.work), TimerActionWorkMain);
    wgnx::platform::INIT_WORK(std::addressof(g_rekey_dispatcher.work), TimerActionWorkMain);
    wgnx::platform::timer_setup(std::addressof(g_retransmit_dispatcher.timer), RetransmitTimerCallback);
    wgnx::platform::timer_setup(std::addressof(g_keepalive_dispatcher.timer), KeepaliveTimerCallback);
    wgnx::platform::timer_setup(std::addressof(g_rekey_dispatcher.timer), RekeyTimerCallback);
    logger::Log("Started transport timer executor");
}

} // namespace

ams::Result ControlService::GetApiVersion(ams::sf::Out<u32> out) {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();
    out.SetValue(wgnx::IpcApiVersion);
    R_SUCCEED();
}

ams::Result ControlService::GetDaemonStatus(ams::sf::Out<wgnx::DaemonStatus> out) {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();
    TickActivePeer();

    wgnx::DaemonStatus status = {
        .abi_version = wgnx::IpcApiVersion,
        .peer_count = g_state.peer_count,
        .active_peer_index = g_state.active_peer_index,
        .auto_start_peer_index = g_state.auto_start_peer_index,
        .flags = wgnx::DaemonFlag_Ready |
                 (g_state.active_peer_index >= 0 ? wgnx::DaemonFlag_TunnelActive : 0U) |
                 (HasRuntimeErrors() ? wgnx::DaemonFlag_HasErrors : 0U),
        .reserved = 0,
    };

    out.SetValue(status);
    R_SUCCEED();
}

ams::Result ControlService::GetBuildInfo(ams::sf::Out<wgnx::BuildInfo> out) {
    wgnx::BuildInfo info = {};
    std::snprintf(info.version, sizeof(info.version), "%s", VERSION);
    std::snprintf(info.build_id, sizeof(info.build_id), "%s", BUILD_ID);
    out.SetValue(info);
    R_SUCCEED();
}

ams::Result ControlService::ListPeers(ams::sf::Out<u32> out_count, const ams::sf::OutArray<wgnx::PeerInfo> &out) {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();
    TickActivePeer();

    const std::size_t copy_count = std::min<std::size_t>(out.GetSize(), g_state.peer_count);
    for (std::size_t i = 0; i < copy_count; ++i) {
        out[i] = BuildPeerInfo(i);
    }

    out_count.SetValue(g_state.peer_count);
    R_SUCCEED();
}

ams::Result ControlService::SetActivePeer(const wgnx::PeerSelectionRequest &request) {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();

    if (!IsValidPeerIndex(request.peer_index)) {
        logger::Log("Rejected SetActivePeer(%d): invalid index", request.peer_index);
        R_THROW(ams::fs::ResultInvalidArgument());
    }

    if (request.peer_index == g_state.active_peer_index) {
        logger::Log("SetActivePeer(%d): no change", request.peer_index);
        R_SUCCEED();
    }

    if (g_state.active_peer_index >= 0 && g_state.active_peer_index != request.peer_index) {
        const std::size_t old_index = static_cast<std::size_t>(g_state.active_peer_index);
        SetPeerInactive(old_index);
    }

    g_state.active_peer_index = request.peer_index;
    if (request.peer_index >= 0) {
        StartPeerRuntime(static_cast<std::size_t>(request.peer_index));
    }
    logger::Log("SetActivePeer(%d)", request.peer_index);
    R_SUCCEED();
}

ams::Result ControlService::SetAutoStartPeer(const wgnx::PeerSelectionRequest &request) {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();

    if (!IsValidPeerIndex(request.peer_index)) {
        logger::Log("Rejected SetAutoStartPeer(%d): invalid index", request.peer_index);
        R_THROW(ams::fs::ResultInvalidArgument());
    }

    const char *peer_name = nullptr;
    if (request.peer_index >= 0) {
        peer_name = g_state.configured_peers[static_cast<std::size_t>(request.peer_index)].name;
    }

    const ams::Result store_rc = StoreAutoStartPeerName(peer_name);
    if (R_FAILED(store_rc)) {
        logger::Log("Rejected SetAutoStartPeer(%d): persist failed rc=0x%08x", request.peer_index, static_cast<u32>(store_rc.GetValue()));
        R_THROW(store_rc);
    }

    g_state.auto_start_peer_index = request.peer_index;
    logger::Log("SetAutoStartPeer(%d)", request.peer_index);
    R_SUCCEED();
}

void RunIpcServer() {
    {
        std::scoped_lock lock(g_state_mutex);
        InitializeState();
    }
    InitializeResolverWorker();
    InitializeReceiveWorker();
    InitializeTransportTimerExecutor();
    logger::Log("Constructing IPC server");

    g_server_manager = ams::util::ConstructAt(g_server_manager_storage);
    R_ABORT_UNLESS(g_server_manager->RegisterObjectForServer(g_control_service_object.GetShared(), ams::sm::ServiceName::Encode(wgnx::ServiceName), 8));
    logger::Log("Registered service '%s'", wgnx::ServiceName);
    logger::Log("Entering server loop");
    g_server_manager->LoopProcess();
}

} // namespace wgnx::sysmodule
