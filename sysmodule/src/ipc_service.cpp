#include "ipc_service.hpp"

#include "config_loader.hpp"
#include "logger.hpp"
#include "wgnx/platform/clock.hpp"
#include "wgnx/platform/random.hpp"
#include "wgnx/platform/udp.hpp"
#include "wgnx/platform/work.hpp"
#include "wireguard/data.hpp"
#if WGNX_ENABLE_DEBUG_PROBE
#include "wireguard/debug_probe.hpp"
#endif
#include "wireguard/device.hpp"
#include "wireguard/handshake.hpp"
#include "wireguard/session.hpp"
#include "wireguard/timers.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mutex>
#include <span>

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
        wgnx::platform::ktime_t state_changed_ns{0};
        wgnx::platform::ktime_t last_handshake_ns{0};
        wgnx::platform::ktime_t last_rx_ns{0};
        wgnx::platform::ktime_t last_tx_ns{0};
        wgnx::platform::ktime_t debug_probe_state_changed_ns{0};
        std::uint64_t rx_bytes{0};
        std::uint64_t tx_bytes{0};
        wgnx::DebugTriggerAction debug_probe_action{wgnx::DebugTriggerAction::None};
        wgnx::DebugProbeStatus debug_probe_status{wgnx::DebugProbeStatus::None};
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

struct PayloadSubmissionRequest {
    bool pending{false};
    std::size_t peer_index{0};
    std::uint32_t activation_generation{0};
    wgnx::DebugTriggerAction action{wgnx::DebugTriggerAction::None};
};

constinit DaemonState g_state = {};
ams::os::Mutex g_state_mutex(false);
ResolveRequest g_resolve_request = {};
PayloadSubmissionRequest g_payload_submission_request = {};
struct ResolveDispatcher {
    wgnx::platform::work_struct work{};
};
constinit ResolveDispatcher g_resolve_dispatcher = {};
wgnx::platform::workqueue_struct *g_resolver_workqueue = nullptr;
struct PayloadSubmissionDispatcher {
    wgnx::platform::work_struct work{};
};
[[maybe_unused]] constinit PayloadSubmissionDispatcher g_payload_submission_dispatcher = {};
[[maybe_unused]] wgnx::platform::workqueue_struct *g_payload_submission_workqueue = nullptr;
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
struct PayloadProbeTimeoutDispatcher {
    wgnx::platform::work_struct work{};
    wgnx::platform::timer_list timer{};
};
constinit PayloadProbeTimeoutDispatcher g_payload_probe_timeout_dispatcher = {};

constexpr inline wgnx::platform::jiffies_t SimulatedHandshakeRetransmitJiffies = 5U * wgnx::platform::HZ;
constexpr inline wgnx::platform::jiffies_t SimulatedRekeyJiffies = 120U * wgnx::platform::HZ;
#if WGNX_ENABLE_DEBUG_PROBE
constexpr inline wgnx::platform::jiffies_t DebugProbeTimeoutJiffies = 5U * wgnx::platform::HZ;
#endif
constexpr inline std::uint32_t MaxHandshakeSendAttempts = 5;
constexpr inline std::size_t ReceivePacketCapacity = 4096;
constexpr inline std::size_t MaxTransportPayloadSize = 1500;
constinit std::array<std::uint8_t, MaxTransportPayloadSize> g_receive_payload_buffer = {};

template<std::size_t Size>
const char *CStr(const std::array<char, Size> &value) {
    return value.data();
}

[[maybe_unused]] bool IsSupportedDebugTriggerAction(wgnx::DebugTriggerAction action) {
#if WGNX_ENABLE_DEBUG_PROBE
    return wgnx::wireguard::IsSupportedDebugTriggerAction(action);
#else
    static_cast<void>(action);
    return false;
#endif
}

const char *GetIndexSlotName(wgnx::wireguard::wg_index_slot slot) {
    switch (slot) {
        case wgnx::wireguard::wg_index_slot::None:
            return "none";
        case wgnx::wireguard::wg_index_slot::Handshake:
            return "handshake";
        case wgnx::wireguard::wg_index_slot::CurrentKeypair:
            return "current";
        case wgnx::wireguard::wg_index_slot::NextKeypair:
            return "next";
        case wgnx::wireguard::wg_index_slot::PreviousKeypair:
            return "previous";
    }

    return "unknown";
}

std::size_t GetEndpointAddressSize(wgnx::platform::address_family family) {
    switch (family) {
        case wgnx::platform::address_family::inet:
            return 4;
        case wgnx::platform::address_family::inet6:
            return 16;
        case wgnx::platform::address_family::unspecified:
            break;
    }

    return 0;
}

bool EndpointsEqual(const wgnx::platform::endpoint &lhs, const wgnx::platform::endpoint &rhs) {
    if (lhs.family != rhs.family || lhs.port != rhs.port) {
        return false;
    }

    const std::size_t address_size = GetEndpointAddressSize(lhs.family);
    return address_size != 0 && std::memcmp(lhs.address.data(), rhs.address.data(), address_size) == 0;
}

void FormatEndpointText(
    const wgnx::platform::endpoint &endpoint,
    char *out_text,
    std::size_t out_text_size) {
    if (out_text == nullptr || out_text_size == 0) {
        return;
    }

    if (!wgnx::platform::endpoint_to_string(endpoint, std::span<char>(out_text, out_text_size))) {
        std::snprintf(out_text, out_text_size, "<invalid>");
    }
}

wgnx::platform::ktime_t GetRuntimeNowNs() {
    return wgnx::platform::ktime_get_coarse_boottime_ns();
}

void StampRuntimeNow(wgnx::platform::ktime_t *field) {
    if (field == nullptr) {
        return;
    }

    *field = GetRuntimeNowNs();
}

std::int32_t ComputeElapsedSeconds(wgnx::platform::ktime_t timestamp_ns, wgnx::platform::ktime_t now_ns) {
    if (timestamp_ns <= 0 || now_ns < timestamp_ns) {
        return -1;
    }

    const wgnx::platform::ktime_t elapsed_ns = now_ns - timestamp_ns;
    const wgnx::platform::ktime_t elapsed_seconds = elapsed_ns / wgnx::platform::NSEC_PER_SEC;
    if (elapsed_seconds > static_cast<wgnx::platform::ktime_t>(std::numeric_limits<std::int32_t>::max())) {
        return std::numeric_limits<std::int32_t>::max();
    }

    return static_cast<std::int32_t>(elapsed_seconds);
}

void ClearDebugProbeState(DaemonState::PeerRuntimeInfo *runtime) {
    if (runtime == nullptr) {
        return;
    }

    runtime->debug_probe_action = wgnx::DebugTriggerAction::None;
    runtime->debug_probe_status = wgnx::DebugProbeStatus::None;
    runtime->debug_probe_state_changed_ns = 0;
}

[[maybe_unused]] void SetDebugProbeState(
    DaemonState::PeerRuntimeInfo *runtime,
    wgnx::DebugTriggerAction action,
    wgnx::DebugProbeStatus status) {
    if (runtime == nullptr) {
        return;
    }

#if WGNX_ENABLE_DEBUG_PROBE
    if (!wgnx::wireguard::CanTransitionDebugProbeStatus(runtime->debug_probe_status, status)) {
        logger::Log(
            "Debug probe transition override old=%s new=%s action=%s",
            wgnx::GetDebugProbeStatusName(runtime->debug_probe_status),
            wgnx::GetDebugProbeStatusName(status),
            wgnx::GetDebugTriggerActionName(action));
    }
#endif
    runtime->debug_probe_action = action;
    runtime->debug_probe_status = status;
    StampRuntimeNow(std::addressof(runtime->debug_probe_state_changed_ns));
}

[[maybe_unused]] bool IsDebugProbePending(const DaemonState::PeerRuntimeInfo &runtime) {
    return runtime.debug_probe_status == wgnx::DebugProbeStatus::Queued ||
           runtime.debug_probe_status == wgnx::DebugProbeStatus::Sent;
}

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

wgnx::PeerErrorCode MapTransportDataErrorToPeerErrorCode(wgnx::wireguard::TransportDataError error) {
    switch (error) {
        case wgnx::wireguard::TransportDataError::None:
            return wgnx::PeerErrorCode::None;
        case wgnx::wireguard::TransportDataError::CounterExhausted:
        case wgnx::wireguard::TransportDataError::InvalidArgument:
        case wgnx::wireguard::TransportDataError::InvalidKeypair:
        case wgnx::wireguard::TransportDataError::InsufficientCapacity:
        case wgnx::wireguard::TransportDataError::InvalidPacket:
        case wgnx::wireguard::TransportDataError::ReceiverIndexMismatch:
        case wgnx::wireguard::TransportDataError::ReplayRejected:
        case wgnx::wireguard::TransportDataError::AuthenticationFailed:
            return wgnx::PeerErrorCode::InternalFailure;
    }

    return wgnx::PeerErrorCode::InternalFailure;
}

[[maybe_unused]] wgnx::PeerErrorStage GetPayloadSubmissionErrorStage(wgnx::PeerErrorCode code) {
    switch (code) {
        case wgnx::PeerErrorCode::TransportInitFailed:
        case wgnx::PeerErrorCode::TransportOpenFailed:
        case wgnx::PeerErrorCode::TransportSendFailed:
        case wgnx::PeerErrorCode::TransportReceiveFailed:
            return wgnx::PeerErrorStage::Transport;
        case wgnx::PeerErrorCode::None:
        case wgnx::PeerErrorCode::ConfigInvalid:
        case wgnx::PeerErrorCode::EndpointMissing:
        case wgnx::PeerErrorCode::EndpointMalformed:
        case wgnx::PeerErrorCode::EndpointResolutionFailed:
        case wgnx::PeerErrorCode::InternalFailure:
        case wgnx::PeerErrorCode::KeyInvalid:
        case wgnx::PeerErrorCode::HandshakeInitFailed:
        case wgnx::PeerErrorCode::HandshakeTimedOut:
            return wgnx::PeerErrorStage::Internal;
    }

    return wgnx::PeerErrorStage::Internal;
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
            CStr(g_state.configured_peers[peer_index].name));
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
        runtime.resolved_endpoint,
        packet.packet.bytes(),
        std::addressof(sent));
    if (send_error != wgnx::platform::socket_error::none) {
        logger::Log(
            "Failed to send WG handshake initiation for peer %zu endpoint=%s err=%u",
            peer_index,
            runtime.resolved_endpoint_text,
            static_cast<unsigned int>(send_error));
        return MapSocketErrorToPeerErrorCode(send_error);
    }

    runtime.tx_bytes += sent;
    StampRuntimeNow(std::addressof(runtime.last_tx_ns));
    logger::Log(
        "Sent WG handshake initiation for peer %zu bytes=%zu endpoint=%s",
        peer_index,
        sent,
        runtime.resolved_endpoint_text);
    return wgnx::PeerErrorCode::None;
}

wgnx::PeerErrorCode SendProtocolPeerPayload(
    std::size_t peer_index,
    const std::uint8_t *payload,
    std::size_t payload_size,
    const char *reason) {
    auto &runtime = g_state.runtime[peer_index];
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr || !peer->current_keypair.valid || !runtime.has_resolved_endpoint ||
        runtime.socket == wgnx::platform::InvalidSocket) {
        return wgnx::PeerErrorCode::InternalFailure;
    }

    wgnx::platform::static_packet_buffer<
        wgnx::wireguard::TransportDataHeaderSize + MaxTransportPayloadSize + wgnx::wireguard::NoiseMacSize>
        packet;
    const auto payload_span = payload != nullptr ? std::span<const std::uint8_t>(payload, payload_size)
                                                 : std::span<const std::uint8_t>{};
    const wgnx::wireguard::TransportDataError build_error =
        wgnx::wireguard::noise_create_transport_data_packet(
            std::addressof(packet.packet),
            peer->current_keypair,
            payload_span);
    if (build_error != wgnx::wireguard::TransportDataError::None) {
        logger::Log(
            "Failed to build WG transport payload for peer %zu endpoint=%s reason=%s payload=%zu err=%s",
            peer_index,
            runtime.resolved_endpoint_text,
            reason != nullptr ? reason : "unspecified",
            payload_size,
            wgnx::wireguard::GetTransportDataErrorName(build_error));
        return MapTransportDataErrorToPeerErrorCode(build_error);
    }

    std::size_t sent = 0;
    const auto send_error = wgnx::platform::udp_send(
        runtime.socket,
        runtime.resolved_endpoint,
        packet.packet.bytes(),
        std::addressof(sent));
    if (send_error != wgnx::platform::socket_error::none) {
        logger::Log(
            "Failed to send WG transport payload for peer %zu endpoint=%s reason=%s payload=%zu err=%u",
            peer_index,
            runtime.resolved_endpoint_text,
            reason != nullptr ? reason : "unspecified",
            payload_size,
            static_cast<unsigned int>(send_error));
        return MapSocketErrorToPeerErrorCode(send_error);
    }

    ++peer->current_keypair.send_counter;
    runtime.tx_bytes += sent;
    StampRuntimeNow(std::addressof(runtime.last_tx_ns));
    logger::Log(
        "Sent WG transport payload for peer %zu bytes=%zu payload=%zu reason=%s endpoint=%s",
        peer_index,
        sent,
        payload_size,
        reason != nullptr ? reason : "unspecified",
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

    return SendProtocolPeerPayload(peer_index, nullptr, 0, "keepalive");
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

[[maybe_unused]] void SchedulePayloadProbeTimeout() {
#if WGNX_ENABLE_DEBUG_PROBE
    wgnx::platform::mod_timer(
        std::addressof(g_payload_probe_timeout_dispatcher.timer),
        wgnx::platform::get_jiffies_64() + DebugProbeTimeoutJiffies);
#endif
}

void CancelPayloadProbeTimeout() {
#if WGNX_ENABLE_DEBUG_PROBE
    wgnx::platform::timer_delete(std::addressof(g_payload_probe_timeout_dispatcher.timer));
#endif
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
    CancelPayloadProbeTimeout();
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
    runtime->state_changed_ns = 0;
    runtime->last_handshake_ns = 0;
    runtime->last_rx_ns = 0;
    runtime->last_tx_ns = 0;
    runtime->debug_probe_state_changed_ns = 0;
    runtime->rx_bytes = 0;
    runtime->tx_bytes = 0;
    runtime->established = false;
    runtime->debug_probe_action = wgnx::DebugTriggerAction::None;
    runtime->debug_probe_status = wgnx::DebugProbeStatus::None;
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
    std::snprintf(runtime->resolved_endpoint_text, sizeof(runtime->resolved_endpoint_text), "%s", resolved.text.data());
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
            g_state.configured_peers[peer_index].private_key.data())) {
        derived.has_derived_public_key = true;
    }
}

void SetPeerInactive(std::size_t peer_index) {
    const auto &config = g_state.configured_peers[peer_index];
    auto &runtime = g_state.runtime[peer_index];
    CancelPayloadProbeTimeout();
    CloseRuntimeSocket(std::addressof(runtime));
    ResetProtocolPeer(peer_index);
    runtime = {};
    runtime.state = wgnx::PeerRuntimeState::Inactive;
    runtime.persistent_keepalive_interval = config.persistent_keepalive;
    ClearRuntimeError(&runtime);
    ResetRuntimeMetrics(&runtime);
    ClearResolvedEndpoint(&runtime);
    StampRuntimeNow(std::addressof(runtime.state_changed_ns));
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
    CancelPayloadProbeTimeout();
    runtime = {};
    runtime.state = wgnx::PeerRuntimeState::ResolvingEndpoint;
    runtime.persistent_keepalive_interval = config.persistent_keepalive;
    runtime.activation_generation = activation_generation;
    ClearRuntimeError(&runtime);
    ResetRuntimeMetrics(&runtime);
    ClearResolvedEndpoint(&runtime);
    StampRuntimeNow(std::addressof(runtime.state_changed_ns));
}

void SetPeerHandshaking(std::size_t peer_index) {
    auto &runtime = g_state.runtime[peer_index];
    runtime.state = wgnx::PeerRuntimeState::Handshaking;
    ClearRuntimeError(&runtime);
    runtime.state_ticks = 0;
    StampRuntimeNow(std::addressof(runtime.state_changed_ns));
}

void SetPeerActive(std::size_t peer_index) {
    auto &runtime = g_state.runtime[peer_index];
    runtime.state = wgnx::PeerRuntimeState::Active;
    ClearRuntimeError(&runtime);
    runtime.state_ticks = 0;
    runtime.established = true;
    StampRuntimeNow(std::addressof(runtime.state_changed_ns));
    StampRuntimeNow(std::addressof(runtime.last_handshake_ns));
}

void SetPeerError(std::size_t peer_index, wgnx::PeerErrorStage stage, wgnx::PeerErrorCode code) {
    auto &runtime = g_state.runtime[peer_index];
    CancelPayloadProbeTimeout();
    CloseRuntimeSocket(std::addressof(runtime));
    runtime.state = wgnx::PeerRuntimeState::Error;
    runtime.error_stage = stage;
    runtime.last_error_code = static_cast<std::uint32_t>(code);
    runtime.state_ticks = 0;
    runtime.established = false;
    ClearDebugProbeState(std::addressof(runtime));
    StampRuntimeNow(std::addressof(runtime.state_changed_ns));
    FailProtocolPeer(peer_index, wgnx::GetPeerErrorCodeName(code));
}

wgnx::PeerErrorCode ValidatePeerConfiguration(const wgnx::PeerConfigEntry &config) {
    if (config.private_key[0] == '\0' || config.public_key[0] == '\0' || config.allowed_ips[0] == '\0') {
        return wgnx::PeerErrorCode::ConfigInvalid;
    }
    if (!wgnx::wireguard::noise_is_valid_encoded_key(config.private_key.data()) ||
        !wgnx::wireguard::noise_is_valid_encoded_key(config.public_key.data()) ||
        !wgnx::wireguard::noise_is_valid_encoded_key(config.preshared_key.data(), true)) {
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
    std::snprintf(g_resolve_request.endpoint, sizeof(g_resolve_request.endpoint), "%s", config.endpoint.data());
    static_cast<void>(wgnx::platform::queue_work(g_resolver_workqueue, std::addressof(g_resolve_dispatcher.work)));
}

void QueueReceiveWork() {
    if (g_receive_workqueue == nullptr) {
        return;
    }

    static_cast<void>(wgnx::platform::queue_work(g_receive_workqueue, std::addressof(g_receive_dispatcher.work)));
}

[[maybe_unused]] void QueuePayloadSubmissionWork() {
#if WGNX_ENABLE_DEBUG_PROBE
    if (g_payload_submission_workqueue == nullptr) {
        return;
    }

    static_cast<void>(wgnx::platform::queue_work(
        g_payload_submission_workqueue,
        std::addressof(g_payload_submission_dispatcher.work)));
#endif
}

[[maybe_unused]] bool QueuePayloadSubmissionRequestLocked(wgnx::DebugTriggerAction action) {
#if !WGNX_ENABLE_DEBUG_PROBE
    static_cast<void>(action);
    return false;
#else
    if (g_state.active_peer_index < 0) {
        return false;
    }

    const std::size_t peer_index = static_cast<std::size_t>(g_state.active_peer_index);
    auto &runtime = g_state.runtime[peer_index];
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (runtime.state != wgnx::PeerRuntimeState::Active ||
        runtime.socket == wgnx::platform::InvalidSocket ||
        peer == nullptr ||
        !peer->current_keypair.valid) {
        return false;
    }
    if (g_payload_submission_request.pending || IsDebugProbePending(runtime)) {
        return false;
    }
    if (!IsSupportedDebugTriggerAction(action)) {
        return false;
    }

    g_payload_submission_request = {};
    g_payload_submission_request.pending = true;
    g_payload_submission_request.peer_index = peer_index;
    g_payload_submission_request.activation_generation = runtime.activation_generation;
    g_payload_submission_request.action = action;
    SetDebugProbeState(std::addressof(runtime), action, wgnx::DebugProbeStatus::Queued);
    return true;
#endif
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
        peer_index, activation_generation, config.endpoint.data());
}

wgnx::PeerInfo BuildPeerInfo(std::size_t peer_index) {
    const auto &config = g_state.configured_peers[peer_index];
    const auto &runtime = g_state.runtime[peer_index];
    const wgnx::platform::ktime_t now_ns = GetRuntimeNowNs();

    wgnx::PeerInfo peer = {};
    std::snprintf(peer.name, sizeof(peer.name), "%s", config.name.data());
    std::snprintf(peer.address, sizeof(peer.address), "%s", config.address.data());
    std::snprintf(peer.endpoint, sizeof(peer.endpoint), "%s", config.endpoint.data());
    std::snprintf(peer.resolved_endpoint, sizeof(peer.resolved_endpoint), "%s", runtime.resolved_endpoint_text);
    std::snprintf(
        peer.derived_public_key,
        sizeof(peer.derived_public_key),
        "%s",
        g_state.config_derived[peer_index].has_derived_public_key ? g_state.config_derived[peer_index].derived_public_key : "");
    peer.last_handshake_seconds = ComputeElapsedSeconds(runtime.last_handshake_ns, now_ns);
    peer.last_rx_seconds = ComputeElapsedSeconds(runtime.last_rx_ns, now_ns);
    peer.last_tx_seconds = ComputeElapsedSeconds(runtime.last_tx_ns, now_ns);
    peer.last_debug_probe_seconds = ComputeElapsedSeconds(runtime.debug_probe_state_changed_ns, now_ns);
    peer.last_error_code = runtime.last_error_code;
    peer.debug_probe_action = static_cast<std::uint32_t>(runtime.debug_probe_action);
    peer.debug_probe_status = static_cast<std::uint32_t>(runtime.debug_probe_status);
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

            if (has_auto_start_name && std::strncmp(entry.name.data(), auto_start_name, entry.name.size()) == 0) {
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
    /*
     * IPC status queries should observe live runtime state, not advance it.
     * The remaining call sites stay in place so this seam can grow later
     * without making status requests mutate transport-visible ages again.
     */
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

[[maybe_unused]] bool DequeuePayloadSubmissionRequest(PayloadSubmissionRequest *out_request) {
    std::scoped_lock lock(g_state_mutex);
    if (!g_payload_submission_request.pending || out_request == nullptr) {
        return false;
    }

    *out_request = g_payload_submission_request;
    g_payload_submission_request.pending = false;
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
    StampRuntimeNow(std::addressof(runtime.last_rx_ns));

    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr) {
        SetPeerError(peer_index, wgnx::PeerErrorStage::Internal, wgnx::PeerErrorCode::InternalFailure);
        return;
    }

    wgnx::wireguard::MessageType type = wgnx::wireguard::MessageType::Invalid;
    const wgnx::wireguard::ParseResult type_result = wgnx::wireguard::InspectMessageType(packet, &type);
    if (!type_result.success) {
        logger::Log(
            "Rejected UDP packet for peer %zu bytes=%zu source_family=%s inspect_err=%s",
            peer_index,
            packet->len,
            wgnx::GetPeerResolvedFamilyName(static_cast<wgnx::PeerResolvedFamily>(source.family)),
            wgnx::wireguard::GetParseErrorName(type_result.error));
        return;
    }

    if (type == wgnx::wireguard::MessageType::TransportData) {
        char source_text[sizeof(wgnx::PeerInfo::resolved_endpoint)] = {};
        char expected_text[sizeof(wgnx::PeerInfo::resolved_endpoint)] = {};
        FormatEndpointText(source, source_text, sizeof(source_text));
        FormatEndpointText(runtime.resolved_endpoint, expected_text, sizeof(expected_text));

        if (!runtime.has_resolved_endpoint || !EndpointsEqual(source, runtime.resolved_endpoint)) {
            logger::Log(
                "Rejected WG transport data for peer %zu bytes=%zu source=%s expected=%s reason=source_mismatch",
                peer_index,
                packet->len,
                source_text,
                expected_text);
            return;
        }

        wgnx::wireguard::IncomingTransportDataResult decrypt_result{};
        const wgnx::wireguard::TransportDataError decrypt_error =
            wgnx::wireguard::noise_consume_incoming_transport_data_packet(
                packet,
                std::addressof(g_state.protocol[peer_index].device),
                peer,
                g_receive_payload_buffer,
                std::addressof(decrypt_result));
        if (decrypt_error != wgnx::wireguard::TransportDataError::None) {
            logger::Log(
                "Rejected WG transport data for peer %zu bytes=%zu source=%s slot=%s err=%s",
                peer_index,
                packet->len,
                source_text,
                GetIndexSlotName(decrypt_result.slot),
                wgnx::wireguard::GetTransportDataErrorName(decrypt_error));
            return;
        }

        logger::Log(
            "Accepted WG transport data for peer %zu bytes=%zu payload=%zu source=%s slot=%s counter=%llu",
            peer_index,
            packet->len,
            decrypt_result.decrypt.payload_size,
            source_text,
            GetIndexSlotName(decrypt_result.slot),
            static_cast<unsigned long long>(decrypt_result.decrypt.header.counter));

        if (decrypt_result.decrypt.payload_size == 0) {
            logger::Log("Accepted WG keepalive payload for peer %zu", peer_index);
            return;
        }

#if WGNX_ENABLE_DEBUG_PROBE
        wgnx::wireguard::DebugProbeReplyInfo reply_info{};
        const wgnx::wireguard::DebugProbeReplyValidation reply_validation =
            wgnx::wireguard::ValidateDebugIcmpEchoReply(
                std::span<const std::uint8_t>(g_receive_payload_buffer.data(), decrypt_result.decrypt.payload_size),
                g_state.configured_peers[peer_index].address.data(),
                peer_index,
                activation_generation,
                std::addressof(reply_info));
        if (reply_validation == wgnx::wireguard::DebugProbeReplyValidation::Valid) {
            char inner_source[16] = {};
            char inner_destination[16] = {};
            wgnx::wireguard::FormatIpv4Text(reply_info.source_ipv4, inner_source, sizeof(inner_source));
            wgnx::wireguard::FormatIpv4Text(reply_info.destination_ipv4, inner_destination, sizeof(inner_destination));
            CancelPayloadProbeTimeout();
            SetDebugProbeState(
                std::addressof(runtime),
                reply_info.action,
                wgnx::DebugProbeStatus::ReplyValidated);
            logger::Log(
                "Validated debug ICMP reply for peer %zu action=%s source=%s destination=%s seq=%u activation=%u",
                peer_index,
                wgnx::GetDebugTriggerActionName(reply_info.action),
                inner_source,
                inner_destination,
                static_cast<unsigned int>(reply_info.sequence),
                reply_info.activation_generation);
            return;
        }

        if (reply_validation != wgnx::wireguard::DebugProbeReplyValidation::NotDebugReply) {
            CancelPayloadProbeTimeout();
            SetDebugProbeState(
                std::addressof(runtime),
                runtime.debug_probe_action,
                wgnx::DebugProbeStatus::ReplyRejected);
            logger::Log(
                "Rejected debug ICMP reply metadata for peer %zu validation=%s payload=%zu",
                peer_index,
                wgnx::wireguard::GetDebugProbeReplyValidationName(reply_validation),
                decrypt_result.decrypt.payload_size);
            return;
        }
#endif

        logger::Log(
            "Delivered non-debug decrypted payload for peer %zu bytes=%zu",
            peer_index,
            decrypt_result.decrypt.payload_size);
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
            const wgnx::PeerErrorCode keepalive_error = SendProtocolPeerKeepalive(peer_index);
            if (keepalive_error != wgnx::PeerErrorCode::None) {
                SetPeerError(peer_index, wgnx::PeerErrorStage::Transport, keepalive_error);
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

[[maybe_unused]] void CommitPayloadSubmission(const PayloadSubmissionRequest &request) {
#if !WGNX_ENABLE_DEBUG_PROBE
    static_cast<void>(request);
#else
    std::scoped_lock lock(g_state_mutex);
    if (request.peer_index >= g_state.peer_count ||
        g_state.active_peer_index != static_cast<std::int32_t>(request.peer_index)) {
        logger::Log(
            "Discarded queued payload submission for stale peer %zu activation=%u",
            request.peer_index,
            request.activation_generation);
        return;
    }

    auto &runtime = g_state.runtime[request.peer_index];
    if (runtime.activation_generation != request.activation_generation ||
        runtime.state != wgnx::PeerRuntimeState::Active ||
        runtime.socket == wgnx::platform::InvalidSocket) {
        if (runtime.activation_generation == request.activation_generation) {
            SetDebugProbeState(std::addressof(runtime), request.action, wgnx::DebugProbeStatus::InvalidState);
        }
        logger::Log(
            "Discarded queued payload submission for peer %zu state=%s activation=%u current_activation=%u",
            request.peer_index,
            wgnx::GetPeerRuntimeStateName(runtime.state),
            request.activation_generation,
            runtime.activation_generation);
        return;
    }

    std::array<std::uint8_t, wgnx::wireguard::DebugProbePacketSize> payload{};
    const std::size_t payload_size = wgnx::wireguard::BuildDebugIcmpEchoRequest(
        payload,
        g_state.configured_peers[request.peer_index].address.data(),
        request.action,
        request.activation_generation,
        request.peer_index,
        wgnx::platform::get_random_u32_below(std::numeric_limits<std::uint32_t>::max()));
    if (payload_size == 0) {
        char target_text[16] = {};
        std::array<std::uint8_t, 4> target_ipv4{};
        wgnx::wireguard::CopyDebugTargetIpv4(request.action, target_ipv4);
        wgnx::wireguard::FormatIpv4Text(target_ipv4, target_text, sizeof(target_text));
        SetDebugProbeState(std::addressof(runtime), request.action, wgnx::DebugProbeStatus::BuildFailed);
        logger::Log(
            "Failed to build debug ICMP packet for peer %zu activation=%u action=%s source=%s target=%s",
            request.peer_index,
            request.activation_generation,
            wgnx::GetDebugTriggerActionName(request.action),
            g_state.configured_peers[request.peer_index].address.data(),
            target_text);
        return;
    }

    char target_text[16] = {};
    std::array<std::uint8_t, 4> target_ipv4{};
    wgnx::wireguard::CopyDebugTargetIpv4(request.action, target_ipv4);
    wgnx::wireguard::FormatIpv4Text(target_ipv4, target_text, sizeof(target_text));
    logger::Log(
        "Built debug ICMP packet for peer %zu activation=%u action=%s source=%s target=%s bytes=%zu",
        request.peer_index,
        request.activation_generation,
        wgnx::GetDebugTriggerActionName(request.action),
        g_state.configured_peers[request.peer_index].address.data(),
        target_text,
        payload_size);
    const wgnx::PeerErrorCode send_error = SendProtocolPeerPayload(
        request.peer_index,
        payload.data(),
        payload_size,
        wgnx::GetDebugTriggerActionName(request.action));
    if (send_error != wgnx::PeerErrorCode::None) {
        SetDebugProbeState(std::addressof(runtime), request.action, wgnx::DebugProbeStatus::SendFailed);
        SetPeerError(request.peer_index, GetPayloadSubmissionErrorStage(send_error), send_error);
        return;
    }

    SetDebugProbeState(std::addressof(runtime), request.action, wgnx::DebugProbeStatus::Sent);
    SchedulePayloadProbeTimeout();
#endif
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
            packet.storage,
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

[[maybe_unused]] void PayloadSubmissionWorkMain(wgnx::platform::work_struct *) {
#if WGNX_ENABLE_DEBUG_PROBE
    PayloadSubmissionRequest request{};
    while (DequeuePayloadSubmissionRequest(std::addressof(request))) {
        CommitPayloadSubmission(request);
    }
#else
    return;
#endif
}

[[maybe_unused]] void CommitPayloadProbeTimeout() {
#if WGNX_ENABLE_DEBUG_PROBE
    std::scoped_lock lock(g_state_mutex);
    if (g_state.active_peer_index < 0) {
        return;
    }

    const std::size_t peer_index = static_cast<std::size_t>(g_state.active_peer_index);
    auto &runtime = g_state.runtime[peer_index];
    if (runtime.state != wgnx::PeerRuntimeState::Active ||
        runtime.debug_probe_status != wgnx::DebugProbeStatus::Sent ||
        runtime.debug_probe_action == wgnx::DebugTriggerAction::None) {
        return;
    }

    const auto action = runtime.debug_probe_action;
    SetDebugProbeState(std::addressof(runtime), action, wgnx::DebugProbeStatus::TimedOut);
    logger::Log(
        "Debug payload probe timed out for peer %zu action=%s activation=%u",
        peer_index,
        wgnx::GetDebugTriggerActionName(action),
        runtime.activation_generation);
#endif
}

[[maybe_unused]] void PayloadProbeTimeoutWorkMain(wgnx::platform::work_struct *) {
    CommitPayloadProbeTimeout();
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

[[maybe_unused]] void PayloadProbeTimeoutTimerCallback(wgnx::platform::timer_list *) {
#if WGNX_ENABLE_DEBUG_PROBE
    if (g_timer_action_workqueue != nullptr) {
        static_cast<void>(wgnx::platform::queue_work(
            g_timer_action_workqueue,
            std::addressof(g_payload_probe_timeout_dispatcher.work)));
    }
#endif
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
        return;
    }

    if (work == std::addressof(g_payload_probe_timeout_dispatcher.work)) {
#if WGNX_ENABLE_DEBUG_PROBE
        PayloadProbeTimeoutWorkMain(work);
#endif
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

[[maybe_unused]] void InitializePayloadSubmissionWorker() {
#if !WGNX_ENABLE_DEBUG_PROBE
    return;
#else
    if (g_payload_submission_workqueue != nullptr) {
        return;
    }

    g_payload_submission_workqueue = wgnx::platform::alloc_ordered_workqueue("wgnx-payload");
    AMS_ABORT_UNLESS(g_payload_submission_workqueue != nullptr);
    wgnx::platform::INIT_WORK(std::addressof(g_payload_submission_dispatcher.work), PayloadSubmissionWorkMain);
    logger::Log("Started payload submission worker");
#endif
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
#if WGNX_ENABLE_DEBUG_PROBE
    wgnx::platform::INIT_WORK(std::addressof(g_payload_probe_timeout_dispatcher.work), TimerActionWorkMain);
#endif
    wgnx::platform::timer_setup(std::addressof(g_retransmit_dispatcher.timer), RetransmitTimerCallback);
    wgnx::platform::timer_setup(std::addressof(g_keepalive_dispatcher.timer), KeepaliveTimerCallback);
    wgnx::platform::timer_setup(std::addressof(g_rekey_dispatcher.timer), RekeyTimerCallback);
#if WGNX_ENABLE_DEBUG_PROBE
    wgnx::platform::timer_setup(
        std::addressof(g_payload_probe_timeout_dispatcher.timer),
        PayloadProbeTimeoutTimerCallback);
#endif
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
        peer_name = g_state.configured_peers[static_cast<std::size_t>(request.peer_index)].name.data();
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

#if WGNX_ENABLE_DEBUG_PROBE
ams::Result ControlService::TriggerDebugPayload(const wgnx::DebugTriggerRequest &request) {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();

    const auto action = static_cast<wgnx::DebugTriggerAction>(request.action);
    if (!QueuePayloadSubmissionRequestLocked(action)) {
        logger::Log(
            "Rejected TriggerDebugPayload(action=%u): no active session, invalid action, or queue busy",
            request.action);
        R_THROW(ams::fs::ResultInvalidArgument());
    }

    QueuePayloadSubmissionWork();
    logger::Log("Queued debug payload trigger action=%s", wgnx::GetDebugTriggerActionName(action));
    R_SUCCEED();
}
#endif

void RunIpcServer() {
    {
        std::scoped_lock lock(g_state_mutex);
        InitializeState();
    }
    InitializeResolverWorker();
#if WGNX_ENABLE_DEBUG_PROBE
    InitializePayloadSubmissionWorker();
#endif
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
