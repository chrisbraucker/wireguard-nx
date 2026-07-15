#include "runtime/daemon_runtime.hpp"
#include "runtime/horizon_dispatcher.hpp"
#include "runtime/packet_channel.hpp"
#include "runtime/peer_runtime.hpp"
#include "runtime/runtime_coordinator.hpp"
#include "runtime/runtime_contracts.hpp"
#include "runtime/udp_binding.hpp"

#include "config_loader.hpp"
#include "development_config.hpp"
#include "logger.hpp"
#include "wgnx/platform/clock.hpp"
#include "wgnx/platform/packet.hpp"
#include "wgnx/platform/random.hpp"
#include "wgnx/platform/udp.hpp"
#include "wgnx/platform/work.hpp"
#include "wireguard/data.hpp"
#include "wireguard/crypto/primitives.hpp"
#include "wireguard/debug_probe.hpp"
#include "wireguard/device.hpp"
#include "wireguard/handshake.hpp"
#include "wireguard/inner_packet.hpp"
#include "wireguard/peer_controller.hpp"
#include "wireguard/session.hpp"
#include "wireguard/timer_coordinator.hpp"
#include "wireguard/timers.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mutex>
#include <span>
#include <type_traits>

namespace wgnx::sysmodule {

namespace {

struct DaemonState {
    runtime::PeerRegistry peers{};
    std::uint32_t next_socket_generation{1};
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

struct BindBumpRequest {
    bool pending{false};
    std::size_t peer_index{0};
    std::uint32_t activation_generation{0};
};

constinit DaemonState g_state = {};
ams::os::Mutex g_state_mutex(false);
ResolveRequest g_resolve_request = {};
PayloadSubmissionRequest g_payload_submission_request = {};
BindBumpRequest g_bind_bump_request = {};
runtime::HorizonDispatcher g_horizon_dispatcher{};
runtime::PacketChannel g_packet_channel{};
runtime::RuntimeCoordinator g_runtime_coordinator{g_state.peers};

constexpr inline wgnx::platform::jiffies_t DebugProbeTimeoutJiffies = 5U * wgnx::platform::HZ;
constexpr inline wgnx::platform::jiffies_t NetworkPathObservationJiffies = 2U * wgnx::platform::HZ;
constexpr inline std::size_t ReceivePacketCapacity = 4096;
constexpr inline std::size_t MaxTransportPayloadSize = 1500;
constexpr inline std::size_t MaxPaddedTransportPayloadSize =
    wgnx::wireguard::GetPaddedTransportPayloadSize(MaxTransportPayloadSize);
static_assert(MaxTransportPayloadSize == wgnx::MaxInnerIpv4PacketSize);
static_assert(MaxTransportPayloadSize == wgnx::wireguard::MaxInnerIpv4PacketSize);
constinit std::array<std::uint8_t, MaxPaddedTransportPayloadSize> g_receive_payload_buffer = {};

void QueueInnerPacketSubmissionWork();

runtime::PeerRuntime &PeerAt(std::size_t peer_index) {
    return g_state.peers[peer_index];
}

template<std::size_t Size>
const char *CStr(const std::array<char, Size> &value) {
    return value.data();
}

[[maybe_unused]] bool IsSupportedDebugTriggerAction(wgnx::DebugTriggerAction action) {
    return wgnx::wireguard::IsSupportedDebugTriggerAction(action);
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

[[maybe_unused]] void SetDebugProbeState(
    runtime::PeerRuntime &peer_runtime,
    wgnx::DebugTriggerAction action,
    wgnx::DebugProbeStatus status) {
    const auto old_status = peer_runtime.Lifecycle().debug_probe_status;
    if (!peer_runtime.SetDebugProbeState(action, status, GetRuntimeNowNs())) {
        logger::Log(
            "Debug probe transition override old=%s new=%s action=%s",
            wgnx::GetDebugProbeStatusName(old_status),
            wgnx::GetDebugProbeStatusName(status),
            wgnx::GetDebugTriggerActionName(action));
    }
}

[[maybe_unused]] bool IsDebugProbePending(const runtime::PeerRuntime &peer_runtime) {
    const auto &lifecycle = peer_runtime.Lifecycle();
    return lifecycle.debug_probe_status == wgnx::DebugProbeStatus::Queued ||
           lifecycle.debug_probe_status == wgnx::DebugProbeStatus::Sent;
}

void CloseRuntimeSocket(std::size_t peer_index) {
    runtime::UdpBinding &binding = PeerAt(peer_index).binding;
    if (binding.IsOpen()) {
        logger::Log(
            "Closing runtime UDP socket generation=%u socket=%d suspended=%u",
            binding.Generation(),
            static_cast<int>(binding.Socket()),
            binding.IsSuspended() ? 1U : 0U);
        const std::uint32_t generation = binding.Generation();
        const auto socket = binding.Socket();
        binding.Close();
        logger::Log(
            "Closed runtime UDP socket generation=%u socket=%d",
            generation,
            static_cast<int>(socket));
    }
}

std::uint32_t AllocateSocketGeneration() {
    const std::uint32_t generation = g_state.next_socket_generation++;
    if (g_state.next_socket_generation == 0) {
        g_state.next_socket_generation = 1;
    }
    return generation;
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
        case wgnx::wireguard::TransportDataError::KeyExpired:
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

bool IsRecoverableTransportIoError(wgnx::PeerErrorCode code) {
    return code == wgnx::PeerErrorCode::TransportSendFailed ||
           code == wgnx::PeerErrorCode::TransportReceiveFailed;
}

void CancelAllTransportTimers();
void CancelProtocolTimer(std::size_t peer_index, wgnx::wireguard::TimerHook hook);

void SuspendRuntimeTransportAfterSendFailure(std::size_t peer_index, const char *operation) {
    if constexpr (!development_config::SuspendUdpTransportOnFirstSendFailure) {
        return;
    }

    const auto &runtime = PeerAt(peer_index).Lifecycle();
    auto &binding = PeerAt(peer_index).binding;
    if (binding.IsSuspended()) {
        logger::Log(
            "UDP transport already suspended peer=%zu activation=%u operation=%s",
            peer_index,
            runtime.activation_generation,
            operation != nullptr ? operation : "unspecified");
        return;
    }

    const auto socket = binding.Socket();
    const std::uint32_t socket_generation = binding.Generation();
    logger::Log(
        "EXPERIMENT suspending UDP transport after send failure peer=%zu activation=%u socket_generation=%u socket=%d operation=%s; preserving peer, keys, protocol, and NIFM state",
        peer_index,
        runtime.activation_generation,
        socket_generation,
        static_cast<int>(socket),
        operation != nullptr ? operation : "unspecified");
    CancelProtocolTimer(peer_index, wgnx::wireguard::TimerHook::RetransmitHandshake);
    CancelProtocolTimer(peer_index, wgnx::wireguard::TimerHook::SendKeepalive);
    CancelProtocolTimer(peer_index, wgnx::wireguard::TimerHook::Rekey);
    binding.Suspend();
    logger::Log(
        "EXPERIMENT UDP transport suspended peer=%zu activation=%u old_socket_generation=%u old_socket=%d state=%s",
        peer_index,
        runtime.activation_generation,
        socket_generation,
        static_cast<int>(socket),
        wgnx::GetPeerRuntimeStateName(runtime.state));
}

void LogRecoverableTransportIoError(
    std::size_t peer_index,
    wgnx::PeerErrorCode code,
    const char *operation) {
    const auto &runtime = PeerAt(peer_index).Lifecycle();
    logger::Log(
        "Nonterminal WG transport I/O failure peer=%zu activation=%u state=%s operation=%s error=%s",
        peer_index,
        runtime.activation_generation,
        wgnx::GetPeerRuntimeStateName(runtime.state),
        operation != nullptr ? operation : "unspecified",
        wgnx::GetPeerErrorCodeName(code));
    if (code == wgnx::PeerErrorCode::TransportSendFailed) {
        SuspendRuntimeTransportAfterSendFailure(peer_index, operation);
    }
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

void ResetProtocolPeer(std::size_t peer_index) {
    auto &protocol = PeerAt(peer_index).protocol;
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
    auto &protocol = PeerAt(peer_index).protocol;
    if (!protocol.instantiated) {
        return nullptr;
    }

    return wgnx::wireguard::wg_device_first_peer(std::addressof(protocol.device));
}

wgnx::PeerErrorCode InstantiateProtocolPeer(std::size_t peer_index, std::uint32_t activation_generation) {
    auto &protocol = PeerAt(peer_index).protocol;
    const auto &derived = PeerAt(peer_index).derived;
    if (!derived.secrets_valid || !wgnx::wireguard::wg_device_init_from_parsed_config(
            std::addressof(protocol.device),
            PeerAt(peer_index).config,
            derived.local_private_key,
            derived.has_preshared_key ? std::addressof(derived.preshared_key) : nullptr)) {
        logger::Log(
            "Failed to instantiate WG protocol peer for '%s'",
            CStr(PeerAt(peer_index).config.name));
        return wgnx::PeerErrorCode::KeyInvalid;
    }
    protocol.instantiated = true;

    logger::Log(
        "Instantiated WG protocol peer '%s' activation=%u",
        CStr(PeerAt(peer_index).config.name),
        activation_generation);

    return wgnx::PeerErrorCode::None;
}

wgnx::PeerErrorCode BindResolvedEndpointToProtocolPeer(std::size_t peer_index) {
    const auto &binding = PeerAt(peer_index).binding;
    if (GetProtocolPeer(peer_index) == nullptr || !binding.HasEndpoint()) {
        return wgnx::PeerErrorCode::InternalFailure;
    }
    return wgnx::PeerErrorCode::None;
}

wgnx::PeerErrorCode OpenRuntimeSocket(std::size_t peer_index) {
    auto &binding = PeerAt(peer_index).binding;
    CloseRuntimeSocket(peer_index);

    logger::Log(
        "Opening UDP socket for peer %zu family=%s endpoint=%s",
        peer_index,
        wgnx::GetPeerResolvedFamilyName(
            static_cast<wgnx::PeerResolvedFamily>(binding.Endpoint().family)),
        binding.EndpointText());

    const auto open_error = binding.Open(AllocateSocketGeneration());
    if (open_error != wgnx::platform::socket_error::none) {
        logger::Log(
            "Failed to open UDP socket for peer %zu endpoint=%s err=%u",
            peer_index,
            binding.EndpointText(),
            static_cast<unsigned int>(open_error));
        return MapSocketErrorToPeerErrorCode(open_error);
    }

    logger::Log(
        "Opened UDP socket for peer %zu generation=%u socket=%d family=%s endpoint=%s",
        peer_index,
        binding.Generation(),
        static_cast<int>(binding.Socket()),
        wgnx::GetPeerResolvedFamilyName(
            static_cast<wgnx::PeerResolvedFamily>(binding.Endpoint().family)),
        binding.EndpointText());
    return wgnx::PeerErrorCode::None;
}

wgnx::PeerErrorCode SendProtocolPeerInitiation(std::size_t peer_index) {
    const auto &binding = PeerAt(peer_index).binding;
    if (binding.IsSuspended()) {
        return wgnx::PeerErrorCode::TransportSendFailed;
    }
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr || !peer->has_last_initiation || !binding.HasEndpoint() ||
        !binding.IsOpen()) {
        return wgnx::PeerErrorCode::InternalFailure;
    }

    wgnx::platform::static_packet_buffer<wgnx::wireguard::HandshakeInitiationSize> packet;
    if (wgnx::wireguard::SerializeHandshakeInitiation(
            packet.storage,
            peer->last_initiation) != wgnx::wireguard::ParseError::None) {
        return wgnx::PeerErrorCode::InternalFailure;
    }
    static_cast<void>(wgnx::platform::packet_set_len(
        std::addressof(packet.packet),
        wgnx::wireguard::HandshakeInitiationSize));

    std::size_t sent = 0;
    const auto send_error = binding.Send(packet.packet.bytes(), std::addressof(sent));
    if (send_error != wgnx::platform::socket_error::none) {
        logger::Log(
            "Failed to send WG handshake initiation for peer %zu endpoint=%s err=%u",
            peer_index,
            binding.EndpointText(),
            static_cast<unsigned int>(send_error));
        return MapSocketErrorToPeerErrorCode(send_error);
    }

    PeerAt(peer_index).RecordTransmittedBytes(sent, GetRuntimeNowNs());
    logger::Log(
        "Sent WG handshake initiation for peer %zu bytes=%zu endpoint=%s",
        peer_index,
        sent,
        binding.EndpointText());
    return wgnx::PeerErrorCode::None;
}

struct PayloadSendResult {
    wgnx::PeerErrorCode error{wgnx::PeerErrorCode::None};
    wgnx::wireguard::OutboundSendOutcome outcome{
        wgnx::wireguard::OutboundSendOutcome::TransportFatal()};
};

PayloadSendResult SendProtocolPeerPayload(
    std::size_t peer_index,
    const std::uint8_t *payload,
    std::size_t payload_size,
    const char *reason) {
    const auto &binding = PeerAt(peer_index).binding;
    if (binding.IsSuspended()) {
        return {
            .error = wgnx::PeerErrorCode::TransportSendFailed,
            .outcome = wgnx::wireguard::OutboundSendOutcome::TransportDropped(),
        };
    }
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr || !binding.HasEndpoint() || !binding.IsOpen()) {
        return {.error = wgnx::PeerErrorCode::InternalFailure};
    }

    wgnx::platform::static_packet_buffer<
        wgnx::wireguard::TransportDataHeaderSize + MaxPaddedTransportPayloadSize + wgnx::wireguard::NoiseMacSize>
        packet;
    const auto payload_span = payload != nullptr ? std::span<const std::uint8_t>(payload, payload_size)
                                                 : std::span<const std::uint8_t>{};
    const wgnx::wireguard::TransportDataCreateResult build_result =
        wgnx::wireguard::noise_create_transport_data_packet(
            packet.storage,
            peer->current_keypair,
            payload_span);
    if (build_result.error != wgnx::wireguard::TransportDataError::None) {
        logger::Log(
            "Failed to build WG transport payload for peer %zu endpoint=%s reason=%s payload=%zu err=%s",
            peer_index,
            binding.EndpointText(),
            reason != nullptr ? reason : "unspecified",
            payload_size,
            wgnx::wireguard::GetTransportDataErrorName(build_result.error));
        return {
            .error = MapTransportDataErrorToPeerErrorCode(build_result.error),
            .outcome = wgnx::wireguard::OutboundSendOutcome::BuildFailed(build_result.error),
        };
    }
    static_cast<void>(wgnx::platform::packet_set_len(
        std::addressof(packet.packet),
        build_result.packet_size));

    std::size_t sent = 0;
    const auto send_error = binding.Send(packet.packet.bytes(), std::addressof(sent));
    if (send_error != wgnx::platform::socket_error::none) {
        logger::Log(
            "Failed to send WG transport payload for peer %zu endpoint=%s reason=%s payload=%zu err=%u",
            peer_index,
            binding.EndpointText(),
            reason != nullptr ? reason : "unspecified",
            payload_size,
            static_cast<unsigned int>(send_error));
        return {
            .error = MapSocketErrorToPeerErrorCode(send_error),
            .outcome = wgnx::wireguard::OutboundSendOutcome::TransportDropped(),
        };
    }

    PeerAt(peer_index).RecordTransmittedBytes(sent, GetRuntimeNowNs());
    logger::Log(
        "Sent WG transport payload for peer %zu bytes=%zu payload=%zu reason=%s endpoint=%s",
        peer_index,
        sent,
        payload_size,
        reason != nullptr ? reason : "unspecified",
        binding.EndpointText());
    return {
        .outcome = wgnx::wireguard::OutboundSendOutcome::Sent(),
    };
}

[[maybe_unused]] PayloadSendResult SendInnerIpv4PacketDetailedLocked(
    std::size_t peer_index,
    std::span<const std::uint8_t> packet,
    const char *reason) {
    const auto validation = wgnx::wireguard::ValidateInnerIpv4Packet(packet);
    if (validation != wgnx::wireguard::InnerIpv4ValidationError::None) {
        logger::Log(
            "Rejected inner IPv4 send for peer %zu bytes=%zu reason=%s validation=%s",
            peer_index,
            packet.size(),
            reason != nullptr ? reason : "unspecified",
            wgnx::wireguard::GetInnerIpv4ValidationErrorName(validation));
        return {.error = wgnx::PeerErrorCode::InternalFailure};
    }

    return SendProtocolPeerPayload(peer_index, packet.data(), packet.size(), reason);
}

[[maybe_unused]] wgnx::PeerErrorCode SendInnerIpv4PacketLocked(
    std::size_t peer_index,
    std::span<const std::uint8_t> packet,
    const char *reason) {
    return SendInnerIpv4PacketDetailedLocked(peer_index, packet, reason).error;
}

wgnx::PeerErrorCode SendProtocolPeerKeepalive(std::size_t peer_index) {
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr || !peer->current_keypair.CanSendAt(wgnx::wireguard::GetMonotonicTime()) ||
        !PeerAt(peer_index).binding.HasEndpoint() ||
        !PeerAt(peer_index).binding.IsOpen()) {
        return wgnx::PeerErrorCode::InternalFailure;
    }

    return SendProtocolPeerPayload(peer_index, nullptr, 0, "keepalive").error;
}

void ScheduleProtocolTimer(
    std::size_t peer_index,
    wgnx::wireguard::TimerHook hook,
    wgnx::wireguard::TimerDeadline deadline) {
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
        deadline,
        peer->name);

    const auto &runtime = PeerAt(peer_index).Lifecycle();
    const std::uint32_t protocol_sequence =
        hook == wgnx::wireguard::TimerHook::RetransmitHandshake
            ? peer->handshake_retry.sequence_count
            : 0;
    const wgnx::wireguard::TimerToken token = PeerAt(peer_index).controller.Timers().Arm(
        hook,
        {
            .peer_index = static_cast<std::uint32_t>(peer_index),
            .activation_generation = runtime.activation_generation,
            .protocol_sequence = protocol_sequence,
        });
    g_horizon_dispatcher.ArmProtocolTimer(
        hook,
        token,
        wgnx::wireguard::TimerDeadlineToJiffies(deadline));
}

void CancelProtocolTimer(std::size_t peer_index, wgnx::wireguard::TimerHook hook) {
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer != nullptr) {
        wgnx::wireguard::wg_timers_cancel(
            std::addressof(peer->timers),
            hook,
            peer->name);
    }

    PeerAt(peer_index).controller.Timers().Cancel(hook);
    g_horizon_dispatcher.CancelProtocolTimer(hook);
}

void CancelAllTransportTimers() {
    if (g_state.peers.ActivePeerIndex() < 0) {
        g_horizon_dispatcher.CancelAllProtocolTimers();
        for (std::size_t peer_index = 0; peer_index < g_state.peers.Count(); ++peer_index) {
            PeerAt(peer_index).controller.Timers().CancelAll();
        }
        return;
    }

    const std::size_t peer_index = static_cast<std::size_t>(g_state.peers.ActivePeerIndex());
    CancelProtocolTimer(peer_index, wgnx::wireguard::TimerHook::RetransmitHandshake);
    CancelProtocolTimer(peer_index, wgnx::wireguard::TimerHook::SendKeepalive);
    CancelProtocolTimer(peer_index, wgnx::wireguard::TimerHook::Rekey);
    CancelProtocolTimer(peer_index, wgnx::wireguard::TimerHook::ZeroKeyMaterial);
}

[[maybe_unused]] void SchedulePayloadProbeTimeout() {
    g_horizon_dispatcher.ArmDebugProbeTimeout(
        wgnx::platform::get_jiffies_64() + DebugProbeTimeoutJiffies);
}

void CancelPayloadProbeTimeout() {
    g_horizon_dispatcher.CancelDebugProbeTimeout();
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
            wgnx::wireguard::TimerDeadlineFromJiffies(wgnx::platform::get_jiffies_64()) +
                std::chrono::seconds{peer->persistent_keepalive_interval});
    }
    ScheduleProtocolTimer(
        peer_index,
        wgnx::wireguard::TimerHook::Rekey,
        wgnx::wireguard::TimerDeadlineFromJiffies(wgnx::platform::get_jiffies_64()) +
            wgnx::wireguard::RekeyAfterTime);
    ScheduleProtocolTimer(
        peer_index,
        wgnx::wireguard::TimerHook::ZeroKeyMaterial,
        wgnx::wireguard::TimerDeadlineFromJiffies(wgnx::platform::get_jiffies_64()) +
            wgnx::wireguard::ZeroKeyMaterialAfterTime);
}

void ScheduleNextHandshakeRetry(std::size_t peer_index) {
    const auto jitter_ms = wgnx::platform::get_random_u32_below(
        wgnx::wireguard::RekeyTimeoutJitterMaxMs);
    ScheduleProtocolTimer(
        peer_index,
        wgnx::wireguard::TimerHook::RetransmitHandshake,
        wgnx::wireguard::TimerDeadlineFromJiffies(wgnx::platform::get_jiffies_64()) +
            wgnx::wireguard::GetHandshakeRetryDelay(jitter_ms));
}

wgnx::PeerErrorCode SendFreshHandshakeInitiation(
    std::size_t peer_index,
    const char *reason) {
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr) {
        return wgnx::PeerErrorCode::HandshakeInitFailed;
    }

    const auto transition = PeerAt(peer_index).controller.StartHandshake(
        PeerAt(peer_index).protocol.device,
        *peer);
    if (transition.action == wgnx::wireguard::HandshakeTransitionAction::Ignore) {
        logger::Log(
            "Coalesced WG handshake request peer=%zu activation=%u reason=%s staged_depth=%zu sequence=%u attempt=%u",
            peer_index,
            PeerAt(peer_index).Lifecycle().activation_generation,
            reason != nullptr ? reason : "outbound traffic",
            peer->staged_outbound_packets.Size(),
            peer->handshake_retry.sequence_count,
            peer->handshake_retry.send_attempts);
        return wgnx::PeerErrorCode::None;
    }
    if (transition.action != wgnx::wireguard::HandshakeTransitionAction::SendInitiation) {
        return wgnx::PeerErrorCode::HandshakeInitFailed;
    }

    const wgnx::PeerErrorCode send_error = SendProtocolPeerInitiation(peer_index);
    ScheduleNextHandshakeRetry(peer_index);
    logger::Log(
        "WG handshake attempt peer=%zu sequence=%u attempt=%u retry=%u reason=%s",
        peer_index,
        peer->handshake_retry.sequence_count,
        peer->handshake_retry.send_attempts,
        0U,
        reason != nullptr ? reason : "unspecified");
    return send_error;
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

    if (!PeerAt(peer_index).controller.CompleteSession(PeerAt(peer_index).protocol.device, *peer)) {
        return wgnx::PeerErrorCode::InternalFailure;
    }

    ScheduleProtocolSessionTimers(peer_index, peer);
    return wgnx::PeerErrorCode::None;
}

wgnx::PeerErrorCode EnsureHandshakeForOutboundTraffic(
    std::size_t peer_index,
    const char *reason) {
    const auto &runtime = PeerAt(peer_index).Lifecycle();
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr) {
        return wgnx::PeerErrorCode::InternalFailure;
    }

    logger::Log(
        "Starting WG handshake for outbound traffic peer=%zu activation=%u reason=%s staged_depth=%zu key_state=%s",
        peer_index,
        runtime.activation_generation,
        reason != nullptr ? reason : "outbound traffic",
        peer->staged_outbound_packets.Size(),
        wgnx::wireguard::GetKeypairSendStateName(
            peer->current_keypair.SendStateAt(wgnx::wireguard::GetMonotonicTime())));
    return SendFreshHandshakeInitiation(
        peer_index,
        reason != nullptr ? reason : "outbound traffic");
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
    wgnx::wireguard::wg_device_clear_index_registry(std::addressof(PeerAt(peer_index).protocol.device));
}

void ClearResolvedEndpoint(std::size_t peer_index) {
    PeerAt(peer_index).binding.ClearEndpoint();
}

void SetResolvedEndpoint(
    std::size_t peer_index,
    const wgnx::platform::endpoint_resolution_result &resolved) {
    PeerAt(peer_index).binding.SetEndpoint(resolved.resolved, resolved.text.data());
}

void ParseConfiguredPeerSecrets(std::size_t peer_index) {
    if (peer_index >= g_state.peers.Count()) {
        return;
    }

    auto &derived = PeerAt(peer_index).derived;
    auto &config = PeerAt(peer_index).config;
    derived = {};
    const bool private_key_valid = wgnx::wireguard::noise_parse_private_key(
        std::addressof(derived.local_private_key),
        config.private_key.data());
    const bool preshared_key_valid = config.preshared_key[0] == '\0' ||
        wgnx::wireguard::noise_parse_preshared_key(
            std::addressof(derived.preshared_key),
            config.preshared_key.data());
    derived.has_preshared_key = config.preshared_key[0] != '\0' && preshared_key_valid;
    derived.secrets_valid = private_key_valid && preshared_key_valid;
    if (private_key_valid && wgnx::wireguard::noise_derive_public_key_text(
            derived.derived_public_key,
            std::addressof(derived.local_private_key))) {
        derived.has_derived_public_key = true;
    }
    wgnx::wireguard::crypto::secure_clear(config.private_key.data(), config.private_key.size());
    wgnx::wireguard::crypto::secure_clear(config.preshared_key.data(), config.preshared_key.size());
}

void ClearInnerPacketStateLocked(const char *reason) {
    std::size_t tx_count = 0;
    for (std::size_t peer_index = 0; peer_index < g_state.peers.Count(); ++peer_index) {
        if (wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index)) {
            tx_count += wgnx::wireguard::wg_peer_clear_staged_outbound_packets(peer);
        }
    }
    const std::size_t rx_count = g_packet_channel.Release();
    if (tx_count != 0 || rx_count != 0) {
        logger::Log(
            "Cleared inner packet state reason=%s tx=%zu rx=%zu",
            reason != nullptr ? reason : "unspecified",
            tx_count,
            rx_count);
    }
}

void SetPeerInactive(std::size_t peer_index) {
    CancelPayloadProbeTimeout();
    ClearInnerPacketStateLocked("peer inactive");
    PeerAt(peer_index).binding.Reset();
    ResetProtocolPeer(peer_index);
    ClearResolvedEndpoint(peer_index);
    PeerAt(peer_index).Deactivate(GetRuntimeNowNs());
}

std::uint32_t SetPeerResolving(std::size_t peer_index) {
    CancelPayloadProbeTimeout();
    PeerAt(peer_index).binding.Reset();
    ClearResolvedEndpoint(peer_index);
    return PeerAt(peer_index).BeginActivation(GetRuntimeNowNs());
}

void SetPeerHandshaking(std::size_t peer_index) {
    const auto &runtime = PeerAt(peer_index).Lifecycle();
    AMS_ABORT_UNLESS(PeerAt(peer_index).EnterHandshaking(
        runtime.activation_generation,
        GetRuntimeNowNs()));
}

void SetPeerError(std::size_t peer_index, wgnx::PeerErrorStage stage, wgnx::PeerErrorCode code) {
    CancelPayloadProbeTimeout();
    ClearInnerPacketStateLocked("peer error");
    CloseRuntimeSocket(peer_index);
    PeerAt(peer_index).EnterError(stage, code, GetRuntimeNowNs());
    FailProtocolPeer(peer_index, wgnx::GetPeerErrorCodeName(code));
}

wgnx::PeerErrorCode ValidatePeerConfiguration(std::size_t peer_index) {
    const auto &config = PeerAt(peer_index).config;
    const auto &derived = PeerAt(peer_index).derived;
    if (config.public_key[0] == '\0' || config.allowed_ips[0] == '\0') {
        return wgnx::PeerErrorCode::ConfigInvalid;
    }
    if (!derived.secrets_valid ||
        !wgnx::wireguard::noise_is_valid_encoded_key(config.public_key.data())) {
        return wgnx::PeerErrorCode::KeyInvalid;
    }
    if (config.endpoint[0] == '\0') {
        return wgnx::PeerErrorCode::EndpointMissing;
    }

    return wgnx::PeerErrorCode::None;
}

void QueueEndpointResolve(std::size_t peer_index) {
    const auto &config = PeerAt(peer_index).config;
    const auto &runtime = PeerAt(peer_index).Lifecycle();
    g_resolve_request = {};
    g_resolve_request.pending = true;
    g_resolve_request.peer_index = peer_index;
    g_resolve_request.activation_generation = runtime.activation_generation;
    std::snprintf(g_resolve_request.endpoint, sizeof(g_resolve_request.endpoint), "%s", config.endpoint.data());
    g_horizon_dispatcher.QueueResolve();
}

void QueueReceiveWork() {
    g_horizon_dispatcher.QueueReceive();
}

[[maybe_unused]] void QueuePayloadSubmissionWork() {
    g_horizon_dispatcher.QueueDebugPayloadSubmission();
}

void QueueInnerPacketSubmissionWork() {
    g_horizon_dispatcher.QueueInnerPacketSubmission();
}

[[maybe_unused]] bool QueuePayloadSubmissionRequestLocked(wgnx::DebugTriggerAction action) {
    if (g_state.peers.ActivePeerIndex() < 0) {
        return false;
    }

    const std::size_t peer_index = static_cast<std::size_t>(g_state.peers.ActivePeerIndex());
    const auto &runtime = PeerAt(peer_index).Lifecycle();
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (runtime.state != wgnx::PeerRuntimeState::Active ||
        !PeerAt(peer_index).binding.IsOpen() ||
        peer == nullptr ||
        !peer->current_keypair.CanSendAt(wgnx::wireguard::GetMonotonicTime())) {
        return false;
    }
    if (g_payload_submission_request.pending || IsDebugProbePending(PeerAt(peer_index))) {
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
    SetDebugProbeState(PeerAt(peer_index), action, wgnx::DebugProbeStatus::Queued);
    return true;
}

void StartPeerRuntime(std::size_t peer_index) {
    const auto &config = PeerAt(peer_index).config;
    const wgnx::PeerErrorCode config_error = ValidatePeerConfiguration(peer_index);
    if (config_error == wgnx::PeerErrorCode::ConfigInvalid) {
        SetPeerError(peer_index, wgnx::PeerErrorStage::Config, config_error);
        return;
    }
    if (config_error != wgnx::PeerErrorCode::None) {
        SetPeerError(peer_index, wgnx::PeerErrorStage::ResolveEndpoint, config_error);
        return;
    }

    const std::uint32_t activation_generation = SetPeerResolving(peer_index);
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
    return PeerAt(peer_index).BuildInfo(
        GetRuntimeNowNs(),
        static_cast<std::int32_t>(peer_index) == g_state.peers.ActivePeerIndex(),
        static_cast<std::int32_t>(peer_index) == g_state.peers.AutoStartPeerIndex());
}

bool HasRuntimeErrors() {
    for (std::size_t i = 0; i < g_state.peers.Count(); ++i) {
        if (PeerAt(i).Lifecycle().state == wgnx::PeerRuntimeState::Error) {
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
        const bool assigned = g_state.peers.Assign(
            std::span<const wgnx::PeerConfigEntry>(config.peers).first(config.peer_count));
        AMS_ABORT_UNLESS(assigned);

        for (std::size_t i = 0; i < config.peer_count; ++i) {
            auto &entry = config.peers[i];
            ParseConfiguredPeerSecrets(i);
            SetPeerInactive(i);

            if (has_auto_start_name && std::strncmp(entry.name.data(), auto_start_name, entry.name.size()) == 0) {
                AMS_ABORT_UNLESS(g_state.peers.SetAutoStartPeerIndex(static_cast<std::int32_t>(i)));
            }
            wgnx::wireguard::crypto::secure_clear(
                entry.private_key.data(),
                entry.private_key.size());
            wgnx::wireguard::crypto::secure_clear(
                entry.preshared_key.data(),
                entry.preshared_key.size());
        }
    } else {
        g_state.peers.ClearConfiguration();
    }

    g_state.initialized = true;
    logger::Log("Initialized peer state with %u configured peer(s)", g_state.peers.Count());
}

bool IsValidPeerIndex(std::int32_t peer_index) {
    return runtime::IsValidPeerSelection(peer_index, g_state.peers.Count());
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
    std::uint32_t *out_socket_generation,
    wgnx::platform::socket_handle *out_socket) {
    if (out_peer_index == nullptr || out_activation_generation == nullptr ||
        out_socket_generation == nullptr || out_socket == nullptr) {
        return false;
    }

    std::scoped_lock lock(g_state_mutex);
    if (g_state.peers.ActivePeerIndex() < 0) {
        return false;
    }

    const std::size_t peer_index = static_cast<std::size_t>(g_state.peers.ActivePeerIndex());
    const auto &runtime = PeerAt(peer_index).Lifecycle();
    const auto &binding = PeerAt(peer_index).binding;
    if ((runtime.state != wgnx::PeerRuntimeState::Handshaking &&
         runtime.state != wgnx::PeerRuntimeState::Active) ||
        !binding.IsOpen()) {
        return false;
    }

    *out_peer_index = peer_index;
    *out_activation_generation = runtime.activation_generation;
    *out_socket_generation = binding.Generation();
    *out_socket = binding.Socket();
    return true;
}

void CommitResolveResult(const ResolveRequest &request, const wgnx::platform::endpoint_resolution_result &result) {
    std::scoped_lock lock(g_state_mutex);
    if (request.peer_index >= g_state.peers.Count()) {
        return;
    }

    const auto &runtime = PeerAt(request.peer_index).Lifecycle();
    if (g_state.peers.ActivePeerIndex() != static_cast<std::int32_t>(request.peer_index) ||
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

    SetResolvedEndpoint(request.peer_index, result);
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
    const wgnx::PeerErrorCode send_error = SendFreshHandshakeInitiation(
        request.peer_index,
        "initial handshake");
    if (send_error != wgnx::PeerErrorCode::None) {
        if (!IsRecoverableTransportIoError(send_error)) {
            SetPeerError(request.peer_index, wgnx::PeerErrorStage::Transport, send_error);
            return;
        }
        LogRecoverableTransportIoError(request.peer_index, send_error, "initial handshake");
    }
    SetPeerHandshaking(request.peer_index);
    QueueReceiveWork();
    logger::Log("Endpoint resolved for peer %zu activation=%u -> %s",
        request.peer_index,
        request.activation_generation,
        PeerAt(request.peer_index).binding.EndpointText());
}

void EnqueueReceivedInnerIpv4PacketLocked(
    std::size_t peer_index,
    std::uint32_t activation_generation,
    std::span<const std::uint8_t> packet) {
    if (g_packet_channel.OwnerProcessId() == 0) {
        logger::Log(
            "Dropped decrypted inner packet peer=%zu activation=%u bytes=%zu reason=no_consumer",
            peer_index,
            activation_generation,
            packet.size());
        return;
    }

    const auto validation = wgnx::wireguard::ValidateInnerIpv4Packet(packet);
    if (validation != wgnx::wireguard::InnerIpv4ValidationError::None) {
        logger::Log(
            "Dropped decrypted inner packet peer=%zu activation=%u bytes=%zu validation=%s",
            peer_index,
            activation_generation,
            packet.size(),
            wgnx::wireguard::GetInnerIpv4ValidationErrorName(validation));
        return;
    }

    wgnx::wireguard::InnerPacketRecord record{};
    record.packet_id = g_packet_channel.AllocatePacketId();
    record.owner_process_id = g_packet_channel.OwnerProcessId();
    record.activation_generation = activation_generation;
    record.peer_index = static_cast<std::uint32_t>(peer_index);
    record.size = static_cast<std::uint16_t>(packet.size());
    std::memcpy(record.bytes.data(), packet.data(), packet.size());
    if (g_packet_channel.PushReceived(record) == wgnx::wireguard::QueuePushResult::Full) {
        logger::Log(
            "Dropped decrypted inner packet peer=%zu activation=%u bytes=%zu reason=rx_queue_full capacity=%zu",
            peer_index,
            activation_generation,
            packet.size(),
            g_packet_channel.ReceivedCapacity());
        return;
    }

    logger::Log(
        "Queued decrypted inner packet id=%llu peer=%zu activation=%u bytes=%zu depth=%zu",
        static_cast<unsigned long long>(record.packet_id),
        peer_index,
        activation_generation,
        packet.size(),
        g_packet_channel.ReceivedSize());
}

void ExecuteRuntimeEffects(const runtime::EffectBatch &effects) {
    for (const auto &effect : effects) {
        std::visit(
            [](const auto &value) {
                using Effect = std::remove_cvref_t<decltype(value)>;
                if constexpr (std::is_same_v<Effect, runtime::QueueInnerPacketSubmissionEffect>) {
                    bool current = false;
                    {
                        std::scoped_lock lock(g_state_mutex);
                        current = value.peer.peer_index < g_state.peers.Count() &&
                                  g_state.peers.ActivePeerIndex() ==
                                      static_cast<std::int32_t>(value.peer.peer_index) &&
                                  PeerAt(value.peer.peer_index).IsCurrentActivation(
                                      value.peer.activation_generation) &&
                                  PeerAt(value.peer.peer_index).Lifecycle().state ==
                                      wgnx::PeerRuntimeState::Active;
                    }
                    if (current) {
                        QueueInnerPacketSubmissionWork();
                    }
                }
            },
            effect);
    }
}

void CommitReceivedPacket(
    std::size_t peer_index,
    std::uint32_t activation_generation,
    std::uint32_t socket_generation,
    wgnx::platform::socket_handle socket,
    std::span<const std::uint8_t> packet,
    const wgnx::platform::endpoint &source) {
    std::unique_lock lock(g_state_mutex);
    if (peer_index >= g_state.peers.Count() || g_state.peers.ActivePeerIndex() != static_cast<std::int32_t>(peer_index)) {
        return;
    }

    const auto &runtime = PeerAt(peer_index).Lifecycle();
    auto &binding = PeerAt(peer_index).binding;
    if (runtime.activation_generation != activation_generation ||
        !binding.Matches(socket_generation, socket) ||
        (runtime.state != wgnx::PeerRuntimeState::Handshaking &&
         runtime.state != wgnx::PeerRuntimeState::Active)) {
        return;
    }

    PeerAt(peer_index).RecordReceivedBytes(packet.size(), GetRuntimeNowNs());

    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr) {
        SetPeerError(peer_index, wgnx::PeerErrorStage::Internal, wgnx::PeerErrorCode::InternalFailure);
        return;
    }

    const wgnx::wireguard::ParseResult type_result = wgnx::wireguard::InspectMessageType(packet);
    if (!type_result.success) {
        logger::Log(
            "Rejected UDP packet for peer %zu bytes=%zu source_family=%s inspect_err=%s",
            peer_index,
            packet.size(),
            wgnx::GetPeerResolvedFamilyName(static_cast<wgnx::PeerResolvedFamily>(source.family)),
            wgnx::wireguard::GetParseErrorName(type_result.error));
        return;
    }

    if (type_result.type == wgnx::wireguard::MessageType::TransportData) {
        char source_text[sizeof(wgnx::PeerInfo::resolved_endpoint)] = {};
        char expected_text[sizeof(wgnx::PeerInfo::resolved_endpoint)] = {};
        FormatEndpointText(source, source_text, sizeof(source_text));
        FormatEndpointText(binding.Endpoint(), expected_text, sizeof(expected_text));

        if (!binding.HasEndpoint() || !EndpointsEqual(source, binding.Endpoint())) {
            logger::Log(
                "Rejected WG transport data for peer %zu bytes=%zu source=%s expected=%s reason=source_mismatch",
                peer_index,
                packet.size(),
                source_text,
                expected_text);
            return;
        }

        wgnx::wireguard::IncomingTransportDataResult decrypt_result{};
        const wgnx::wireguard::TransportDataError decrypt_error =
            wgnx::wireguard::noise_consume_incoming_transport_data_packet(
                packet,
                PeerAt(peer_index).protocol.device,
                *peer,
                g_receive_payload_buffer,
                decrypt_result);
        if (decrypt_error != wgnx::wireguard::TransportDataError::None) {
            logger::Log(
                "Rejected WG transport data for peer %zu bytes=%zu source=%s slot=%s err=%s",
                peer_index,
                packet.size(),
                source_text,
                GetIndexSlotName(decrypt_result.slot),
                wgnx::wireguard::GetTransportDataErrorName(decrypt_error));
            return;
        }

        logger::Log(
            "Accepted WG transport data for peer %zu bytes=%zu payload=%zu source=%s slot=%s counter=%llu",
            peer_index,
            packet.size(),
            decrypt_result.decrypt.payload_size,
            source_text,
            GetIndexSlotName(decrypt_result.slot),
            static_cast<unsigned long long>(decrypt_result.decrypt.header.counter));

        if (decrypt_result.decrypt.payload_size == 0) {
            logger::Log("Accepted WG keepalive payload for peer %zu", peer_index);
            return;
        }

        const auto padded_payload = std::span<const std::uint8_t>(
            g_receive_payload_buffer.data(),
            decrypt_result.decrypt.payload_size);
        std::size_t inner_packet_size = 0;
        const auto inner_validation = wgnx::wireguard::ValidatePaddedInnerIpv4Packet(
            padded_payload,
            std::addressof(inner_packet_size));
        if (inner_validation != wgnx::wireguard::InnerIpv4ValidationError::None) {
            logger::Log(
                "Dropped decrypted inner packet peer=%zu activation=%u bytes=%zu validation=%s",
                peer_index,
                activation_generation,
                padded_payload.size(),
                wgnx::wireguard::GetInnerIpv4ValidationErrorName(inner_validation));
            return;
        }
        const auto inner_packet = padded_payload.first(inner_packet_size);
        if (inner_packet.size() != padded_payload.size()) {
            logger::Log(
                "Removed WG transport padding for peer %zu payload=%zu inner=%zu padding=%zu",
                peer_index,
                padded_payload.size(),
                inner_packet.size(),
                padded_payload.size() - inner_packet.size());
        }

        wgnx::wireguard::DebugProbeReplyInfo reply_info{};
        const wgnx::wireguard::DebugProbeReplyValidation reply_validation =
            wgnx::wireguard::ValidateDebugIcmpEchoReply(
                inner_packet,
                PeerAt(peer_index).config.address.data(),
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
                PeerAt(peer_index),
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
                PeerAt(peer_index),
                runtime.debug_probe_action,
                wgnx::DebugProbeStatus::ReplyRejected);
            logger::Log(
                "Rejected debug ICMP reply metadata for peer %zu validation=%s payload=%zu",
                peer_index,
                wgnx::wireguard::GetDebugProbeReplyValidationName(reply_validation),
                decrypt_result.decrypt.payload_size);
            return;
        }

        EnqueueReceivedInnerIpv4PacketLocked(
            peer_index,
            activation_generation,
            inner_packet);
        return;
    }

    const auto outcome = wgnx::wireguard::noise_handshake_consume_incoming_packet(
        packet,
        std::addressof(PeerAt(peer_index).protocol.device),
        peer);
    logger::Log(
        "Received UDP packet for peer %zu bytes=%zu source_family=%s outcome=%s",
        peer_index,
        packet.size(),
        wgnx::GetPeerResolvedFamilyName(static_cast<wgnx::PeerResolvedFamily>(source.family)),
        wgnx::wireguard::GetHandshakePacketOutcomeName(outcome));

    switch (outcome) {
        case wgnx::wireguard::HandshakePacketOutcome::Invalid:
            return;
        case wgnx::wireguard::HandshakePacketOutcome::CookieReplyConsumed: {
            logger::Log(
                "Stored WG cookie reply peer=%zu sequence=%u attempt=%u; applying it to the next fresh retry",
                peer_index,
                peer->handshake_retry.sequence_count,
                peer->handshake_retry.send_attempts);
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
                if (!IsRecoverableTransportIoError(keepalive_error)) {
                    SetPeerError(peer_index, wgnx::PeerErrorStage::Transport, keepalive_error);
                    return;
                }
                LogRecoverableTransportIoError(peer_index, keepalive_error, "session confirmation keepalive");
            }
            const runtime::EffectBatch effects = g_runtime_coordinator.Dispatch(
                runtime::SessionEstablishedEvent{
                    .peer = {
                        .peer_index = static_cast<std::uint32_t>(peer_index),
                        .activation_generation = activation_generation,
                    },
                    .occurred_at = GetRuntimeNowNs(),
                });
            lock.unlock();
            ExecuteRuntimeEffects(effects);
            return;
        }
    }
}

void CommitReceiveFailure(
    std::size_t peer_index,
    std::uint32_t activation_generation,
    std::uint32_t socket_generation,
    wgnx::platform::socket_handle socket,
    wgnx::platform::socket_error error) {
    std::scoped_lock lock(g_state_mutex);
    if (peer_index >= g_state.peers.Count() || g_state.peers.ActivePeerIndex() != static_cast<std::int32_t>(peer_index)) {
        return;
    }

    const auto &runtime = PeerAt(peer_index).Lifecycle();
    const auto &binding = PeerAt(peer_index).binding;
    if (runtime.activation_generation != activation_generation ||
        !binding.Matches(socket_generation, socket) ||
        (runtime.state != wgnx::PeerRuntimeState::Handshaking &&
         runtime.state != wgnx::PeerRuntimeState::Active)) {
        return;
    }

    logger::Log(
        "UDP receive failed for peer %zu endpoint=%s err=%u",
        peer_index,
        binding.EndpointText(),
        static_cast<unsigned int>(error));
    const wgnx::PeerErrorCode receive_error = MapSocketErrorToPeerErrorCode(error);
    if (IsRecoverableTransportIoError(receive_error)) {
        LogRecoverableTransportIoError(peer_index, receive_error, "receive worker");
        logger::Log(
            "WG receive worker stopped after nonterminal transport failure peer=%zu activation=%u socket_generation=%u socket=%d",
            peer_index,
            activation_generation,
            socket_generation,
            static_cast<int>(socket));
        return;
    }
    SetPeerError(peer_index, wgnx::PeerErrorStage::Transport, receive_error);
}

[[maybe_unused]] void CommitPayloadSubmission(const PayloadSubmissionRequest &request) {
    std::scoped_lock lock(g_state_mutex);
    if (request.peer_index >= g_state.peers.Count() ||
        g_state.peers.ActivePeerIndex() != static_cast<std::int32_t>(request.peer_index)) {
        logger::Log(
            "Discarded queued payload submission for stale peer %zu activation=%u",
            request.peer_index,
            request.activation_generation);
        return;
    }

    const auto &runtime = PeerAt(request.peer_index).Lifecycle();
    if (runtime.activation_generation != request.activation_generation ||
        runtime.state != wgnx::PeerRuntimeState::Active ||
        !PeerAt(request.peer_index).binding.IsOpen()) {
        if (runtime.activation_generation == request.activation_generation) {
            SetDebugProbeState(
                PeerAt(request.peer_index),
                request.action,
                wgnx::DebugProbeStatus::InvalidState);
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
        PeerAt(request.peer_index).config.address.data(),
        request.action,
        request.activation_generation,
        request.peer_index,
        wgnx::platform::get_random_u32_below(std::numeric_limits<std::uint32_t>::max()));
    if (payload_size == 0) {
        char target_text[16] = {};
        std::array<std::uint8_t, 4> target_ipv4{};
        wgnx::wireguard::CopyDebugTargetIpv4(request.action, target_ipv4);
        wgnx::wireguard::FormatIpv4Text(target_ipv4, target_text, sizeof(target_text));
        SetDebugProbeState(
            PeerAt(request.peer_index),
            request.action,
            wgnx::DebugProbeStatus::BuildFailed);
        logger::Log(
            "Failed to build debug ICMP packet for peer %zu activation=%u action=%s source=%s target=%s",
            request.peer_index,
            request.activation_generation,
            wgnx::GetDebugTriggerActionName(request.action),
            PeerAt(request.peer_index).config.address.data(),
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
        PeerAt(request.peer_index).config.address.data(),
        target_text,
        payload_size);
    const wgnx::PeerErrorCode send_error = SendInnerIpv4PacketLocked(
        request.peer_index,
        std::span<const std::uint8_t>(payload.data(), payload_size),
        wgnx::GetDebugTriggerActionName(request.action));
    if (send_error != wgnx::PeerErrorCode::None) {
        SetDebugProbeState(
            PeerAt(request.peer_index),
            request.action,
            wgnx::DebugProbeStatus::SendFailed);
        if (IsRecoverableTransportIoError(send_error)) {
            LogRecoverableTransportIoError(request.peer_index, send_error, "debug payload");
        } else {
            SetPeerError(request.peer_index, GetPayloadSubmissionErrorStage(send_error), send_error);
        }
        return;
    }

    SetDebugProbeState(
        PeerAt(request.peer_index),
        request.action,
        wgnx::DebugProbeStatus::Sent);
    SchedulePayloadProbeTimeout();
}

void ResolverWorkMain(wgnx::platform::work_struct *) {
    ResolveRequest request{};
    while (DequeueResolveRequest(std::addressof(request))) {
        const auto result = wgnx::platform::resolve_endpoint(request.endpoint);
        CommitResolveResult(request, result);
    }
}

void ProcessPendingBindBump() {
    std::scoped_lock lock(g_state_mutex);
    if (!g_bind_bump_request.pending) {
        return;
    }

    const BindBumpRequest request = g_bind_bump_request;
    g_bind_bump_request = {};
    if (request.peer_index >= g_state.peers.Count() ||
        g_state.peers.ActivePeerIndex() != static_cast<std::int32_t>(request.peer_index)) {
        logger::Log(
            "Discarded UDP bind bump peer=%zu activation=%u reason=inactive_peer",
            request.peer_index,
            request.activation_generation);
        return;
    }

    const auto &runtime = PeerAt(request.peer_index).Lifecycle();
    auto &binding = PeerAt(request.peer_index).binding;
    if (runtime.activation_generation != request.activation_generation ||
        (runtime.state != wgnx::PeerRuntimeState::Handshaking &&
         runtime.state != wgnx::PeerRuntimeState::Active) ||
        !binding.HasEndpoint()) {
        logger::Log(
            "Discarded UDP bind bump peer=%zu activation=%u reason=stale_runtime state=%s current_activation=%u",
            request.peer_index,
            request.activation_generation,
            wgnx::GetPeerRuntimeStateName(runtime.state),
            runtime.activation_generation);
        return;
    }

    const std::uint32_t old_socket_generation = binding.Generation();
    const auto old_socket = binding.Socket();
    logger::Log(
        "Starting UDP bind bump peer=%zu activation=%u old_socket_generation=%u old_socket=%d state=%s",
        request.peer_index,
        request.activation_generation,
        old_socket_generation,
        static_cast<int>(old_socket),
        wgnx::GetPeerRuntimeStateName(runtime.state));

    const wgnx::PeerErrorCode open_error = OpenRuntimeSocket(request.peer_index);
    if (open_error != wgnx::PeerErrorCode::None) {
        logger::Log(
            "UDP bind bump open failed peer=%zu activation=%u code=%s; peer state preserved",
            request.peer_index,
            request.activation_generation,
            wgnx::GetPeerErrorCodeName(open_error));
        return;
    }

    const char *resume_action = nullptr;
    wgnx::PeerErrorCode send_error = wgnx::PeerErrorCode::None;
    if (runtime.state == wgnx::PeerRuntimeState::Active) {
        if (wgnx::wireguard::wg_peer *peer = GetProtocolPeer(request.peer_index);
            peer != nullptr && peer->current_keypair.CanSendAt(wgnx::wireguard::GetMonotonicTime())) {
            resume_action = "keepalive";
            send_error = SendProtocolPeerKeepalive(request.peer_index);
        } else {
            resume_action = "handshake_initiation";
            send_error = EnsureHandshakeForOutboundTraffic(request.peer_index, "UDP bind bump");
        }
    } else {
        resume_action = "handshake_initiation";
        send_error = EnsureHandshakeForOutboundTraffic(request.peer_index, "UDP bind bump");
    }

    if (send_error != wgnx::PeerErrorCode::None) {
        logger::Log(
            "UDP bind bump resume send failed peer=%zu activation=%u socket_generation=%u action=%s code=%s; peer state preserved",
            request.peer_index,
            request.activation_generation,
            binding.Generation(),
            resume_action,
            wgnx::GetPeerErrorCodeName(send_error));
    } else {
        logger::Log(
            "Completed UDP bind bump peer=%zu activation=%u socket_generation=%u socket=%d action=%s",
            request.peer_index,
            request.activation_generation,
            binding.Generation(),
            static_cast<int>(binding.Socket()),
            resume_action);
    }
}

void ReceiveWorkMain(wgnx::platform::work_struct *) {
    wgnx::platform::static_packet_buffer<ReceivePacketCapacity> packet;
    while (true) {
        ProcessPendingBindBump();

        std::size_t peer_index = 0;
        std::uint32_t activation_generation = 0;
        std::uint32_t socket_generation = 0;
        wgnx::platform::socket_handle socket = wgnx::platform::InvalidSocket;
        if (!SnapshotReceiveRuntime(
                std::addressof(peer_index),
                std::addressof(activation_generation),
                std::addressof(socket_generation),
                std::addressof(socket))) {
            return;
        }

        wgnx::platform::endpoint source{};
        std::size_t received = 0;
        logger::Log(
            "WG receive iteration begin peer=%zu activation=%u socket_generation=%u socket=%d",
            peer_index,
            activation_generation,
            socket_generation,
            static_cast<int>(socket));
        const auto receive_error = wgnx::platform::udp_receive(
            socket,
            packet.storage,
            std::addressof(received),
            std::addressof(source));
        logger::Log(
            "WG receive iteration end peer=%zu activation=%u socket_generation=%u socket=%d error=%u bytes=%zu",
            peer_index,
            activation_generation,
            socket_generation,
            static_cast<int>(socket),
            static_cast<unsigned int>(receive_error),
            received);
        if (receive_error != wgnx::platform::socket_error::none) {
            CommitReceiveFailure(peer_index, activation_generation, socket_generation, socket, receive_error);
            return;
        }
        if (received == 0) {
            continue;
        }

        static_cast<void>(wgnx::platform::packet_set_len(std::addressof(packet.packet), received));
        CommitReceivedPacket(
            peer_index,
            activation_generation,
            socket_generation,
            socket,
            packet.packet.bytes(),
            source);
        wgnx::platform::packet_clear(std::addressof(packet.packet));
    }
}

[[maybe_unused]] void PayloadSubmissionWorkMain(wgnx::platform::work_struct *) {
    PayloadSubmissionRequest request{};
    while (DequeuePayloadSubmissionRequest(std::addressof(request))) {
        CommitPayloadSubmission(request);
    }
}

[[maybe_unused]] void InnerPacketSubmissionWorkMain(wgnx::platform::work_struct *) {
    while (true) {
        std::scoped_lock lock(g_state_mutex);
        if (g_state.peers.ActivePeerIndex() < 0) {
            return;
        }

        const std::size_t active_peer_index = static_cast<std::size_t>(g_state.peers.ActivePeerIndex());
        wgnx::wireguard::wg_peer *peer = GetProtocolPeer(active_peer_index);
        if (peer == nullptr) {
            return;
        }

        auto &queue = peer->staged_outbound_packets;
        const auto *front = queue.Front();
        if (front == nullptr) {
            return;
        }

        if (front->peer_index >= g_state.peers.Count() ||
            g_state.peers.ActivePeerIndex() != static_cast<std::int32_t>(front->peer_index)) {
            wgnx::wireguard::InnerPacketRecord stale{};
            static_cast<void>(queue.Pop(
                std::addressof(stale),
                wgnx::wireguard::QueueDisposition::Stale));
            logger::Log(
                "Discarded queued inner packet id=%llu reason=stale_peer",
                static_cast<unsigned long long>(stale.packet_id));
            continue;
        }

        const auto &runtime = PeerAt(front->peer_index).Lifecycle();
        if (runtime.activation_generation != front->activation_generation) {
            wgnx::wireguard::InnerPacketRecord stale{};
            static_cast<void>(queue.Pop(
                std::addressof(stale),
                wgnx::wireguard::QueueDisposition::Stale));
            logger::Log(
                "Discarded queued inner packet id=%llu reason=stale_activation queued=%u current=%u",
                static_cast<unsigned long long>(stale.packet_id),
                stale.activation_generation,
                runtime.activation_generation);
            continue;
        }
        if (runtime.state == wgnx::PeerRuntimeState::ResolvingEndpoint) {
            return;
        }
        if (runtime.state != wgnx::PeerRuntimeState::Handshaking &&
            runtime.state != wgnx::PeerRuntimeState::Active) {
            wgnx::wireguard::InnerPacketRecord unavailable{};
            static_cast<void>(queue.Pop(
                std::addressof(unavailable),
                wgnx::wireguard::QueueDisposition::Unavailable));
            logger::Log(
                "Discarded queued inner packet id=%llu reason=tunnel_unavailable state=%s",
                static_cast<unsigned long long>(unavailable.packet_id),
                wgnx::GetPeerRuntimeStateName(runtime.state));
            continue;
        }

        const auto staging_action = wgnx::wireguard::wg_peer_get_outbound_staging_action(
            *peer,
            wgnx::wireguard::GetMonotonicTime());
        if (staging_action == wgnx::wireguard::OutboundStagingAction::InitiateHandshake) {
            const wgnx::PeerErrorCode handshake_error = EnsureHandshakeForOutboundTraffic(
                active_peer_index,
                "staged outbound traffic");
            if (handshake_error != wgnx::PeerErrorCode::None) {
                if (IsRecoverableTransportIoError(handshake_error)) {
                    LogRecoverableTransportIoError(
                        active_peer_index,
                        handshake_error,
                        "staged outbound handshake");
                } else {
                    SetPeerError(
                        active_peer_index,
                        handshake_error == wgnx::PeerErrorCode::HandshakeInitFailed
                            ? wgnx::PeerErrorStage::Handshake
                            : wgnx::PeerErrorStage::Transport,
                        handshake_error);
                }
            }
            return;
        }
        if (staging_action != wgnx::wireguard::OutboundStagingAction::Send) {
            return;
        }

        const wgnx::wireguard::InnerPacketRecord record = *front;
        const PayloadSendResult send_result = SendInnerIpv4PacketDetailedLocked(
            record.peer_index,
            std::span<const std::uint8_t>(record.bytes.data(), record.size),
            "packet-api");
        const wgnx::PeerErrorCode send_error = send_result.error;
        const auto transition = PeerAt(front->peer_index).controller.ApplyStagedSendOutcome(
            *peer,
            send_result.outcome);
        if (send_error != wgnx::PeerErrorCode::None) {
            if (transition.action == wgnx::wireguard::StagedPacketAction::InitiateHandshake) {
                logger::Log(
                    "Retained queued inner packet id=%llu peer=%u reason=key_became_unusable error=%s",
                    static_cast<unsigned long long>(record.packet_id),
                    record.peer_index,
                    wgnx::GetPeerErrorCodeName(send_error));
                const wgnx::PeerErrorCode handshake_error = EnsureHandshakeForOutboundTraffic(
                    active_peer_index,
                    "key changed during staged send");
                if (handshake_error != wgnx::PeerErrorCode::None) {
                    if (IsRecoverableTransportIoError(handshake_error)) {
                        LogRecoverableTransportIoError(
                            active_peer_index,
                            handshake_error,
                            "key-change handshake");
                    } else {
                        SetPeerError(
                            active_peer_index,
                            handshake_error == wgnx::PeerErrorCode::HandshakeInitFailed
                                ? wgnx::PeerErrorStage::Handshake
                                : wgnx::PeerErrorStage::Transport,
                            handshake_error);
                    }
                }
                return;
            }

            logger::Log(
                "Failed queued inner packet id=%llu peer=%u activation=%u error=%s",
                static_cast<unsigned long long>(record.packet_id),
                record.peer_index,
                record.activation_generation,
                wgnx::GetPeerErrorCodeName(send_error));
            if (transition.retired &&
                transition.disposition == wgnx::wireguard::QueueDisposition::SendFailed) {
                LogRecoverableTransportIoError(record.peer_index, send_error, "packet API");
                continue;
            }
            SetPeerError(record.peer_index, GetPayloadSubmissionErrorStage(send_error), send_error);
            return;
        }

        logger::Log(
            "Sent queued inner packet id=%llu peer=%u activation=%u bytes=%u remaining=%zu",
            static_cast<unsigned long long>(record.packet_id),
            record.peer_index,
            record.activation_generation,
            static_cast<unsigned int>(record.size),
            transition.remaining);
    }
}

[[maybe_unused]] void CommitPayloadProbeTimeout() {
    std::scoped_lock lock(g_state_mutex);
    if (g_state.peers.ActivePeerIndex() < 0) {
        return;
    }

    const std::size_t peer_index = static_cast<std::size_t>(g_state.peers.ActivePeerIndex());
    const auto &runtime = PeerAt(peer_index).Lifecycle();
    if (runtime.state != wgnx::PeerRuntimeState::Active ||
        runtime.debug_probe_status != wgnx::DebugProbeStatus::Sent ||
        runtime.debug_probe_action == wgnx::DebugTriggerAction::None) {
        return;
    }

    const auto action = runtime.debug_probe_action;
    SetDebugProbeState(PeerAt(peer_index), action, wgnx::DebugProbeStatus::TimedOut);
    logger::Log(
        "Debug payload probe timed out for peer %zu action=%s activation=%u",
        peer_index,
        wgnx::GetDebugTriggerActionName(action),
        runtime.activation_generation);
}

[[maybe_unused]] void PayloadProbeTimeoutWorkMain(wgnx::platform::work_struct *) {
    CommitPayloadProbeTimeout();
}

void RunTimerAction(
    wgnx::wireguard::TimerHook hook,
    const wgnx::wireguard::TimerToken &token) {
    std::scoped_lock lock(g_state_mutex);
    if (g_state.peers.ActivePeerIndex() < 0 || !token.IsValid() || token.hook != hook) {
        return;
    }

    const std::size_t peer_index = static_cast<std::size_t>(g_state.peers.ActivePeerIndex());
    const auto &runtime = PeerAt(peer_index).Lifecycle();
    wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
    if (peer == nullptr) {
        return;
    }

    const wgnx::wireguard::TimerOwner current_owner = {
        .peer_index = static_cast<std::uint32_t>(peer_index),
        .activation_generation = runtime.activation_generation,
        .protocol_sequence = hook == wgnx::wireguard::TimerHook::RetransmitHandshake
            ? peer->handshake_retry.sequence_count
            : 0,
    };
    if (!PeerAt(peer_index).controller.Timers().IsCurrent(token, current_owner)) {
        logger::Log(
            "Ignored stale WG timer action hook=%s token_peer=%u current_peer=%zu token_activation=%u current_activation=%u token_sequence=%u current_sequence=%u generation=%u",
            wgnx::wireguard::GetTimerHookName(hook),
            token.owner.peer_index,
            peer_index,
            token.owner.activation_generation,
            runtime.activation_generation,
            token.owner.protocol_sequence,
            current_owner.protocol_sequence,
            token.generation);
        return;
    }

    if (PeerAt(peer_index).binding.IsSuspended() &&
        hook != wgnx::wireguard::TimerHook::ZeroKeyMaterial) {
        CancelProtocolTimer(peer_index, hook);
        logger::Log(
            "WG timer canceled for suspended UDP transport peer=%zu activation=%u hook=%s",
            peer_index,
            runtime.activation_generation,
            wgnx::wireguard::GetTimerHookName(hook));
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
                !peer->handshake_retry.active) {
                return;
            }

            CancelProtocolTimer(peer_index, hook);
            const auto transition = PeerAt(peer_index).controller.HandleHandshakeRetryTimer(
                PeerAt(peer_index).protocol.device,
                *peer);
            if (transition.action == wgnx::wireguard::HandshakeTransitionAction::Ignore) {
                return;
            }
            if (transition.action == wgnx::wireguard::HandshakeTransitionAction::Exhausted) {
                if (!peer->timers.zero_key_material.pending) {
                    ScheduleProtocolTimer(
                        peer_index,
                        wgnx::wireguard::TimerHook::ZeroKeyMaterial,
                        wgnx::wireguard::TimerDeadlineFromJiffies(wgnx::platform::get_jiffies_64()) +
                            wgnx::wireguard::ZeroKeyMaterialAfterTime);
                }
                logger::Log(
                    "WG handshake retry sequence exhausted peer=%zu endpoint=%s sequence=%u attempts=%u dropped_staged=%zu; peer and UDP binding preserved",
                    peer_index,
                    PeerAt(peer_index).binding.EndpointText(),
                    peer->handshake_retry.sequence_count,
                    peer->handshake_retry.send_attempts,
                    transition.dropped_staged_packets);
                return;
            }

            if (transition.action != wgnx::wireguard::HandshakeTransitionAction::SendInitiation) {
                SetPeerError(
                    peer_index,
                    wgnx::PeerErrorStage::Handshake,
                    wgnx::PeerErrorCode::HandshakeInitFailed);
                return;
            }
            const wgnx::PeerErrorCode retry_error = SendProtocolPeerInitiation(peer_index);
            ScheduleNextHandshakeRetry(peer_index);
            logger::Log(
                "WG handshake attempt peer=%zu sequence=%u attempt=%u retry=1 reason=retransmit timer",
                peer_index,
                peer->handshake_retry.sequence_count,
                peer->handshake_retry.send_attempts);
            if (retry_error == wgnx::PeerErrorCode::None) {
                return;
            }
            if (IsRecoverableTransportIoError(retry_error)) {
                LogRecoverableTransportIoError(peer_index, retry_error, "handshake retransmit timer");
                return;
            }
            SetPeerError(peer_index, wgnx::PeerErrorStage::Handshake, retry_error);
            return;
        }
        case wgnx::wireguard::TimerHook::SendKeepalive: {
            if (runtime.state != wgnx::PeerRuntimeState::Active) {
                return;
            }

            if (!peer->current_keypair.CanSendAt(wgnx::wireguard::GetMonotonicTime())) {
                const wgnx::PeerErrorCode handshake_error = EnsureHandshakeForOutboundTraffic(
                    peer_index,
                    "persistent keepalive");
                if (handshake_error != wgnx::PeerErrorCode::None) {
                    SetPeerError(
                        peer_index,
                        handshake_error == wgnx::PeerErrorCode::HandshakeInitFailed
                            ? wgnx::PeerErrorStage::Handshake
                            : wgnx::PeerErrorStage::Transport,
                        handshake_error);
                }
                return;
            }

            const wgnx::PeerErrorCode keepalive_error = SendProtocolPeerKeepalive(peer_index);
            if (keepalive_error != wgnx::PeerErrorCode::None) {
                if (!IsRecoverableTransportIoError(keepalive_error)) {
                    SetPeerError(peer_index, wgnx::PeerErrorStage::Transport, keepalive_error);
                    return;
                }
                LogRecoverableTransportIoError(peer_index, keepalive_error, "persistent keepalive timer");
            }

            if (peer->persistent_keepalive_interval > 0) {
                ScheduleProtocolTimer(
                    peer_index,
                    hook,
                    wgnx::wireguard::TimerDeadlineFromJiffies(wgnx::platform::get_jiffies_64()) +
                        std::chrono::seconds{peer->persistent_keepalive_interval});
            }
            return;
        }
        case wgnx::wireguard::TimerHook::Rekey: {
            if (runtime.state != wgnx::PeerRuntimeState::Active) {
                return;
            }

            const wgnx::PeerErrorCode send_error = SendFreshHandshakeInitiation(
                peer_index,
                "rekey timer");
            if (send_error != wgnx::PeerErrorCode::None) {
                if (!IsRecoverableTransportIoError(send_error)) {
                    SetPeerError(peer_index, wgnx::PeerErrorStage::Transport, send_error);
                    return;
                }
                LogRecoverableTransportIoError(peer_index, send_error, "rekey initiation");
            }
            return;
        }
        case wgnx::wireguard::TimerHook::ZeroKeyMaterial:
            CancelProtocolTimer(peer_index, hook);
            wgnx::wireguard::wg_peer_zero_key_material(peer);
            wgnx::wireguard::wg_device_clear_index_registry(
                std::addressof(PeerAt(peer_index).protocol.device));
            logger::Log(
                "WG zeroed stale handshake and keypair material peer=%zu activation=%u; peer and UDP binding preserved",
                peer_index,
                runtime.activation_generation);
            return;
    }
}

void NetworkPathObserverWorkMain(wgnx::platform::work_struct *) {
    bool has_active_transport = false;
    {
        std::scoped_lock lock(g_state_mutex);
        has_active_transport = g_state.peers.ActivePeerIndex() >= 0;
    }

    if (has_active_transport) {
        wgnx::platform::observe_network_path();
    }
}

void InitializeHorizonDispatcher() {
    g_horizon_dispatcher.Initialize(
        {
            .resolve = ResolverWorkMain,
            .submit_debug_payload = PayloadSubmissionWorkMain,
            .submit_inner_packet = InnerPacketSubmissionWorkMain,
            .receive = ReceiveWorkMain,
            .protocol_timer = RunTimerAction,
            .debug_probe_timeout = [] { PayloadProbeTimeoutWorkMain(nullptr); },
            .network_path_observer = [] { NetworkPathObserverWorkMain(nullptr); },
        },
        development_config::NifmPathObserverEnabled,
        NetworkPathObservationJiffies);

    logger::Log("Started endpoint resolver worker");
    logger::Log("Started shared payload and inner packet submission worker");
    logger::Log("Started UDP receive worker");
    if constexpr (development_config::NifmPathObserverEnabled) {
        logger::Log("NIFM network-path observer enabled mode=%s interval_jiffies=%llu",
            development_config::GetNifmPathObserverModeName(),
            static_cast<unsigned long long>(NetworkPathObservationJiffies));
    } else {
        logger::Log("NIFM network-path observer disabled mode=%s",
            development_config::GetNifmPathObserverModeName());
    }
    logger::Log("Started transport timer executor");
}

} // namespace

namespace runtime {

wgnx::DaemonStatus GetDaemonStatus() {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();
    TickActivePeer();

    return {
        .abi_version = wgnx::IpcApiVersion,
        .peer_count = g_state.peers.Count(),
        .active_peer_index = g_state.peers.ActivePeerIndex(),
        .auto_start_peer_index = g_state.peers.AutoStartPeerIndex(),
        .flags = runtime::BuildDaemonFlags(
            g_state.peers.ActivePeerIndex() >= 0,
            HasRuntimeErrors()),
        .reserved = 0,
    };
}

std::uint32_t CopyPeers(std::span<wgnx::PeerInfo> out) {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();
    TickActivePeer();

    const std::size_t copy_count = std::min<std::size_t>(out.size(), g_state.peers.Count());
    for (std::size_t i = 0; i < copy_count; ++i) {
        out[i] = BuildPeerInfo(i);
    }

    return g_state.peers.Count();
}

ams::Result SetActivePeer(std::int32_t peer_index) {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();

    if (!IsValidPeerIndex(peer_index)) {
        logger::Log("Rejected SetActivePeer(%d): invalid index", peer_index);
        R_THROW(ams::fs::ResultInvalidArgument());
    }

    if (peer_index == g_state.peers.ActivePeerIndex()) {
        logger::Log("SetActivePeer(%d): no change", peer_index);
        R_SUCCEED();
    }

    if (g_state.peers.ActivePeerIndex() >= 0 && g_state.peers.ActivePeerIndex() != peer_index) {
        const std::size_t old_index = static_cast<std::size_t>(g_state.peers.ActivePeerIndex());
        SetPeerInactive(old_index);
    }

    AMS_ABORT_UNLESS(g_state.peers.SetActivePeerIndex(peer_index));
    if (peer_index >= 0) {
        StartPeerRuntime(static_cast<std::size_t>(peer_index));
    }
    logger::Log("SetActivePeer(%d)", peer_index);
    R_SUCCEED();
}

ams::Result SetAutoStartPeer(std::int32_t peer_index) {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();

    if (!IsValidPeerIndex(peer_index)) {
        logger::Log("Rejected SetAutoStartPeer(%d): invalid index", peer_index);
        R_THROW(ams::fs::ResultInvalidArgument());
    }

    const char *peer_name = nullptr;
    if (peer_index >= 0) {
        peer_name = PeerAt(static_cast<std::size_t>(peer_index)).config.name.data();
    }

    const ams::Result store_rc = StoreAutoStartPeerName(peer_name);
    if (R_FAILED(store_rc)) {
        logger::Log("Rejected SetAutoStartPeer(%d): persist failed rc=0x%08x", peer_index, static_cast<u32>(store_rc.GetValue()));
        R_THROW(store_rc);
    }

    AMS_ABORT_UNLESS(g_state.peers.SetAutoStartPeerIndex(peer_index));
    logger::Log("SetAutoStartPeer(%d)", peer_index);
    R_SUCCEED();
}

ams::Result TriggerDebugPayload(wgnx::DebugTriggerAction action) {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();

    if (!QueuePayloadSubmissionRequestLocked(action)) {
        logger::Log(
            "Rejected TriggerDebugPayload(action=%u): no active session, invalid action, or queue busy",
            static_cast<unsigned int>(action));
        R_THROW(ams::fs::ResultInvalidArgument());
    }

    QueuePayloadSubmissionWork();
    logger::Log("Queued debug payload trigger action=%s", wgnx::GetDebugTriggerActionName(action));
    R_SUCCEED();
}

ams::Result BumpUdpBinding() {
    {
        std::scoped_lock lock(g_state_mutex);
        InitializeState();
        if (g_state.peers.ActivePeerIndex() < 0) {
            logger::Log("Rejected BumpUdpBinding: no active peer");
            R_THROW(ams::fs::ResultInvalidArgument());
        }

        const std::size_t peer_index = static_cast<std::size_t>(g_state.peers.ActivePeerIndex());
        const auto &runtime = PeerAt(peer_index).Lifecycle();
        const auto &binding = PeerAt(peer_index).binding;
        if ((runtime.state != wgnx::PeerRuntimeState::Handshaking &&
             runtime.state != wgnx::PeerRuntimeState::Active) ||
            !binding.HasEndpoint()) {
            logger::Log(
                "Rejected BumpUdpBinding: peer=%zu state=%s resolved=%u",
                peer_index,
                wgnx::GetPeerRuntimeStateName(runtime.state),
                binding.HasEndpoint() ? 1U : 0U);
            R_THROW(ams::fs::ResultInvalidArgument());
        }

        if (g_bind_bump_request.pending &&
            g_bind_bump_request.peer_index == peer_index &&
            g_bind_bump_request.activation_generation == runtime.activation_generation) {
            logger::Log(
                "Coalesced UDP bind bump peer=%zu activation=%u",
                peer_index,
                runtime.activation_generation);
        } else {
            g_bind_bump_request = {
                .pending = true,
                .peer_index = peer_index,
                .activation_generation = runtime.activation_generation,
            };
            logger::Log(
                "Queued UDP bind bump peer=%zu activation=%u socket_generation=%u socket=%d",
                peer_index,
                runtime.activation_generation,
                binding.Generation(),
                static_cast<int>(binding.Socket()));
        }
    }

    QueueReceiveWork();
    R_SUCCEED();
}

wgnx::PacketSubmissionResult SubmitInnerIpv4Packet(
    std::span<const std::uint8_t> packet_bytes,
    std::uint64_t process_id) {
    wgnx::PacketSubmissionResult result = {
        .packet_id = 0,
        .status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::InternalError),
        .packet_size = static_cast<std::uint32_t>(packet_bytes.size()),
        .activation_generation = 0,
        .peer_index = -1,
    };

    const auto validation = wgnx::wireguard::ValidateInnerIpv4Packet(packet_bytes);
    if (validation != wgnx::wireguard::InnerIpv4ValidationError::None) {
        result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::MalformedPacket);
        logger::Log(
            "Rejected packet API submission pid=%llu bytes=%zu validation=%s",
            static_cast<unsigned long long>(process_id),
            packet_bytes.size(),
            wgnx::wireguard::GetInnerIpv4ValidationErrorName(validation));
        return result;
    }

    bool queue_worker = false;
    {
        std::scoped_lock lock(g_state_mutex);
        InitializeState();
        if (g_state.peers.ActivePeerIndex() < 0) {
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::TunnelUnavailable);
            return result;
        }

        const std::size_t peer_index = static_cast<std::size_t>(g_state.peers.ActivePeerIndex());
        const auto &runtime = PeerAt(peer_index).Lifecycle();
        result.peer_index = static_cast<std::int32_t>(peer_index);
        result.activation_generation = runtime.activation_generation;
        if (runtime.state != wgnx::PeerRuntimeState::ResolvingEndpoint &&
            runtime.state != wgnx::PeerRuntimeState::Handshaking &&
            runtime.state != wgnx::PeerRuntimeState::Active) {
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::TunnelUnavailable);
            return result;
        }

        if (!g_packet_channel.IsOwnedBy(process_id)) {
            wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
            if (peer == nullptr) {
                result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::InternalError);
                return result;
            }
            const std::size_t old_tx_count =
                wgnx::wireguard::wg_peer_clear_staged_outbound_packets(peer);
            const std::size_t old_rx_count = g_packet_channel.Claim(process_id);
            logger::Log(
                "Transferred packet API ownership pid=%llu discarded_tx=%zu discarded_rx=%zu",
                static_cast<unsigned long long>(process_id),
                old_tx_count,
                old_rx_count);
        }

        wgnx::wireguard::wg_peer *peer = GetProtocolPeer(peer_index);
        if (peer == nullptr) {
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::InternalError);
            return result;
        }

        wgnx::wireguard::InnerPacketRecord record{};
        record.packet_id = g_packet_channel.AllocatePacketId();
        record.owner_process_id = process_id;
        record.activation_generation = runtime.activation_generation;
        record.peer_index = static_cast<std::uint32_t>(peer_index);
        record.size = static_cast<std::uint16_t>(packet_bytes.size());
        std::memcpy(record.bytes.data(), packet_bytes.data(), packet_bytes.size());
        if (peer->staged_outbound_packets.Push(record) == wgnx::wireguard::QueuePushResult::Full) {
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::QueueFull);
            logger::Log(
                "Rejected packet API submission pid=%llu reason=tx_queue_full capacity=%zu",
                static_cast<unsigned long long>(process_id),
                peer->staged_outbound_packets.CapacityValue());
            return result;
        }

        result.packet_id = record.packet_id;
        result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::Queued);
        queue_worker = runtime.state == wgnx::PeerRuntimeState::Handshaking ||
                       runtime.state == wgnx::PeerRuntimeState::Active;
        logger::Log(
            "Queued packet API submission id=%llu pid=%llu peer=%zu activation=%u bytes=%zu depth=%zu state=%s",
            static_cast<unsigned long long>(record.packet_id),
            static_cast<unsigned long long>(process_id),
            peer_index,
            runtime.activation_generation,
            packet_bytes.size(),
            peer->staged_outbound_packets.Size(),
            wgnx::GetPeerRuntimeStateName(runtime.state));
    }

    if (queue_worker) {
        QueueInnerPacketSubmissionWork();
    }
    return result;
}

wgnx::PacketReceiveResult ReceiveInnerIpv4Packet(
    std::span<std::uint8_t> packet,
    std::uint64_t process_id) {
    wgnx::PacketReceiveResult result = {
        .packet_id = 0,
        .status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::QueueEmpty),
        .packet_size = 0,
        .activation_generation = 0,
        .peer_index = -1,
    };

    std::scoped_lock lock(g_state_mutex);
    InitializeState();
    if (!g_packet_channel.IsOwnedBy(process_id)) {
        result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::AccessDenied);
        return result;
    }

    const auto *front = g_packet_channel.FrontReceived();
    if (front == nullptr) {
        return result;
    }

    result.packet_id = front->packet_id;
    result.packet_size = front->size;
    result.activation_generation = front->activation_generation;
    result.peer_index = static_cast<std::int32_t>(front->peer_index);
    if (front->peer_index >= g_state.peers.Count() ||
        g_state.peers.ActivePeerIndex() != static_cast<std::int32_t>(front->peer_index) ||
        PeerAt(front->peer_index).Lifecycle().activation_generation != front->activation_generation) {
        wgnx::wireguard::InnerPacketRecord stale{};
        static_cast<void>(g_packet_channel.PopReceived(
            std::addressof(stale),
            wgnx::wireguard::QueueDisposition::Stale));
        result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::StaleActivation);
        logger::Log(
            "Discarded packet API receive id=%llu reason=stale_activation",
            static_cast<unsigned long long>(stale.packet_id));
        return result;
    }
    if (packet.size() < front->size) {
        result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::OutputBufferTooSmall);
        return result;
    }

    std::memcpy(packet.data(), front->bytes.data(), front->size);
    wgnx::wireguard::InnerPacketRecord delivered{};
    static_cast<void>(g_packet_channel.PopReceived(
        std::addressof(delivered),
        wgnx::wireguard::QueueDisposition::Delivered));
    result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::Success);
    logger::Log(
        "Delivered packet API receive id=%llu pid=%llu peer=%u activation=%u bytes=%u remaining=%zu",
        static_cast<unsigned long long>(delivered.packet_id),
        static_cast<unsigned long long>(process_id),
        delivered.peer_index,
        delivered.activation_generation,
        static_cast<unsigned int>(delivered.size),
        g_packet_channel.ReceivedSize());
    return result;
}

void Initialize() {
    {
        std::scoped_lock lock(g_state_mutex);
        InitializeState();
    }
    InitializeHorizonDispatcher();
}

} // namespace runtime

} // namespace wgnx::sysmodule
