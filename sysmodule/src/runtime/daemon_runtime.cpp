#include "runtime/daemon_runtime.hpp"
#include "runtime/endpoint_resolver.hpp"
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
runtime::EndpointResolver g_endpoint_resolver{};
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
constinit std::array<std::uint8_t, ReceivePacketCapacity> g_receive_packet_storage = {};
constinit runtime::EffectBatch g_receive_effects{};

void QueueInnerPacketSubmissionWork();
void ExecuteRuntimeEffects(const runtime::EffectBatch &effects);
void PublishDecryptedPacketLocked(
    std::size_t peer_index,
    std::uint32_t activation_generation,
    std::span<const std::uint8_t> inner_packet);

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
        tx_count += PeerAt(peer_index).ClearStagedInnerPackets();
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

void SetPeerError(std::size_t peer_index, wgnx::PeerErrorStage stage, wgnx::PeerErrorCode code) {
    CancelPayloadProbeTimeout();
    ClearInnerPacketStateLocked("peer error");
    CloseRuntimeSocket(peer_index);
    PeerAt(peer_index).EnterError(stage, code, GetRuntimeNowNs());
    FailProtocolPeer(peer_index, wgnx::GetPeerErrorCodeName(code));
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

NOINLINE void ExecuteOpenUdpBindEffect(
    const runtime::OpenUdpBindEffect &effect,
    runtime::EffectBatch &generated) {
    wgnx::platform::socket_handle socket = wgnx::platform::InvalidSocket;
    const auto error = wgnx::platform::udp_open(
        std::addressof(socket),
        effect.endpoint.family);
    logger::Log(
        "UDP bind open completion peer=%u activation=%u socket_generation=%u socket=%d endpoint=%s error=%u",
        effect.peer.peer_index,
        effect.peer.activation_generation,
        effect.socket_generation,
        static_cast<int>(socket),
        effect.endpoint_text.data(),
        static_cast<unsigned int>(error));
    const auto retry_deadline =
        wgnx::wireguard::TimerDeadlineFromJiffies(
            wgnx::platform::get_jiffies_64()) +
        wgnx::wireguard::GetHandshakeRetryDelay(
            wgnx::platform::get_random_u32_below(
                wgnx::wireguard::RekeyTimeoutJitterMaxMs));
    runtime::EffectBatch completion{};
    {
        std::scoped_lock lock(g_state_mutex);
        completion = g_runtime_coordinator.Dispatch(runtime::UdpBindOpenedEvent{
            .peer = effect.peer,
            .endpoint = effect.endpoint,
            .endpoint_text = effect.endpoint_text,
            .socket = socket,
            .error = error,
            .socket_generation = effect.socket_generation,
            .retry_deadline = retry_deadline,
            .occurred_at = GetRuntimeNowNs(),
        });
    }
    AMS_ABORT_UNLESS(generated.Append(completion));
}

NOINLINE void ExecutePendingDatagramSendEffect(
    const runtime::SendPendingDatagramEffect &effect,
    runtime::EffectBatch &generated) {
    runtime::PendingDatagramSnapshot snapshot{};
    bool current = false;
    {
        std::scoped_lock lock(g_state_mutex);
        current = effect.peer.peer_index < g_state.peers.Count() &&
                  g_state.peers.ActivePeerIndex() ==
                      static_cast<std::int32_t>(effect.peer.peer_index) &&
                  PeerAt(effect.peer.peer_index).SnapshotPendingDatagram(
                      effect.peer.activation_generation,
                      effect.datagram_generation,
                      snapshot);
    }
    if (!current) {
        return;
    }
    std::size_t sent = 0;
    const auto error = wgnx::platform::udp_send(
        snapshot.binding.socket,
        snapshot.binding.endpoint,
        std::span<const std::uint8_t>(snapshot.bytes).first(snapshot.size),
        std::addressof(sent));
    logger::Log(
        "Encrypted datagram send completion peer=%u activation=%u datagram_generation=%u kind=%s packet_id=%llu bytes=%zu sent=%zu socket_generation=%u socket=%d error=%u",
        effect.peer.peer_index,
        effect.peer.activation_generation,
        effect.datagram_generation,
        runtime::GetPendingDatagramKindName(snapshot.kind),
        static_cast<unsigned long long>(snapshot.inner_packet_id),
        snapshot.size,
        sent,
        snapshot.binding.generation,
        static_cast<int>(snapshot.binding.socket),
        static_cast<unsigned int>(error));
    runtime::EffectBatch completion{};
    {
        std::scoped_lock lock(g_state_mutex);
        completion = g_runtime_coordinator.Dispatch(runtime::PendingDatagramSentEvent{
            .peer = effect.peer,
            .datagram_generation = effect.datagram_generation,
            .bytes_sent = sent,
            .error = error,
            .occurred_at = GetRuntimeNowNs(),
        });
    }
    AMS_ABORT_UNLESS(generated.Append(completion));
}

NOINLINE void ExecutePublishDecryptedPacketEffect(
    const runtime::PublishDecryptedPacketEffect &effect) {
    std::scoped_lock lock(g_state_mutex);
    if (effect.peer.peer_index >= g_state.peers.Count() ||
        g_state.peers.ActivePeerIndex() !=
            static_cast<std::int32_t>(effect.peer.peer_index)) {
        return;
    }

    runtime::DecryptedPacketView view{};
    if (PeerAt(effect.peer.peer_index).ViewDecryptedPacket(
            effect.peer.activation_generation,
            effect.packet_generation,
            view)) {
        PublishDecryptedPacketLocked(
            effect.peer.peer_index,
            effect.peer.activation_generation,
            view.packet);
    }
}

void ExecuteRuntimeEffects(const runtime::EffectBatch &effects) {
    runtime::EffectBatch current = effects;
    while (!current.Empty()) {
        runtime::EffectBatch generated{};
        for (const auto &effect : current) {
            std::visit(
                [&generated](const auto &value) {
                    using Effect = std::remove_cvref_t<decltype(value)>;
                    if constexpr (std::is_same_v<Effect, runtime::ResolveEndpointEffect>) {
                        bool current = false;
                        bool schedule = false;
                        {
                            std::scoped_lock lock(g_state_mutex);
                            current = value.peer.peer_index < g_state.peers.Count() &&
                                      g_state.peers.ActivePeerIndex() ==
                                          static_cast<std::int32_t>(value.peer.peer_index) &&
                                      PeerAt(value.peer.peer_index).IsCurrentActivation(
                                          value.peer.activation_generation);
                            if (current) {
                                schedule = g_endpoint_resolver.Queue(value);
                            }
                        }
                        if (current) {
                            logger::Log(
                                "Queued endpoint resolution for peer %u activation=%u endpoint='%s' schedule=%u",
                                value.peer.peer_index,
                                value.peer.activation_generation,
                                value.endpoint.data(),
                                schedule ? 1U : 0U);
                        }
                        if (schedule) {
                            g_horizon_dispatcher.QueueResolve();
                        }
                    } else if constexpr (std::is_same_v<Effect, runtime::OpenUdpBindEffect>) {
                        ExecuteOpenUdpBindEffect(value, generated);
                    } else if constexpr (std::is_same_v<Effect, runtime::CloseUdpSocketEffect>) {
                        if (value.socket != wgnx::platform::InvalidSocket) {
                            wgnx::platform::udp_close(value.socket);
                        }
                    } else if constexpr (std::is_same_v<Effect, runtime::SendPendingDatagramEffect>) {
                        ExecutePendingDatagramSendEffect(value, generated);
                    } else if constexpr (std::is_same_v<Effect, runtime::QueueReceiveEffect>) {
                        bool current = false;
                        {
                            std::scoped_lock lock(g_state_mutex);
                            current = value.peer.peer_index < g_state.peers.Count() &&
                                      g_state.peers.ActivePeerIndex() ==
                                          static_cast<std::int32_t>(value.peer.peer_index) &&
                                      PeerAt(value.peer.peer_index).IsCurrentActivation(
                                          value.peer.activation_generation) &&
                                      PeerAt(value.peer.peer_index).IsInTransportState();
                        }
                        if (current) {
                            QueueReceiveWork();
                        }
                    } else if constexpr (std::is_same_v<Effect, runtime::ArmProtocolTimerEffect>) {
                        std::scoped_lock lock(g_state_mutex);
                        if (value.peer.peer_index < g_state.peers.Count() &&
                            g_state.peers.ActivePeerIndex() ==
                                static_cast<std::int32_t>(value.peer.peer_index) &&
                            PeerAt(value.peer.peer_index).IsCurrentActivation(
                                value.peer.activation_generation)) {
                            ScheduleProtocolTimer(
                                value.peer.peer_index,
                                value.hook,
                                value.deadline);
                        }
                    } else if constexpr (std::is_same_v<Effect, runtime::CancelProtocolTimerEffect>) {
                        std::scoped_lock lock(g_state_mutex);
                        if (value.peer.peer_index < g_state.peers.Count() &&
                            PeerAt(value.peer.peer_index).IsCurrentActivation(
                                value.peer.activation_generation)) {
                            CancelProtocolTimer(value.peer.peer_index, value.hook);
                        }
                    } else if constexpr (std::is_same_v<Effect, runtime::SuspendUdpTransportEffect>) {
                        std::scoped_lock lock(g_state_mutex);
                        if (value.peer.peer_index < g_state.peers.Count() &&
                            g_state.peers.ActivePeerIndex() ==
                                static_cast<std::int32_t>(value.peer.peer_index) &&
                            PeerAt(value.peer.peer_index).IsCurrentActivation(
                                value.peer.activation_generation)) {
                            SuspendRuntimeTransportAfterSendFailure(
                                value.peer.peer_index,
                                "event-driven datagram send");
                        }
                    } else if constexpr (std::is_same_v<Effect, runtime::QueueInnerPacketSubmissionEffect>) {
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
                    } else if constexpr (std::is_same_v<Effect, runtime::PublishDecryptedPacketEffect>) {
                        ExecutePublishDecryptedPacketEffect(value);
                    }
                },
                effect);
        }
        current = generated;
    }
}

void PublishDecryptedPacketLocked(
    std::size_t peer_index,
    std::uint32_t activation_generation,
    std::span<const std::uint8_t> inner_packet) {
    const auto &lifecycle = PeerAt(peer_index).Lifecycle();
    wgnx::wireguard::DebugProbeReplyInfo reply_info{};
    const auto reply_validation = wgnx::wireguard::ValidateDebugIcmpEchoReply(
        inner_packet,
        PeerAt(peer_index).config.address.data(),
        peer_index,
        activation_generation,
        std::addressof(reply_info));
    if (reply_validation == wgnx::wireguard::DebugProbeReplyValidation::Valid) {
        char inner_source[16] = {};
        char inner_destination[16] = {};
        wgnx::wireguard::FormatIpv4Text(
            reply_info.source_ipv4,
            inner_source,
            sizeof(inner_source));
        wgnx::wireguard::FormatIpv4Text(
            reply_info.destination_ipv4,
            inner_destination,
            sizeof(inner_destination));
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

    if (reply_validation !=
        wgnx::wireguard::DebugProbeReplyValidation::NotDebugReply) {
        CancelPayloadProbeTimeout();
        SetDebugProbeState(
            PeerAt(peer_index),
            lifecycle.debug_probe_action,
            wgnx::DebugProbeStatus::ReplyRejected);
        logger::Log(
            "Rejected debug ICMP reply metadata for peer %zu validation=%s payload=%zu",
            peer_index,
            wgnx::wireguard::GetDebugProbeReplyValidationName(reply_validation),
            inner_packet.size());
        return;
    }

    EnqueueReceivedInnerIpv4PacketLocked(
        peer_index,
        activation_generation,
        inner_packet);
}

NOINLINE void CommitReceivedPacket(
    std::size_t peer_index,
    std::uint32_t activation_generation,
    std::uint32_t socket_generation,
    wgnx::platform::socket_handle socket,
    std::span<const std::uint8_t> packet,
    const wgnx::platform::endpoint &source,
    runtime::EffectBatch &out_effects) {
    out_effects.Clear();
    std::scoped_lock lock(g_state_mutex);
    if (peer_index >= g_state.peers.Count() ||
        g_state.peers.ActivePeerIndex() !=
            static_cast<std::int32_t>(peer_index)) {
        return;
    }

    const auto &lifecycle = PeerAt(peer_index).Lifecycle();
    const auto &binding = PeerAt(peer_index).binding;
    if (lifecycle.activation_generation != activation_generation ||
        !binding.Matches(socket_generation, socket) ||
        !PeerAt(peer_index).IsInTransportState()) {
        return;
    }

    std::array<char, sizeof(wgnx::PeerInfo::resolved_endpoint)> source_text{};
    FormatEndpointText(source, source_text.data(), source_text.size());
    const auto now_jiffies = wgnx::platform::get_jiffies_64();
    out_effects = g_runtime_coordinator.Dispatch(
        runtime::EncryptedDatagramReceivedEvent{
            .peer = {
                .peer_index = static_cast<std::uint32_t>(peer_index),
                .activation_generation = activation_generation,
            },
            .packet = packet,
            .source = source,
            .source_text = source_text,
            .keepalive_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(now_jiffies) +
                std::chrono::seconds{
                    PeerAt(peer_index).Lifecycle().persistent_keepalive_interval},
            .rekey_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(now_jiffies) +
                wgnx::wireguard::RekeyAfterTime,
            .zero_key_material_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(now_jiffies) +
                wgnx::wireguard::ZeroKeyMaterialAfterTime,
            .occurred_at = GetRuntimeNowNs(),
        });
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
    while (true) {
        std::optional<runtime::ResolveEndpointEffect> request{};
        {
            std::scoped_lock lock(g_state_mutex);
            request = g_endpoint_resolver.Take();
            if (!request.has_value()) {
                g_endpoint_resolver.MarkWorkerIdle();
            }
        }
        if (!request.has_value()) {
            return;
        }
        const auto result = wgnx::platform::resolve_endpoint(request->endpoint.data());
        logger::Log(
            "Endpoint resolution completion peer=%u activation=%u endpoint='%s' success=%u stage=%s code=%s resolved=%s",
            request->peer.peer_index,
            request->peer.activation_generation,
            request->endpoint.data(),
            result.success ? 1U : 0U,
            wgnx::GetPeerErrorStageName(result.error_stage),
            wgnx::GetPeerErrorCodeName(result.error_code),
            result.text.data());
        runtime::EffectBatch effects{};
        {
            std::scoped_lock lock(g_state_mutex);
            effects = g_runtime_coordinator.Dispatch(runtime::EndpointResolvedEvent{
                .peer = request->peer,
                .result = result,
                .occurred_at = GetRuntimeNowNs(),
            });
        }
        ExecuteRuntimeEffects(effects);
    }
}

void ProcessPendingBindBump() {
    std::unique_lock lock(g_state_mutex);
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

    const runtime::EffectBatch effects = g_runtime_coordinator.Dispatch(
        runtime::TransportReboundEvent{
            .peer = {
                .peer_index = static_cast<std::uint32_t>(request.peer_index),
                .activation_generation = request.activation_generation,
            },
            .retry_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(
                    wgnx::platform::get_jiffies_64()) +
                wgnx::wireguard::GetHandshakeRetryDelay(
                    wgnx::platform::get_random_u32_below(
                        wgnx::wireguard::RekeyTimeoutJitterMaxMs)),
            .occurred_at = GetRuntimeNowNs(),
        });
    logger::Log(
        "Completed UDP bind bump peer=%zu activation=%u socket_generation=%u socket=%d",
        request.peer_index,
        request.activation_generation,
        binding.Generation(),
        static_cast<int>(binding.Socket()));
    lock.unlock();
    ExecuteRuntimeEffects(effects);
}

void ReceiveWorkMain(wgnx::platform::work_struct *) {
    // HorizonDispatcher serializes this callback on one ordered work queue, so
    // the process-lifetime receive storage has one exclusive user at a time.
    wgnx::platform::packet_buffer packet{
        .data = g_receive_packet_storage.data(),
        .len = 0,
        .capacity = g_receive_packet_storage.size(),
    };
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
            packet.storage(),
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

        static_cast<void>(wgnx::platform::packet_set_len(std::addressof(packet), received));
        CommitReceivedPacket(
            peer_index,
            activation_generation,
            socket_generation,
            socket,
            packet.bytes(),
            source,
            g_receive_effects);
        ExecuteRuntimeEffects(g_receive_effects);
        g_receive_effects.Clear();
        wgnx::platform::packet_clear(std::addressof(packet));
    }
}

[[maybe_unused]] void PayloadSubmissionWorkMain(wgnx::platform::work_struct *) {
    PayloadSubmissionRequest request{};
    while (DequeuePayloadSubmissionRequest(std::addressof(request))) {
        CommitPayloadSubmission(request);
    }
}

[[maybe_unused]] void InnerPacketSubmissionWorkMain(wgnx::platform::work_struct *) {
    runtime::EffectBatch effects{};
    {
        std::scoped_lock lock(g_state_mutex);
        if (g_state.peers.ActivePeerIndex() < 0) {
            return;
        }
        const auto peer_index = static_cast<std::uint32_t>(
            g_state.peers.ActivePeerIndex());
        const auto &lifecycle = PeerAt(peer_index).Lifecycle();
        effects = g_runtime_coordinator.Dispatch(runtime::ProcessOutboundQueueEvent{
            .peer = {
                .peer_index = peer_index,
                .activation_generation = lifecycle.activation_generation,
            },
            .retry_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(
                    wgnx::platform::get_jiffies_64()) +
                wgnx::wireguard::GetHandshakeRetryDelay(
                    wgnx::platform::get_random_u32_below(
                        wgnx::wireguard::RekeyTimeoutJitterMaxMs)),
            .occurred_at = GetRuntimeNowNs(),
        });
    }
    ExecuteRuntimeEffects(effects);
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
    std::unique_lock lock(g_state_mutex);
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
        case wgnx::wireguard::TimerHook::RetransmitHandshake:
        case wgnx::wireguard::TimerHook::SendKeepalive:
        case wgnx::wireguard::TimerHook::Rekey: {
            const auto now_jiffies = wgnx::platform::get_jiffies_64();
            const runtime::EffectBatch effects = g_runtime_coordinator.Dispatch(
                runtime::ProtocolTimerExpiredEvent{
                    .peer = {
                        .peer_index = static_cast<std::uint32_t>(peer_index),
                        .activation_generation = runtime.activation_generation,
                    },
                    .hook = hook,
                    .retry_deadline =
                        wgnx::wireguard::TimerDeadlineFromJiffies(now_jiffies) +
                        wgnx::wireguard::GetHandshakeRetryDelay(
                            wgnx::platform::get_random_u32_below(
                                wgnx::wireguard::RekeyTimeoutJitterMaxMs)),
                    .keepalive_deadline =
                        wgnx::wireguard::TimerDeadlineFromJiffies(now_jiffies) +
                        std::chrono::seconds{peer->persistent_keepalive_interval},
                    .zero_key_material_deadline =
                        wgnx::wireguard::TimerDeadlineFromJiffies(now_jiffies) +
                        wgnx::wireguard::ZeroKeyMaterialAfterTime,
                    .occurred_at = GetRuntimeNowNs(),
                });
            lock.unlock();
            ExecuteRuntimeEffects(effects);
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
    std::unique_lock lock(g_state_mutex);
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
    runtime::EffectBatch effects{};
    if (peer_index >= 0) {
        effects = g_runtime_coordinator.Dispatch(runtime::ActivationRequestedEvent{
            .peer_index = static_cast<std::uint32_t>(peer_index),
            .occurred_at = GetRuntimeNowNs(),
        });
    }
    logger::Log("SetActivePeer(%d)", peer_index);
    lock.unlock();
    ExecuteRuntimeEffects(effects);
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

    runtime::EffectBatch effects{};
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
            if (!PeerAt(peer_index).protocol.instantiated) {
                result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::InternalError);
                return result;
            }
            const std::size_t old_tx_count =
                PeerAt(peer_index).ClearStagedInnerPackets();
            const std::size_t old_rx_count = g_packet_channel.Claim(process_id);
            logger::Log(
                "Transferred packet API ownership pid=%llu discarded_tx=%zu discarded_rx=%zu",
                static_cast<unsigned long long>(process_id),
                old_tx_count,
                old_rx_count);
        }

        if (!PeerAt(peer_index).CanStageInnerPacket()) {
            result.status = PeerAt(peer_index).protocol.instantiated
                ? static_cast<std::uint32_t>(wgnx::PacketApiStatus::QueueFull)
                : static_cast<std::uint32_t>(wgnx::PacketApiStatus::InternalError);
            if (PeerAt(peer_index).protocol.instantiated) {
                logger::Log(
                    "Rejected packet API submission pid=%llu reason=tx_queue_full",
                    static_cast<unsigned long long>(process_id));
            }
            return result;
        }

        if (!PeerAt(peer_index).protocol.instantiated) {
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::InternalError);
            return result;
        }

        const std::uint64_t packet_id = g_packet_channel.AllocatePacketId();
        effects = g_runtime_coordinator.Dispatch(runtime::InnerPacketStagedEvent{
            .peer = {
                .peer_index = static_cast<std::uint32_t>(peer_index),
                .activation_generation = runtime.activation_generation,
            },
            .packet = packet_bytes,
            .packet_id = packet_id,
            .owner_process_id = process_id,
            .retry_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(
                    wgnx::platform::get_jiffies_64()) +
                wgnx::wireguard::GetHandshakeRetryDelay(
                    wgnx::platform::get_random_u32_below(
                        wgnx::wireguard::RekeyTimeoutJitterMaxMs)),
            .occurred_at = GetRuntimeNowNs(),
        });

        result.packet_id = packet_id;
        result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::Queued);
        logger::Log(
            "Queued packet API submission id=%llu pid=%llu peer=%zu activation=%u bytes=%zu depth=%zu state=%s",
            static_cast<unsigned long long>(packet_id),
            static_cast<unsigned long long>(process_id),
            peer_index,
            runtime.activation_generation,
            packet_bytes.size(),
            PeerAt(peer_index).StagedInnerPacketCount(),
            wgnx::GetPeerRuntimeStateName(runtime.state));
    }

    ExecuteRuntimeEffects(effects);
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
