#include "runtime/peer_runtime.hpp"

#include "wireguard/debug_probe.hpp"

#include <cstdio>
#include <limits>
#include <type_traits>

namespace wgnx::sysmodule::runtime {

namespace {

std::int32_t ComputeElapsedSeconds(
    wgnx::platform::ktime_t timestamp_ns,
    wgnx::platform::ktime_t now_ns) {
    if (timestamp_ns <= 0 || now_ns < timestamp_ns) {
        return -1;
    }

    const auto elapsed_seconds =
        (now_ns - timestamp_ns) / wgnx::platform::NSEC_PER_SEC;
    if (elapsed_seconds > static_cast<wgnx::platform::ktime_t>(
                              std::numeric_limits<std::int32_t>::max())) {
        return std::numeric_limits<std::int32_t>::max();
    }
    return static_cast<std::int32_t>(elapsed_seconds);
}

} // namespace

void PeerRuntime::ResetLifecycle(
    wgnx::PeerRuntimeState state,
    std::uint32_t activation_generation,
    wgnx::platform::ktime_t now) {
    m_lifecycle = {};
    m_lifecycle.state = state;
    m_lifecycle.persistent_keepalive_interval = config.persistent_keepalive;
    m_lifecycle.activation_generation = activation_generation;
    m_lifecycle.state_changed_ns = now;
}

void PeerRuntime::Deactivate(wgnx::platform::ktime_t now) {
    ResetLifecycle(wgnx::PeerRuntimeState::Inactive, 0, now);
}

std::uint32_t PeerRuntime::BeginActivation(wgnx::platform::ktime_t now) {
    const std::uint32_t activation_generation = m_next_activation_generation++;
    if (m_next_activation_generation == 0) {
        m_next_activation_generation = 1;
    }
    ResetLifecycle(
        wgnx::PeerRuntimeState::ResolvingEndpoint,
        activation_generation,
        now);
    return activation_generation;
}

bool PeerRuntime::EnterHandshaking(
    std::uint32_t activation_generation,
    wgnx::platform::ktime_t now) {
    if (!IsCurrentActivation(activation_generation) ||
        m_lifecycle.state != wgnx::PeerRuntimeState::ResolvingEndpoint) {
        return false;
    }
    m_lifecycle.state = wgnx::PeerRuntimeState::Handshaking;
    m_lifecycle.error_stage = wgnx::PeerErrorStage::None;
    m_lifecycle.last_error_code = static_cast<std::uint32_t>(wgnx::PeerErrorCode::None);
    m_lifecycle.state_ticks = 0;
    m_lifecycle.state_changed_ns = now;
    return true;
}

bool PeerRuntime::EnterActive(
    std::uint32_t activation_generation,
    wgnx::platform::ktime_t now) {
    if (!IsCurrentActivation(activation_generation) ||
        m_lifecycle.state != wgnx::PeerRuntimeState::Handshaking) {
        return false;
    }
    m_lifecycle.state = wgnx::PeerRuntimeState::Active;
    m_lifecycle.error_stage = wgnx::PeerErrorStage::None;
    m_lifecycle.last_error_code = static_cast<std::uint32_t>(wgnx::PeerErrorCode::None);
    m_lifecycle.state_ticks = 0;
    m_lifecycle.established = true;
    m_lifecycle.state_changed_ns = now;
    m_lifecycle.last_handshake_ns = now;
    return true;
}

void PeerRuntime::EnterError(
    wgnx::PeerErrorStage stage,
    wgnx::PeerErrorCode code,
    wgnx::platform::ktime_t now) {
    m_lifecycle.state = wgnx::PeerRuntimeState::Error;
    m_lifecycle.error_stage = stage;
    m_lifecycle.last_error_code = static_cast<std::uint32_t>(code);
    m_lifecycle.state_ticks = 0;
    m_lifecycle.established = false;
    ClearDebugProbeState();
    m_lifecycle.state_changed_ns = now;
}

bool PeerRuntime::IsCurrentActivation(std::uint32_t activation_generation) const {
    return IsCurrentGeneration(m_lifecycle.activation_generation, activation_generation);
}

bool PeerRuntime::IsInTransportState() const {
    return m_lifecycle.state == wgnx::PeerRuntimeState::Handshaking ||
           m_lifecycle.state == wgnx::PeerRuntimeState::Active;
}

bool PeerRuntime::AcceptsInnerPacketSubmission() const {
    return m_lifecycle.state == wgnx::PeerRuntimeState::ResolvingEndpoint ||
           IsInTransportState();
}

void PeerRuntime::RecordReceivedBytes(
    std::size_t byte_count,
    wgnx::platform::ktime_t now) {
    m_lifecycle.rx_bytes += byte_count;
    m_lifecycle.last_rx_ns = now;
}

void PeerRuntime::RecordTransmittedBytes(
    std::size_t byte_count,
    wgnx::platform::ktime_t now) {
    m_lifecycle.tx_bytes += byte_count;
    m_lifecycle.last_tx_ns = now;
}

bool PeerRuntime::SetDebugProbeState(
    wgnx::DebugTriggerAction action,
    wgnx::DebugProbeStatus status,
    wgnx::platform::ktime_t now) {
    const bool valid_transition =
        wgnx::wireguard::CanTransitionDebugProbeStatus(m_lifecycle.debug_probe_status, status);
    m_lifecycle.debug_probe_action = action;
    m_lifecycle.debug_probe_status = status;
    m_lifecycle.debug_probe_state_changed_ns = now;
    return valid_transition;
}

void PeerRuntime::ClearDebugProbeState() {
    m_lifecycle.debug_probe_action = wgnx::DebugTriggerAction::None;
    m_lifecycle.debug_probe_status = wgnx::DebugProbeStatus::None;
    m_lifecycle.debug_probe_state_changed_ns = 0;
}

wgnx::PeerInfo PeerRuntime::BuildInfo(
    wgnx::platform::ktime_t now,
    bool is_active,
    bool is_auto_start) const {
    wgnx::PeerInfo peer{};
    std::snprintf(peer.name, sizeof(peer.name), "%s", config.name.data());
    std::snprintf(peer.address, sizeof(peer.address), "%s", config.address.data());
    std::snprintf(peer.endpoint, sizeof(peer.endpoint), "%s", config.endpoint.data());
    std::snprintf(
        peer.resolved_endpoint,
        sizeof(peer.resolved_endpoint),
        "%s",
        binding.EndpointText());
    std::snprintf(
        peer.derived_public_key,
        sizeof(peer.derived_public_key),
        "%s",
        derived.has_derived_public_key ? derived.derived_public_key : "");
    peer.last_handshake_seconds = ComputeElapsedSeconds(m_lifecycle.last_handshake_ns, now);
    peer.last_rx_seconds = ComputeElapsedSeconds(m_lifecycle.last_rx_ns, now);
    peer.last_tx_seconds = ComputeElapsedSeconds(m_lifecycle.last_tx_ns, now);
    peer.last_debug_probe_seconds =
        ComputeElapsedSeconds(m_lifecycle.debug_probe_state_changed_ns, now);
    peer.last_error_code = m_lifecycle.last_error_code;
    peer.debug_probe_action = static_cast<std::uint32_t>(m_lifecycle.debug_probe_action);
    peer.debug_probe_status = static_cast<std::uint32_t>(m_lifecycle.debug_probe_status);
    peer.persistent_keepalive_interval = m_lifecycle.persistent_keepalive_interval;
    peer.runtime_state = static_cast<std::uint8_t>(m_lifecycle.state);
    peer.error_stage = static_cast<std::uint8_t>(m_lifecycle.error_stage);
    peer.resolved_family = static_cast<std::uint8_t>(binding.Endpoint().family);
    peer.rx_bytes = m_lifecycle.rx_bytes;
    peer.tx_bytes = m_lifecycle.tx_bytes;
    peer.flags = BuildPeerFlags(
        is_active,
        is_auto_start,
        m_lifecycle.established,
        m_lifecycle.state,
        binding.HasEndpoint());
    return peer;
}

EffectBatch PeerRuntime::Handle(const PeerEvent &event) {
    return std::visit(
        [this](const auto &value) {
            EffectBatch effects{};
            using Event = std::remove_cvref_t<decltype(value)>;
            if constexpr (std::is_same_v<Event, SessionEstablishedEvent>) {
                if (EnterActive(value.peer.activation_generation, value.occurred_at)) {
                    static_cast<void>(effects.Push(
                        QueueInnerPacketSubmissionEffect{.peer = value.peer}));
                }
            }
            return effects;
        },
        event);
}

} // namespace wgnx::sysmodule::runtime
