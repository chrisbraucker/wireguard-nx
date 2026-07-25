#include "runtime/debug_probe_runner.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace wgnx::sysmodule::runtime {

namespace {

std::int32_t ElapsedSeconds(wgnx::platform::ktime_t timestamp, wgnx::platform::ktime_t now) {
    if (timestamp <= 0 || now < timestamp) {
        return -1;
    }
    constexpr auto NanosecondsPerSecond = wgnx::platform::ktime_t{1'000'000'000};
    const auto elapsed = (now - timestamp) / NanosecondsPerSecond;
    return elapsed > std::numeric_limits<std::int32_t>::max() ? std::numeric_limits<std::int32_t>::max()
                                                              : static_cast<std::int32_t>(elapsed);
}

} // namespace

DebugProbeQueueResult DebugProbeRunner::Queue(const PeerIdentity& peer, std::string_view source_address, wgnx::DebugTriggerAction action,
                                              wgnx::platform::ktime_t now) {
    if (IsPending()) {
        return DebugProbeQueueResult::Busy;
    }
    if (!wgnx::wireguard::IsSupportedDebugTriggerAction(action)) {
        return DebugProbeQueueResult::UnsupportedAction;
    }
    if (source_address.empty() || source_address.size() >= m_source_address.size()) {
        return DebugProbeQueueResult::InvalidSource;
    }
    if (!Transition(wgnx::DebugProbeStatus::Queued, now)) {
        return DebugProbeQueueResult::InvalidTransition;
    }

    m_peer = peer;
    m_action = action;
    std::ranges::fill(m_source_address, '\0');
    std::memcpy(m_source_address.data(), source_address.data(), source_address.size());
    m_request_pending = true;
    return DebugProbeQueueResult::Queued;
}

bool DebugProbeRunner::TakePending(DebugProbeRequest& out) {
    if (!m_request_pending || m_status != wgnx::DebugProbeStatus::Queued) {
        return false;
    }
    out = {
        .peer = m_peer,
        .action = m_action,
        .source_address = m_source_address,
    };
    m_request_pending = false;
    return true;
}

std::size_t DebugProbeRunner::BuildPacket(const DebugProbeRequest& request, std::span<std::uint8_t> packet, std::uint32_t random_seed) {
    if (!Matches(request) || m_status != wgnx::DebugProbeStatus::Queued) {
        return 0;
    }
    return wgnx::wireguard::BuildDebugIcmpEchoRequest(packet, request.source_address.data(), request.action,
                                                      request.peer.activation_generation.Value(), request.peer.peer_index.Value(),
                                                      random_seed);
}

bool DebugProbeRunner::MarkSent(const DebugProbeRequest& request, wgnx::platform::ktime_t now) {
    return Matches(request) && Transition(wgnx::DebugProbeStatus::Sent, now);
}

bool DebugProbeRunner::MarkFailed(const DebugProbeRequest& request, wgnx::DebugProbeStatus status, wgnx::platform::ktime_t now) {
    return Matches(request) && Transition(status, now);
}

DebugProbeReplyOutcome DebugProbeRunner::HandleDecryptedPacket(const PeerIdentity& peer, std::span<const std::uint8_t> packet,
                                                               wgnx::platform::ktime_t now) {
    DebugProbeReplyOutcome outcome{};
    if (m_status != wgnx::DebugProbeStatus::Sent) {
        return outcome;
    }

    outcome.validation = wgnx::wireguard::ValidateDebugIcmpEchoReply(packet, m_source_address.data(), m_peer.peer_index.Value(),
                                                                     m_peer.activation_generation.Value(), &outcome.info);
    if (outcome.validation == wgnx::wireguard::DebugProbeReplyValidation::NotDebugReply) {
        return outcome;
    }

    outcome.consumed = true;
    if (peer != m_peer) {
        outcome.validation = wgnx::wireguard::DebugProbeReplyValidation::ActivationMismatch;
    }
    static_cast<void>(Transition(outcome.validation == wgnx::wireguard::DebugProbeReplyValidation::Valid
                                     ? wgnx::DebugProbeStatus::ReplyValidated
                                     : wgnx::DebugProbeStatus::ReplyRejected,
                                 now));
    return outcome;
}

bool DebugProbeRunner::HandleTimeout(wgnx::platform::ktime_t now) {
    return m_status == wgnx::DebugProbeStatus::Sent && Transition(wgnx::DebugProbeStatus::TimedOut, now);
}

void DebugProbeRunner::Cancel(const PeerIdentity* peer) {
    if (peer != nullptr && *peer != m_peer) {
        return;
    }
    m_peer = {};
    m_action = wgnx::DebugTriggerAction::None;
    m_status = wgnx::DebugProbeStatus::None;
    std::ranges::fill(m_source_address, '\0');
    m_state_changed_ns = 0;
    m_request_pending = false;
}

void DebugProbeRunner::Project(std::uint32_t peer_index, wgnx::platform::ktime_t now, wgnx::PeerInfo& info) const {
    if (m_status == wgnx::DebugProbeStatus::None || m_peer.peer_index != PeerIndex{peer_index}) {
        return;
    }
    info.debug_probe_action = static_cast<std::uint32_t>(m_action);
    info.debug_probe_status = static_cast<std::uint32_t>(m_status);
    info.last_debug_probe_seconds = ElapsedSeconds(m_state_changed_ns, now);
}

bool DebugProbeRunner::IsPending() const {
    return m_status == wgnx::DebugProbeStatus::Queued || m_status == wgnx::DebugProbeStatus::Sent;
}

bool DebugProbeRunner::Matches(const DebugProbeRequest& request) const {
    return request.peer == m_peer && request.action == m_action;
}

bool DebugProbeRunner::Transition(wgnx::DebugProbeStatus status, wgnx::platform::ktime_t now) {
    if (!wgnx::wireguard::CanTransitionDebugProbeStatus(m_status, status)) {
        return false;
    }
    m_status = status;
    m_state_changed_ns = now;
    return true;
}

} // namespace wgnx::sysmodule::runtime
