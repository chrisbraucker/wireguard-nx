#pragma once

#include "runtime/runtime_events.hpp"
#include "wgnx/platform/clock.hpp"
#include "wgnx/protocol.hpp"
#include "wireguard/debug_probe.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace wgnx::sysmodule::runtime {

struct DebugProbeRequest {
    PeerIdentity peer{};
    wgnx::DebugTriggerAction action{wgnx::DebugTriggerAction::None};
    std::array<char, sizeof(wgnx::PeerInfo::address)> source_address{};
};

struct DebugProbeReplyOutcome {
    bool consumed{false};
    wgnx::wireguard::DebugProbeReplyValidation validation{wgnx::wireguard::DebugProbeReplyValidation::NotDebugReply};
    wgnx::wireguard::DebugProbeReplyInfo info{};
};

enum class DebugProbeQueueResult : std::uint8_t {
    Queued = 0,
    Busy,
    UnsupportedAction,
    InvalidSource,
    InvalidTransition,
    NoActivePeer,
};

class DebugProbeRunner {
  public:
    [[nodiscard]] DebugProbeQueueResult Queue(const PeerIdentity& peer, std::string_view source_address, wgnx::DebugTriggerAction action,
                                              wgnx::platform::ktime_t now);
    [[nodiscard]] bool TakePending(DebugProbeRequest& out);
    [[nodiscard]] std::size_t BuildPacket(const DebugProbeRequest& request, std::span<std::uint8_t> packet, std::uint32_t random_seed);
    [[nodiscard]] bool MarkSent(const DebugProbeRequest& request, wgnx::platform::ktime_t now);
    [[nodiscard]] bool MarkFailed(const DebugProbeRequest& request, wgnx::DebugProbeStatus status, wgnx::platform::ktime_t now);
    [[nodiscard]] DebugProbeReplyOutcome HandleDecryptedPacket(const PeerIdentity& peer, std::span<const std::uint8_t> packet,
                                                               wgnx::platform::ktime_t now);
    [[nodiscard]] bool HandleTimeout(wgnx::platform::ktime_t now);
    void Cancel(const PeerIdentity* peer = nullptr);
    void Project(std::uint32_t peer_index, wgnx::platform::ktime_t now, wgnx::PeerInfo& info) const;

    bool IsPending() const;
    const PeerIdentity& Peer() const {
        return m_peer;
    }
    wgnx::DebugTriggerAction Action() const {
        return m_action;
    }
    wgnx::DebugProbeStatus Status() const {
        return m_status;
    }

  private:
    bool Matches(const DebugProbeRequest& request) const;
    bool Transition(wgnx::DebugProbeStatus status, wgnx::platform::ktime_t now);

    PeerIdentity m_peer{};
    wgnx::DebugTriggerAction m_action{wgnx::DebugTriggerAction::None};
    wgnx::DebugProbeStatus m_status{wgnx::DebugProbeStatus::None};
    std::array<char, sizeof(wgnx::PeerInfo::address)> m_source_address{};
    wgnx::platform::ktime_t m_state_changed_ns{0};
    bool m_request_pending{false};
};

} // namespace wgnx::sysmodule::runtime
