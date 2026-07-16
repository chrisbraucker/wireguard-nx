#pragma once

#include "wireguard/data.hpp"
#include "wireguard/device.hpp"
#include "wireguard/timer_coordinator.hpp"

#include <cstdint>

namespace wgnx::wireguard {

enum class OutboundSendOutcomeKind : std::uint8_t {
    Sent = 0,
    KeyUnavailable,
    BuildFatal,
    TransportDropped,
    TransportFatal,
};

class OutboundSendOutcome {
public:
    static constexpr OutboundSendOutcome Sent() {
        return OutboundSendOutcome(OutboundSendOutcomeKind::Sent);
    }

    static constexpr OutboundSendOutcome BuildFailed(TransportDataError error) {
        const bool key_unavailable = error == TransportDataError::InvalidKeypair ||
                                     error == TransportDataError::KeyExpired ||
                                     error == TransportDataError::CounterExhausted;
        return OutboundSendOutcome(
            key_unavailable ? OutboundSendOutcomeKind::KeyUnavailable
                            : OutboundSendOutcomeKind::BuildFatal,
            error);
    }

    static constexpr OutboundSendOutcome TransportDropped() {
        return OutboundSendOutcome(OutboundSendOutcomeKind::TransportDropped);
    }

    static constexpr OutboundSendOutcome TransportFatal() {
        return OutboundSendOutcome(OutboundSendOutcomeKind::TransportFatal);
    }

    constexpr OutboundSendOutcomeKind Kind() const { return m_kind; }
    constexpr TransportDataError BuildError() const { return m_build_error; }

private:
    constexpr explicit OutboundSendOutcome(
        OutboundSendOutcomeKind kind,
        TransportDataError build_error = TransportDataError::None)
        : m_kind(kind), m_build_error(build_error) {}

    OutboundSendOutcomeKind m_kind;
    TransportDataError m_build_error;
};

enum class StagedPacketAction : std::uint8_t {
    Continue = 0,
    InitiateHandshake,
    StopOnTerminalFailure,
};

struct StagedPacketTransition {
    StagedPacketAction action{StagedPacketAction::Continue};
    bool retired{false};
    QueueDisposition disposition{QueueDisposition::Sent};
    std::size_t remaining{0};
};

enum class HandshakeTransitionAction : std::uint8_t {
    Ignore = 0,
    SendInitiation,
    Exhausted,
    Fatal,
};

struct HandshakeTransition {
    HandshakeTransitionAction action{HandshakeTransitionAction::Ignore};
    std::size_t dropped_staged_packets{0};
};

class PeerController {
public:
    TimerCoordinator &Timers() { return m_timers; }
    const TimerCoordinator &Timers() const { return m_timers; }

    StagedPacketTransition ApplyStagedSendOutcome(
        wg_peer &peer,
        const OutboundSendOutcome &outcome) const;
    HandshakeTransition StartHandshake(wg_device &device, wg_peer &peer) const;
    HandshakeTransition HandleHandshakeRetryTimer(wg_device &device, wg_peer &peer) const;
    bool CompleteSession(wg_device &device, wg_peer &peer) const;
    bool DeriveResponderSession(wg_device &device, wg_peer &peer) const;
    void ConfirmResponderSession(wg_peer &peer) const;

private:
    static HandshakeTransition PrepareFreshInitiation(
        wg_device &device,
        wg_peer &peer,
        bool begin_sequence);

    TimerCoordinator m_timers{};
};

} // namespace wgnx::wireguard
