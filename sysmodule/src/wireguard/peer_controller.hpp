#pragma once

#include "wireguard/data.hpp"
#include "wireguard/timer_coordinator.hpp"

#include <cstdint>

namespace wgnx::wireguard {

enum class OutboundSendStage : std::uint8_t {
    None = 0,
    Build,
    Transport,
};

struct OutboundSendObservation {
    bool success{false};
    OutboundSendStage stage{OutboundSendStage::None};
    TransportDataError build_error{TransportDataError::None};
    bool recoverable_transport_error{false};
};

enum class StagedPacketDecision : std::uint8_t {
    RetireSent = 0,
    RetainForHandshake,
    RetireTransportFailure,
    StopOnTerminalFailure,
};

class PeerController {
public:
    TimerCoordinator &Timers() { return m_timers; }
    const TimerCoordinator &Timers() const { return m_timers; }

    static StagedPacketDecision ClassifyStagedSend(
        const OutboundSendObservation &observation);

private:
    TimerCoordinator m_timers{};
};

} // namespace wgnx::wireguard
