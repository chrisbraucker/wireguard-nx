#include "wireguard/peer_controller.hpp"

namespace wgnx::wireguard {

StagedPacketDecision PeerController::ClassifyStagedSend(
    const OutboundSendObservation &observation) {
    if (observation.success) {
        return StagedPacketDecision::RetireSent;
    }
    if (observation.stage == OutboundSendStage::Build &&
        (observation.build_error == TransportDataError::InvalidKeypair ||
         observation.build_error == TransportDataError::KeyExpired ||
         observation.build_error == TransportDataError::CounterExhausted)) {
        return StagedPacketDecision::RetainForHandshake;
    }
    if (observation.stage == OutboundSendStage::Transport &&
        observation.recoverable_transport_error) {
        return StagedPacketDecision::RetireTransportFailure;
    }
    return StagedPacketDecision::StopOnTerminalFailure;
}

} // namespace wgnx::wireguard
