#include "wireguard/peer_controller.hpp"

namespace wgnx::wireguard {

StagedPacketTransition PeerController::ApplyStagedSendOutcome(
    wg_peer &peer,
    const OutboundSendOutcome &outcome) const {
    QueueDisposition disposition = QueueDisposition::Sent;
    StagedPacketAction action = StagedPacketAction::Continue;
    bool retire = false;

    switch (outcome.Kind()) {
        case OutboundSendOutcomeKind::Sent:
            retire = true;
            disposition = QueueDisposition::Sent;
            break;
        case OutboundSendOutcomeKind::KeyUnavailable:
            action = StagedPacketAction::InitiateHandshake;
            break;
        case OutboundSendOutcomeKind::TransportDropped:
            retire = true;
            disposition = QueueDisposition::SendFailed;
            break;
        case OutboundSendOutcomeKind::BuildFatal:
        case OutboundSendOutcomeKind::TransportFatal:
            action = StagedPacketAction::StopOnTerminalFailure;
            break;
    }

    if (retire) {
        static_cast<void>(peer.staged_outbound_packets.Pop(nullptr, disposition));
    }
    return {
        .action = action,
        .retired = retire,
        .disposition = disposition,
        .remaining = peer.staged_outbound_packets.Size(),
    };
}

HandshakeTransition PeerController::PrepareFreshInitiation(
    wg_device &device,
    wg_peer &peer,
    bool begin_sequence) {
    if (!wg_device_create_handshake_initiation(&device, &peer.last_initiation)) {
        return {.action = HandshakeTransitionAction::Fatal};
    }
    if (begin_sequence) {
        wg_peer_begin_handshake_retry_sequence(&peer);
    }
    return {.action = HandshakeTransitionAction::SendInitiation};
}

HandshakeTransition PeerController::StartHandshake(wg_device &device, wg_peer &peer) const {
    if (peer.handshake_retry.active && peer.timers.retransmit_handshake.pending) {
        return {};
    }
    return PrepareFreshInitiation(device, peer, true);
}

HandshakeTransition PeerController::HandleHandshakeRetryTimer(
    wg_device &device,
    wg_peer &peer) const {
    const HandshakeRetryTimeoutResult timeout = wg_peer_handle_handshake_retry_timeout(&peer);
    switch (timeout.action) {
        case HandshakeRetryTimeoutAction::Ignore:
            return {};
        case HandshakeRetryTimeoutAction::Exhausted:
            return {
                .action = HandshakeTransitionAction::Exhausted,
                .dropped_staged_packets = timeout.dropped_staged_packets,
            };
        case HandshakeRetryTimeoutAction::Retry:
            return PrepareFreshInitiation(device, peer, false);
    }
    return {.action = HandshakeTransitionAction::Fatal};
}

bool PeerController::CompleteSession(wg_device &device, wg_peer &peer) const {
    if (!noise_handshake_begin_session(&device, &peer)) {
        return false;
    }
    wg_peer_complete_handshake_retry_sequence(&peer);
    return true;
}

bool PeerController::DeriveResponderSession(wg_device &device, wg_peer &peer) const {
    return noise_handshake_begin_session(&device, &peer);
}

void PeerController::ConfirmResponderSession(wg_peer &peer) const {
    wg_peer_complete_handshake_retry_sequence(&peer);
}

} // namespace wgnx::wireguard
