#include "runtime/peer/peer_runtime.hpp"

#include "wireguard/handshake.hpp"
#include "wireguard/messages.hpp"

#include "development_config.hpp"
#include "logger.hpp"

#include <algorithm>
#include <memory>
#include <span>

namespace wgnx::sysmodule::runtime {
bool PeerRuntime::PrepareHandshakeInitiation(PendingDatagramKind kind) {
    auto* peer = ProtocolPeer();
    if (peer == nullptr || !peer->has_last_initiation || m_pending_datagram.IsPending()) {
        return false;
    }

    PendingDatagram pending{};
    if (wgnx::wireguard::SerializeHandshakeInitiation(
            std::span<std::uint8_t>(pending.bytes).first(wgnx::wireguard::HandshakeInitiationSize),
            peer->last_initiation
        ) != wgnx::wireguard::ParseError::None) {
        return false;
    }
    pending.size = wgnx::wireguard::HandshakeInitiationSize;
    pending.generation = AllocateDatagramGeneration();
    pending.kind = kind;
    m_pending_datagram = pending;
    return true;
}

bool PeerRuntime::PrepareHandshakeResponse() {
    auto* peer = ProtocolPeer();
    if (peer == nullptr || m_pending_datagram.IsPending()) {
        return false;
    }

    wgnx::wireguard::message_handshake_response response{};
    PendingDatagram pending{};
    if (!wgnx::wireguard::noise_handshake_create_response(std::addressof(response), peer) ||
        wgnx::wireguard::SerializeHandshakeResponse(
            std::span<std::uint8_t>(pending.bytes).first(wgnx::wireguard::HandshakeResponseSize),
            response
        ) != wgnx::wireguard::ParseError::None ||
        !m_controller.DeriveResponderSession(m_protocol.device, *peer)) {
        return false;
    }

    pending.size = wgnx::wireguard::HandshakeResponseSize;
    pending.generation = AllocateDatagramGeneration();
    pending.kind = PendingDatagramKind::HandshakeResponse;
    m_pending_datagram = pending;
    return true;
}

bool PeerRuntime::PrepareTransportDatagram(
    std::span<const std::uint8_t> payload,
    PendingDatagramKind kind,
    PacketId inner_packet_id,
    wgnx::wireguard::TransportDataError& out_error
) {
    auto* peer = ProtocolPeer();
    if (peer == nullptr || m_pending_datagram.IsPending()) {
        out_error = wgnx::wireguard::TransportDataError::InvalidKeypair;
        return false;
    }

    PendingDatagram pending{};
    const auto result = wgnx::wireguard::noise_create_transport_data_packet(pending.bytes, peer->current_keypair, payload);
    out_error = result.error;
    if (result.error != wgnx::wireguard::TransportDataError::None) {
        return false;
    }
    pending.size = result.packet_size;
    pending.generation = AllocateDatagramGeneration();
    pending.inner_packet_id = inner_packet_id;
    pending.kind = kind;
    m_pending_datagram = pending;
    return true;
}

bool PeerRuntime::StartHandshake(const PeerIdentity& identity, const TimerFacts& timer_facts, EffectBatch& effects, bool retry) {
    // Retransmission is armed only after the initiation is actually submitted.
    static_cast<void>(timer_facts);
    auto* peer = ProtocolPeer();
    if (peer == nullptr) {
        logger::Log(
            "WG handshake start skipped peer=%u activation=%u retry=%u reason=no_protocol_peer",
            identity.peer_index.Value(),
            identity.activation_generation.Value(),
            retry ? 1U : 0U
        );
        return false;
    }
    if (m_pending_datagram.IsPending()) {
        logger::Log(
            "WG handshake start skipped peer=%u activation=%u retry=%u reason=pending_datagram kind=%s generation=%u",
            identity.peer_index.Value(),
            identity.activation_generation.Value(),
            retry ? 1U : 0U,
            GetPendingDatagramKindName(m_pending_datagram.kind),
            m_pending_datagram.generation.Value()
        );
        return false;
    }
    const auto transition =
        retry ? m_controller.HandleHandshakeRetryTimer(m_protocol.device, *peer) : m_controller.StartHandshake(m_protocol.device, *peer);
    if (transition.action == wgnx::wireguard::HandshakeTransitionAction::Ignore) {
        logger::Log(
            "WG handshake start ignored peer=%u activation=%u retry=%u",
            identity.peer_index.Value(),
            identity.activation_generation.Value(),
            retry ? 1U : 0U
        );
        return true;
    }
    if (transition.action != wgnx::wireguard::HandshakeTransitionAction::SendInitiation ||
        !PrepareHandshakeInitiation(PendingDatagramKind::HandshakeInitiation)) {
        logger::Log(
            "WG handshake start failed peer=%u activation=%u retry=%u action=%u",
            identity.peer_index.Value(),
            identity.activation_generation.Value(),
            retry ? 1U : 0U,
            static_cast<unsigned int>(transition.action)
        );
        return false;
    }
    effects.Add(
        SendPendingDatagramEffect{
            .peer = identity,
            .datagram_generation = m_pending_datagram.generation,
        }
    );
    return true;
}

bool PeerRuntime::CanStageInnerPacket() const {
    const auto* peer = ProtocolPeer();
    return peer != nullptr && peer->staged_outbound_packets.Size() < peer->staged_outbound_packets.CapacityValue();
}

std::size_t PeerRuntime::ClearStagedInnerPackets() {
    auto* peer = ProtocolPeer();
    return peer != nullptr ? wgnx::wireguard::wg_peer_clear_staged_outbound_packets(peer) : 0;
}

std::size_t PeerRuntime::StagedInnerPacketCount() const {
    const auto* peer = ProtocolPeer();
    return peer != nullptr ? peer->staged_outbound_packets.Size() : 0;
}

void PeerRuntime::ProcessOutboundQueue(
    const PeerIdentity& identity, const TimerFacts& timer_facts, wgnx::platform::ktime_t now, EffectBatch& effects
) {
    auto* peer = ProtocolPeer();
    if (peer == nullptr || m_pending_datagram.IsPending()) {
        return;
    }

    while (const auto* front = peer->staged_outbound_packets.Front()) {
        if (PeerIndex{front->peer_index} != identity.peer_index ||
            ActivationGeneration{front->activation_generation} != identity.activation_generation) {
            static_cast<void>(peer->staged_outbound_packets.Pop(nullptr, wgnx::wireguard::QueueDisposition::Stale));
            continue;
        }
        if (m_lifecycle.state == wgnx::PeerRuntimeState::ResolvingEndpoint) {
            return;
        }
        // NIFM Unavailable releases the local descriptor but intentionally
        // retains bounded inner packets for the next confirmed local path.
        // Do not consume a peer-owned pending-datagram slot until a binding can
        // actually accept the resulting encrypted datagram.
        if (!m_binding.IsOpen() || m_binding.IsSuspended()) {
            return;
        }
        if (!IsInTransportState()) {
            static_cast<void>(peer->staged_outbound_packets.Pop(nullptr, wgnx::wireguard::QueueDisposition::Unavailable));
            continue;
        }

        const auto action = wgnx::wireguard::wg_peer_get_outbound_staging_action(*peer, wgnx::wireguard::GetMonotonicTime());
        if (action == wgnx::wireguard::OutboundStagingAction::InitiateHandshake) {
            if (!StartHandshake(identity, timer_facts, effects, false)) {
                EnterActivationError(wgnx::PeerErrorStage::Handshake, wgnx::PeerErrorCode::HandshakeInitFailed, now, &effects);
            }
            return;
        }
        if (action != wgnx::wireguard::OutboundStagingAction::Send) {
            return;
        }

        wgnx::wireguard::TransportDataError build_error{};
        if (PrepareTransportDatagram(
                std::span<const std::uint8_t>(front->bytes.data(), front->size),
                PendingDatagramKind::TransportData,
                PacketId{front->packet_id},
                build_error
            )) {
            effects.Add(
                SendPendingDatagramEffect{
                    .peer = identity,
                    .datagram_generation = m_pending_datagram.generation,
                }
            );
            return;
        }

        const auto transition = m_controller.ApplyStagedSendOutcome(*peer, wgnx::wireguard::OutboundSendOutcome::BuildFailed(build_error));
        if (transition.action == wgnx::wireguard::StagedPacketAction::InitiateHandshake) {
            if (!StartHandshake(identity, timer_facts, effects, false)) {
                EnterActivationError(wgnx::PeerErrorStage::Handshake, wgnx::PeerErrorCode::HandshakeInitFailed, now, &effects);
            }
            return;
        }
        if (transition.action == wgnx::wireguard::StagedPacketAction::StopOnTerminalFailure) {
            EnterActivationError(wgnx::PeerErrorStage::Internal, wgnx::PeerErrorCode::InternalFailure, now, &effects);
            return;
        }
    }
}

void PeerRuntime::HandlePendingDatagramCompletion(const PendingDatagramSentEvent& event, EffectBatch& effects) {
    if (!IsCurrentActivation(event.peer.activation_generation) || !m_pending_datagram.IsPending() ||
        m_pending_datagram.generation != event.datagram_generation) {
        return;
    }

    const PendingDatagramKind kind = m_pending_datagram.kind;
    m_pending_datagram = {};
    auto* peer = ProtocolPeer();
    if (event.error == wgnx::platform::socket_error::none) {
        RecordTransmittedBytes(event.bytes_sent, event.occurred_at);
        OnAuthenticatedPacketTraversal(event.peer, event.timer_facts, effects);
        OnAuthenticatedPacketSent(event.peer, effects);
        if (kind == PendingDatagramKind::HandshakeInitiation) {
            effects.Add(
                ArmProtocolTimerEffect{
                    .peer = event.peer,
                    .hook = wgnx::wireguard::TimerHook::RetransmitHandshake,
                    .deadline = HandshakeRetryDeadline(event.timer_facts),
                }
            );
            if (!m_receive_started) {
                // Start initial receive polling only once the initiation crossed
                // the serialized transmit boundary.
                m_receive_started = true;
                effects.Add(QueueReceiveEffect{.peer = event.peer});
            }
        }
        if (kind == PendingDatagramKind::TransportData && peer != nullptr) {
            static_cast<void>(m_controller.ApplyStagedSendOutcome(*peer, wgnx::wireguard::OutboundSendOutcome::Sent()));
            OnDataPacketSent(event.peer, event.timer_facts, effects);
            effects.Add(
                QueueInnerPacketSubmissionEffect{
                    .peer = event.peer,
                }
            );
            RefreshKeyFreshness(event.peer, event.timer_facts, event.occurred_at, effects);
        }
        if (kind == PendingDatagramKind::Keepalive) {
            RefreshKeyFreshness(event.peer, event.timer_facts, event.occurred_at, effects);
        }
        return;
    }

    if (kind == PendingDatagramKind::TransportData && peer != nullptr) {
        static_cast<void>(m_controller.ApplyStagedSendOutcome(*peer, wgnx::wireguard::OutboundSendOutcome::TransportDropped()));
    }
    if (event.error == wgnx::platform::socket_error::send_failed) {
        const auto binding = m_binding.StateSnapshot();
        effects.Append(HandleEvent(
            TransportFailureEvent{
                .peer = event.peer,
                .operation = TransportIoOperation::Send,
                .socket = binding.socket,
                .socket_generation = binding.generation,
                .error = event.error,
                .occurred_at = event.occurred_at,
            }
        ));

        // A local send failure does not prove that the descriptor is stale.
        // Keep the current binding and use the ordinary bounded handshake
        // retry path instead of recursively replacing a live BSD socket.
        if (kind == PendingDatagramKind::HandshakeInitiation) {
            effects.Add(
                ArmProtocolTimerEffect{
                    .peer = event.peer,
                    .hook = wgnx::wireguard::TimerHook::RetransmitHandshake,
                    .deadline = HandshakeRetryDeadline(event.timer_facts),
                }
            );
        }
        return;
    }
    EnterActivationError(wgnx::PeerErrorStage::Transport, wgnx::PeerErrorCode::TransportSendFailed, event.occurred_at, &effects);
}

EffectBatch PeerRuntime::HandleEvent(const PendingDatagramSentEvent& event) {
    EffectBatch effects{};
    HandlePendingDatagramCompletion(event, effects);
    return effects;
}

EffectBatch PeerRuntime::HandleEvent(const InnerPacketStagedEvent& event) {
    EffectBatch effects{};
    auto* peer = ProtocolPeer();
    if (!IsCurrentActivation(event.peer.activation_generation) || !AcceptsInnerPacketSubmission() || peer == nullptr ||
        event.packet.Bytes().empty() || event.packet.Bytes().size() > m_staging_record.bytes.size()) {
        return effects;
    }
    m_staging_record = {};
    m_staging_record.packet_id = event.packet_id.Value();
    m_staging_record.activation_generation = event.peer.activation_generation.Value();
    m_staging_record.peer_index = event.peer.peer_index.Value();
    m_staging_record.size = static_cast<std::uint16_t>(event.packet.Bytes().size());
    std::ranges::copy(event.packet.Bytes(), m_staging_record.bytes.begin());
    if (peer->staged_outbound_packets.Push(m_staging_record) == wgnx::wireguard::QueuePushResult::Full) {
        return effects;
    }
    if (IsInTransportState()) {
        ProcessOutboundQueue(event.peer, event.timer_facts, event.occurred_at, effects);
    }
    return effects;
}

EffectBatch PeerRuntime::HandleEvent(const ProcessOutboundQueueEvent& event) {
    EffectBatch effects{};
    if (IsCurrentActivation(event.peer.activation_generation)) {
        ProcessOutboundQueue(event.peer, event.timer_facts, event.occurred_at, effects);
    }
    return effects;
}

} // namespace wgnx::sysmodule::runtime
