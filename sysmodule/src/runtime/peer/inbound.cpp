#include "runtime/peer/peer_runtime.hpp"

#include "wireguard/handshake.hpp"
#include "wireguard/messages.hpp"

#include "logger.hpp"

#include <memory>

namespace wgnx::sysmodule::runtime {

namespace {

const char *GetIndexSlotName(wgnx::wireguard::wg_index_slot slot) {
    switch (slot) {
        case wgnx::wireguard::wg_index_slot::None: return "none";
        case wgnx::wireguard::wg_index_slot::Handshake: return "handshake";
        case wgnx::wireguard::wg_index_slot::CurrentKeypair: return "current";
        case wgnx::wireguard::wg_index_slot::NextKeypair: return "next";
        case wgnx::wireguard::wg_index_slot::PreviousKeypair: return "previous";
    }
    return "unknown";
}

} // namespace
void PeerRuntime::UpdateEndpointFromAuthenticatedPacket(
    const EncryptedDatagramReceivedEvent &event) {
    if (event.source.family == wgnx::platform::address_family::unspecified) {
        return;
    }
    m_binding.SetEndpoint(event.source, event.source_text.data());
}

void PeerRuntime::CompleteInitiatorSession(
    const EncryptedDatagramReceivedEvent &event,
    EffectBatch &effects) {
    auto *peer = ProtocolPeer();
    if (peer == nullptr || !m_controller.CompleteSession(m_protocol.device, *peer)) {
        logger::Log(
            "Rejected WG handshake response peer=%u activation=%u reason=session_derivation_failed",
            event.peer.peer_index.Value(),
            event.peer.activation_generation.Value());
        return;
    }

    UpdateEndpointFromAuthenticatedPacket(event);
    const auto packet = event.packet.Bytes();
    RecordReceivedBytes(packet.size(), event.occurred_at);
    OnAuthenticatedPacketTraversal(event.peer, event.timer_facts, effects);
    OnAuthenticatedPacketReceived(event.peer, effects);
    if (m_lifecycle.state == wgnx::PeerRuntimeState::Handshaking) {
        if (!EnterActive(event.peer.activation_generation, event.occurred_at)) {
            return;
        }
    } else {
        m_lifecycle.last_handshake_ns = event.occurred_at;
        m_lifecycle.established = true;
    }

    wgnx::wireguard::TransportDataError build_error{};
    if (!PrepareTransportDatagram(
            {},
            PendingDatagramKind::Keepalive,
            PacketId{},
            build_error)) {
        EnterActivationError(
            wgnx::PeerErrorStage::Internal,
            wgnx::PeerErrorCode::InternalFailure,
            event.occurred_at,
            &effects);
        return;
    }

    OnSessionDerived(event.peer, event.timer_facts, effects);
    OnHandshakeComplete(event.peer, effects);
    effects.Add(SendPendingDatagramEffect{
        .peer = event.peer,
        .datagram_generation = m_pending_datagram.generation,
    });
    effects.Add(QueueInnerPacketSubmissionEffect{.peer = event.peer});
}

void PeerRuntime::HandleTransportData(
    const EncryptedDatagramReceivedEvent &event,
    EffectBatch &effects) {
    auto *peer = ProtocolPeer();
    if (peer == nullptr) {
        return;
    }

    wgnx::wireguard::IncomingTransportDataResult result{};
    m_decrypted_packet.size = 0;
    m_decrypted_packet.generation = PacketGeneration{};
    const auto error = wgnx::wireguard::noise_consume_incoming_transport_data_packet(
        event.packet.Bytes(),
        m_protocol.device,
        *peer,
        m_decrypted_packet.bytes,
        result);
    if (error != wgnx::wireguard::TransportDataError::None) {
        logger::Log(
            "Rejected WG transport data peer=%u activation=%u bytes=%zu source=%s slot=%s err=%s",
            event.peer.peer_index.Value(),
            event.peer.activation_generation.Value(),
            event.packet.Bytes().size(),
            event.source_text.data(),
            GetIndexSlotName(result.slot),
            wgnx::wireguard::GetTransportDataErrorName(error));
        return;
    }

    UpdateEndpointFromAuthenticatedPacket(event);
    RecordReceivedBytes(event.packet.Bytes().size(), event.occurred_at);
    OnAuthenticatedPacketTraversal(event.peer, event.timer_facts, effects);
    OnAuthenticatedPacketReceived(event.peer, effects);
    logger::Log(
        "Accepted WG transport data peer=%u activation=%u bytes=%zu payload=%zu source=%s slot=%s counter=%llu promoted=%u",
        event.peer.peer_index.Value(),
        event.peer.activation_generation.Value(),
        event.packet.Bytes().size(),
        result.decrypt.payload_size,
        event.source_text.data(),
        GetIndexSlotName(result.slot),
        static_cast<unsigned long long>(result.decrypt.header.counter),
        result.promoted_next_keypair ? 1U : 0U);

    if (result.promoted_next_keypair) {
        m_controller.ConfirmResponderSession(*peer);
        if (m_lifecycle.state == wgnx::PeerRuntimeState::Handshaking) {
            static_cast<void>(EnterActive(
                event.peer.activation_generation,
                event.occurred_at));
        } else {
            m_lifecycle.last_handshake_ns = event.occurred_at;
            m_lifecycle.established = true;
        }
        OnHandshakeComplete(event.peer, effects);
        effects.Add(QueueInnerPacketSubmissionEffect{.peer = event.peer});
    }

    if (result.decrypt.payload_size == 0) {
        logger::Log(
            "Accepted WG keepalive payload peer=%u activation=%u",
            event.peer.peer_index.Value(),
            event.peer.activation_generation.Value());
        return;
    }

    OnDataPacketReceived(event.peer, event.timer_facts, effects);

    const auto padded_payload = std::span<const std::uint8_t>(
        m_decrypted_packet.bytes.data(),
        result.decrypt.payload_size);
    std::size_t inner_packet_size = 0;
    const auto validation = wgnx::wireguard::ValidatePaddedInnerIpPacket(
        padded_payload,
        std::addressof(inner_packet_size));
    if (validation != wgnx::wireguard::InnerIpValidationError::None) {
        logger::Log(
            "Dropped decrypted inner packet peer=%u activation=%u bytes=%zu validation=%s",
            event.peer.peer_index.Value(),
            event.peer.activation_generation.Value(),
            padded_payload.size(),
            wgnx::wireguard::GetInnerIpValidationErrorName(validation));
        return;
    }

    m_decrypted_packet.size = inner_packet_size;
    m_decrypted_packet.generation = AllocateDecryptedPacketGeneration();
    effects.Add(PublishDecryptedPacketEffect{
        .peer = event.peer,
        .packet_generation = m_decrypted_packet.generation,
    });
}

void PeerRuntime::HandleEncryptedDatagram(
    const EncryptedDatagramReceivedEvent &event,
    EffectBatch &effects) {
    auto *peer = ProtocolPeer();
    const auto packet = event.packet.Bytes();
    if (!IsCurrentActivation(event.peer.activation_generation) ||
        !IsInTransportState() || peer == nullptr || packet.empty()) {
        return;
    }

    const auto type = wgnx::wireguard::InspectMessageType(packet);
    if (!type.success) {
        logger::Log(
            "Rejected WG datagram peer=%u activation=%u bytes=%zu source=%s inspect_err=%s",
            event.peer.peer_index.Value(),
            event.peer.activation_generation.Value(),
            packet.size(),
            event.source_text.data(),
            wgnx::wireguard::GetParseErrorName(type.error));
        return;
    }
    if (type.type == wgnx::wireguard::MessageType::TransportData) {
        HandleTransportData(event, effects);
        return;
    }
    if (m_pending_datagram.IsPending()) {
        logger::Log(
            "Dropped WG handshake datagram peer=%u activation=%u type=%s reason=send_pending",
            event.peer.peer_index.Value(),
            event.peer.activation_generation.Value(),
            wgnx::wireguard::GetMessageTypeName(type.type));
        return;
    }

    const auto outcome = wgnx::wireguard::noise_handshake_consume_incoming_packet(
        packet,
        std::addressof(m_protocol.device),
        peer);
    logger::Log(
        "Processed WG handshake datagram peer=%u activation=%u bytes=%zu source=%s outcome=%s",
            event.peer.peer_index.Value(),
            event.peer.activation_generation.Value(),
        packet.size(),
        event.source_text.data(),
        wgnx::wireguard::GetHandshakePacketOutcomeName(outcome));
    switch (outcome) {
        case wgnx::wireguard::HandshakePacketOutcome::Invalid:
            return;
        case wgnx::wireguard::HandshakePacketOutcome::CookieReplyConsumed:
            RecordReceivedBytes(packet.size(), event.occurred_at);
            return;
        case wgnx::wireguard::HandshakePacketOutcome::ResponseConsumed:
            CompleteInitiatorSession(event, effects);
            return;
        case wgnx::wireguard::HandshakePacketOutcome::InitiationConsumed:
            OnAuthenticatedPacketTraversal(event.peer, event.timer_facts, effects);
            OnAuthenticatedPacketReceived(event.peer, effects);
            if (!PrepareHandshakeResponse()) {
                logger::Log(
                    "Failed WG handshake response peer=%u activation=%u reason=response_or_session_build",
                    event.peer.peer_index.Value(),
                    event.peer.activation_generation.Value());
                return;
            }
            UpdateEndpointFromAuthenticatedPacket(event);
            RecordReceivedBytes(packet.size(), event.occurred_at);
            OnSessionDerived(event.peer, event.timer_facts, effects);
            effects.Add(SendPendingDatagramEffect{
                .peer = event.peer,
                .datagram_generation = m_pending_datagram.generation,
            });
            return;
    }
}

EffectBatch PeerRuntime::HandleEvent(const EncryptedDatagramReceivedEvent &event) {
    EffectBatch effects{};
    HandleEncryptedDatagram(event, effects);
    return effects;
}

} // namespace wgnx::sysmodule::runtime
