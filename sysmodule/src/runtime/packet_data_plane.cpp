#include "runtime/packet_data_plane.hpp"

#include "runtime/peer_runtime.hpp"
#include "runtime/runtime_coordinator.hpp"

#include <cstring>
#include <memory>

namespace wgnx::sysmodule::runtime {

PacketSubmissionOutcome PacketDataPlane::SubmitIpPacket(
    std::span<const std::uint8_t> packet,
    PacketConsumerId consumer_id,
    wireguard::TimerDeadline retry_deadline,
    wgnx::platform::ktime_t occurred_at,
    EffectBatch &out_effects) {
    return SubmitValidatedPacket(
        packet,
        consumer_id,
        retry_deadline,
        occurred_at,
        wireguard::ValidateInnerIpPacket(packet),
        out_effects);
}

PacketSubmissionOutcome PacketDataPlane::SubmitIpv4Packet(
    std::span<const std::uint8_t> packet,
    PacketConsumerId consumer_id,
    wireguard::TimerDeadline retry_deadline,
    wgnx::platform::ktime_t occurred_at,
    EffectBatch &out_effects) {
    return SubmitValidatedPacket(
        packet,
        consumer_id,
        retry_deadline,
        occurred_at,
        wireguard::ValidateInnerIpv4Packet(packet),
        out_effects);
}

PacketSubmissionOutcome PacketDataPlane::SubmitValidatedPacket(
    std::span<const std::uint8_t> packet,
    PacketConsumerId consumer_id,
    wireguard::TimerDeadline retry_deadline,
    wgnx::platform::ktime_t occurred_at,
    wireguard::InnerIpValidationError validation,
    EffectBatch &out_effects) {
    out_effects.Clear();
    PacketSubmissionOutcome outcome{
        .status = PacketSubmissionStatus::InternalError,
        .validation = validation,
        .packet_size = packet.size(),
    };
    if (validation != wireguard::InnerIpValidationError::None) {
        outcome.status = PacketSubmissionStatus::MalformedPacket;
        return outcome;
    }
    if (m_peers.ActivePeerIndex() < 0) {
        outcome.status = PacketSubmissionStatus::TunnelUnavailable;
        return outcome;
    }

    const auto peer_index = static_cast<std::uint32_t>(m_peers.ActivePeerIndex());
    auto &peer = m_peers[peer_index];
    const auto &lifecycle = peer.Lifecycle();
    outcome.has_peer = true;
    outcome.peer = {
        .peer_index = peer_index,
        .activation_generation = lifecycle.activation_generation,
    };
    outcome.peer_state = lifecycle.state;
    if (lifecycle.state != wgnx::PeerRuntimeState::ResolvingEndpoint &&
        lifecycle.state != wgnx::PeerRuntimeState::Handshaking &&
        lifecycle.state != wgnx::PeerRuntimeState::Active) {
        outcome.status = PacketSubmissionStatus::TunnelUnavailable;
        return outcome;
    }

    if (!m_transport.IsOwnedBy(consumer_id)) {
        if (!peer.protocol.instantiated) {
            return outcome;
        }
        outcome.discarded_outbound = peer.ClearStagedInnerPackets();
        outcome.discarded_inbound = m_transport.Claim(consumer_id);
        outcome.ownership_transferred = true;
    }

    if (!peer.CanStageInnerPacket()) {
        outcome.status = peer.protocol.instantiated
            ? PacketSubmissionStatus::QueueFull
            : PacketSubmissionStatus::InternalError;
        return outcome;
    }
    if (!peer.protocol.instantiated) {
        return outcome;
    }

    outcome.packet_id = AllocatePacketId();
    out_effects = m_coordinator.Dispatch(InnerPacketStagedEvent{
        .peer = outcome.peer,
        .packet = packet,
        .packet_id = outcome.packet_id,
        .retry_deadline = retry_deadline,
        .occurred_at = occurred_at,
    });
    outcome.queue_depth = peer.StagedInnerPacketCount();
    outcome.status = PacketSubmissionStatus::Queued;
    return outcome;
}

PacketDeliveryOutcome PacketDataPlane::DeliverDecryptedPacket(
    const PeerIdentity &peer_identity,
    std::span<const std::uint8_t> packet) {
    PacketDeliveryOutcome outcome{.packet_size = packet.size()};
    outcome.queue_capacity = m_transport.ReceivedCapacity();
    if (peer_identity.peer_index >= m_peers.Count() ||
        m_peers.ActivePeerIndex() != static_cast<std::int32_t>(peer_identity.peer_index) ||
        !m_peers[peer_identity.peer_index].IsCurrentActivation(
            peer_identity.activation_generation)) {
        return outcome;
    }
    if (m_transport.ConsumerId() == 0) {
        outcome.status = PacketDeliveryStatus::NoConsumer;
        return outcome;
    }

    outcome.validation = wireguard::ValidateInnerIpPacket(packet, &outcome.version);
    if (outcome.validation != wireguard::InnerIpValidationError::None) {
        outcome.status = PacketDeliveryStatus::MalformedPacket;
        return outcome;
    }
    if (!m_transport.AcceptsDelivery(outcome.version)) {
        outcome.status = PacketDeliveryStatus::UnsupportedPacket;
        return outcome;
    }

    wireguard::InnerPacketRecord record{};
    record.packet_id = AllocatePacketId();
    record.activation_generation = peer_identity.activation_generation;
    record.peer_index = peer_identity.peer_index;
    record.size = static_cast<std::uint16_t>(packet.size());
    std::memcpy(record.bytes.data(), packet.data(), packet.size());
    outcome.packet_id = record.packet_id;
    if (m_transport.PushReceived(record) == wireguard::QueuePushResult::Full) {
        outcome.status = PacketDeliveryStatus::QueueFull;
        outcome.queue_depth = m_transport.ReceivedSize();
        return outcome;
    }

    outcome.status = PacketDeliveryStatus::Queued;
    outcome.queue_depth = m_transport.ReceivedSize();
    return outcome;
}

PacketReceiveOutcome PacketDataPlane::ReceivePacket(
    std::span<std::uint8_t> packet,
    PacketConsumerId consumer_id) {
    PacketReceiveOutcome outcome{};
    if (!m_transport.IsOwnedBy(consumer_id)) {
        outcome.status = PacketReceiveStatus::AccessDenied;
        return outcome;
    }

    const auto *front = m_transport.FrontReceived();
    if (front == nullptr) {
        return outcome;
    }
    outcome.packet_id = front->packet_id;
    outcome.packet_size = front->size;
    outcome.peer = {
        .peer_index = front->peer_index,
        .activation_generation = front->activation_generation,
    };
    if (front->peer_index >= m_peers.Count() ||
        m_peers.ActivePeerIndex() != static_cast<std::int32_t>(front->peer_index) ||
        !m_peers[front->peer_index].IsCurrentActivation(front->activation_generation)) {
        wireguard::InnerPacketRecord stale{};
        static_cast<void>(m_transport.PopReceived(
            std::addressof(stale),
            wireguard::QueueDisposition::Stale));
        outcome.status = PacketReceiveStatus::StaleActivation;
        outcome.queue_depth = m_transport.ReceivedSize();
        return outcome;
    }
    if (packet.size() < front->size) {
        outcome.status = PacketReceiveStatus::OutputBufferTooSmall;
        outcome.queue_depth = m_transport.ReceivedSize();
        return outcome;
    }

    std::memcpy(packet.data(), front->bytes.data(), front->size);
    wireguard::InnerPacketRecord delivered{};
    static_cast<void>(m_transport.PopReceived(
        std::addressof(delivered),
        wireguard::QueueDisposition::Delivered));
    outcome.status = PacketReceiveStatus::Success;
    outcome.queue_depth = m_transport.ReceivedSize();
    return outcome;
}

PacketClearOutcome PacketDataPlane::Clear() {
    PacketClearOutcome outcome{};
    for (std::size_t peer_index = 0; peer_index < m_peers.Count(); ++peer_index) {
        outcome.outbound_count += m_peers[peer_index].ClearStagedInnerPackets();
    }
    outcome.inbound_count = m_transport.Release();
    return outcome;
}

std::uint64_t PacketDataPlane::AllocatePacketId() {
    const std::uint64_t packet_id = m_next_packet_id++;
    if (m_next_packet_id == 0) {
        m_next_packet_id = 1;
    }
    return packet_id;
}

} // namespace wgnx::sysmodule::runtime
