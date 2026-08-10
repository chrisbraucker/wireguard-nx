#include "runtime/packet_data_plane.hpp"

#include "runtime/peer/peer_runtime.hpp"
#include "runtime/runtime_coordinator.hpp"

#include <cstring>
#include <memory>

namespace wgnx::sysmodule::runtime {

PacketSubmissionOutcome PacketDataPlane::SubmitIpPacket(
    std::span<const std::uint8_t> packet,
    ProcessId consumer_id,
    const TimerFacts& timer_facts,
    wgnx::platform::ktime_t occurred_at,
    EffectBatch& out_effects
) {
    return SubmitValidatedPacket(
        packet,
        consumer_id,
        timer_facts,
        occurred_at,
        wireguard::ValidateInnerIpPacket(packet),
        true,
        out_effects
    );
}

PacketSubmissionOutcome PacketDataPlane::SubmitIpv4Packet(
    std::span<const std::uint8_t> packet,
    ProcessId consumer_id,
    const TimerFacts& timer_facts,
    wgnx::platform::ktime_t occurred_at,
    EffectBatch& out_effects
) {
    return SubmitValidatedPacket(
        packet,
        consumer_id,
        timer_facts,
        occurred_at,
        wireguard::ValidateInnerIpv4Packet(packet),
        true,
        out_effects
    );
}

PacketSubmissionOutcome PacketDataPlane::SubmitInternalIpPacket(
    std::span<const std::uint8_t> packet, const TimerFacts& timer_facts, wgnx::platform::ktime_t occurred_at, EffectBatch& out_effects
) {
    return SubmitValidatedPacket(
        packet,
        ProcessId{},
        timer_facts,
        occurred_at,
        wireguard::ValidateInnerIpPacket(packet),
        false,
        out_effects
    );
}

PacketSubmissionOutcome PacketDataPlane::SubmitInternalIpPacketBatch(
    std::span<const SynchronousPacketView> packets,
    const TimerFacts& timer_facts,
    wgnx::platform::ktime_t occurred_at,
    EffectBatch& out_effects
) {
    PeerPacketStateSnapshot peer{};
    if (!m_coordinator.SnapshotPacketState(peer)) {
        out_effects.Clear();
        return {.status = PacketSubmissionStatus::TunnelUnavailable};
    }
    return SubmitInternalIpPacketBatchForPeer(peer.identity, packets, timer_facts, occurred_at, out_effects);
}

PacketSubmissionOutcome PacketDataPlane::SubmitInternalIpPacketBatchForPeer(
    const PeerIdentity& peer_identity,
    std::span<const SynchronousPacketView> packets,
    const TimerFacts& timer_facts,
    wgnx::platform::ktime_t occurred_at,
    EffectBatch& out_effects
) {
    out_effects.Clear();
    PacketSubmissionOutcome outcome{.status = PacketSubmissionStatus::InternalError};
    if (packets.empty() || packets.size() > MaximumInnerPacketBatchSize) {
        outcome.status = PacketSubmissionStatus::MalformedPacket;
        return outcome;
    }
    for (const auto& packet : packets) {
        outcome.packet_size += packet.Bytes().size();
        outcome.validation = wireguard::ValidateInnerIpPacket(packet.Bytes());
        if (outcome.validation != wireguard::InnerIpValidationError::None) {
            outcome.status = PacketSubmissionStatus::MalformedPacket;
            return outcome;
        }
    }
    PeerPacketStateSnapshot peer{};
    if (!m_coordinator.SnapshotPacketState(peer) || peer.identity != peer_identity) {
        outcome.status = PacketSubmissionStatus::TunnelUnavailable;
        return outcome;
    }
    outcome.has_peer = true;
    outcome.peer = peer.identity;
    outcome.peer_state = peer.state;
    if ((peer.state != wgnx::PeerRuntimeState::ResolvingEndpoint && peer.state != wgnx::PeerRuntimeState::Handshaking &&
         peer.state != wgnx::PeerRuntimeState::Active) ||
        !peer.protocol_instantiated) {
        outcome.status = PacketSubmissionStatus::TunnelUnavailable;
        return outcome;
    }
    if (peer.staged_packet_count + packets.size() > wgnx::wireguard::PeerStagedPacketCapacity) {
        outcome.status = PacketSubmissionStatus::QueueFull;
        return outcome;
    }
    InnerPacketBatchStagedEvent event{
        .peer = outcome.peer,
        .count = static_cast<std::uint8_t>(packets.size()),
        .timer_facts = timer_facts,
        .occurred_at = occurred_at,
    };
    for (std::size_t index = 0; index < packets.size(); ++index) {
        event.packets[index] = packets[index];
        event.packet_ids[index] = AllocatePacketId();
        if (index == 0) {
            outcome.packet_id = event.packet_ids[index];
        }
    }
    out_effects = m_coordinator.Dispatch(event);
    if (m_coordinator.SnapshotPacketState(peer) && peer.identity == outcome.peer) {
        outcome.queue_depth = peer.staged_packet_count;
    }
    outcome.status = PacketSubmissionStatus::Queued;
    return outcome;
}

PacketSubmissionOutcome PacketDataPlane::SubmitValidatedPacket(
    std::span<const std::uint8_t> packet,
    ProcessId consumer_id,
    const TimerFacts& timer_facts,
    wgnx::platform::ktime_t occurred_at,
    wireguard::InnerIpValidationError validation,
    bool claim_transport,
    EffectBatch& out_effects
) {
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
    PeerPacketStateSnapshot peer{};
    if (!m_coordinator.SnapshotPacketState(peer)) {
        outcome.status = PacketSubmissionStatus::TunnelUnavailable;
        return outcome;
    }
    outcome.has_peer = true;
    outcome.peer = peer.identity;
    outcome.peer_state = peer.state;
    if (peer.state != wgnx::PeerRuntimeState::ResolvingEndpoint && peer.state != wgnx::PeerRuntimeState::Handshaking &&
        peer.state != wgnx::PeerRuntimeState::Active) {
        outcome.status = PacketSubmissionStatus::TunnelUnavailable;
        return outcome;
    }

    if (claim_transport && !m_transport.IsOwnedBy(consumer_id)) {
        if (!peer.protocol_instantiated) {
            return outcome;
        }
        outcome.discarded_outbound = m_coordinator.ClearStagedInnerPackets(peer.identity.peer_index);
        outcome.discarded_inbound = m_transport.Claim(consumer_id);
        outcome.ownership_transferred = true;
        if (!m_coordinator.SnapshotPacketState(peer)) {
            return outcome;
        }
    }

    if (!peer.can_stage_packet) {
        outcome.status = peer.protocol_instantiated ? PacketSubmissionStatus::QueueFull : PacketSubmissionStatus::InternalError;
        return outcome;
    }
    if (!peer.protocol_instantiated) {
        return outcome;
    }

    outcome.packet_id = AllocatePacketId();
    out_effects = m_coordinator.Dispatch(
        InnerPacketStagedEvent{
            .peer = outcome.peer,
            .packet = SynchronousPacketView{packet},
            .packet_id = outcome.packet_id,
            .timer_facts = timer_facts,
            .occurred_at = occurred_at,
        }
    );
    if (m_coordinator.SnapshotPacketState(peer) && peer.identity == outcome.peer) {
        outcome.queue_depth = peer.staged_packet_count;
    }
    outcome.status = PacketSubmissionStatus::Queued;
    return outcome;
}

PacketDeliveryOutcome PacketDataPlane::DeliverDecryptedPacket(const PeerIdentity& peer_identity, std::span<const std::uint8_t> packet) {
    PacketDeliveryOutcome outcome{.packet_size = packet.size()};
    outcome.queue_capacity = m_transport.ReceivedCapacity();
    if (!m_coordinator.IsActiveIdentity(peer_identity)) {
        return outcome;
    }
    if (m_transport.ConsumerId().IsZero()) {
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
    const auto packet_id = AllocatePacketId();
    record.packet_id = packet_id.Value();
    record.activation_generation = peer_identity.activation_generation.Value();
    record.peer_index = peer_identity.peer_index.Value();
    record.size = static_cast<std::uint16_t>(packet.size());
    std::memcpy(record.bytes.data(), packet.data(), packet.size());
    outcome.packet_id = packet_id;
    if (m_transport.PushReceived(record) == wireguard::QueuePushResult::Full) {
        outcome.status = PacketDeliveryStatus::QueueFull;
        outcome.queue_depth = m_transport.ReceivedSize();
        return outcome;
    }

    outcome.status = PacketDeliveryStatus::Queued;
    outcome.queue_depth = m_transport.ReceivedSize();
    return outcome;
}

PacketReceiveOutcome PacketDataPlane::ReceivePacket(std::span<std::uint8_t> packet, ProcessId consumer_id) {
    PacketReceiveOutcome outcome{};
    if (!m_transport.IsOwnedBy(consumer_id)) {
        outcome.status = PacketReceiveStatus::AccessDenied;
        return outcome;
    }

    const auto* front = m_transport.FrontReceived();
    if (front == nullptr) {
        return outcome;
    }
    outcome.packet_id = PacketId{front->packet_id};
    outcome.packet_size = front->size;
    outcome.peer = {
        .peer_index = PeerIndex{front->peer_index},
        .activation_generation = ActivationGeneration{front->activation_generation},
    };
    if (!m_coordinator.IsActiveIdentity(outcome.peer)) {
        wireguard::InnerPacketRecord stale{};
        static_cast<void>(m_transport.PopReceived(std::addressof(stale), wireguard::QueueDisposition::Stale));
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
    static_cast<void>(m_transport.PopReceived(std::addressof(delivered), wireguard::QueueDisposition::Delivered));
    outcome.status = PacketReceiveStatus::Success;
    outcome.queue_depth = m_transport.ReceivedSize();
    return outcome;
}

PacketClearOutcome PacketDataPlane::Clear() {
    PacketClearOutcome outcome{};
    outcome.outbound_count = m_coordinator.ClearAllStagedInnerPackets();
    outcome.inbound_count = m_transport.Release();
    return outcome;
}

PacketId PacketDataPlane::AllocatePacketId() {
    return AllocateGeneration(m_next_packet_id);
}

} // namespace wgnx::sysmodule::runtime
