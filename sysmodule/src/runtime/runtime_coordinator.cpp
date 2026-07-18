#include "runtime/runtime_coordinator.hpp"

#include <memory>
namespace wgnx::sysmodule::runtime {

bool RuntimeCoordinator::Configure(
    std::span<const wgnx::PeerConfigEntry> configured_peers,
    std::span<PeerConfigDerivedInfo> derived,
    std::int32_t auto_start_peer_index,
    wgnx::platform::ktime_t now) {
    return m_peers.Configure(configured_peers, derived, auto_start_peer_index, now);
}

EffectBatch RuntimeCoordinator::ClearConfiguration(wgnx::platform::ktime_t now) {
    return m_peers.ClearConfiguration(now);
}

bool RuntimeCoordinator::SetActivePeerIndex(std::int32_t peer_index) {
    return m_peers.SetActivePeerIndex(peer_index);
}

bool RuntimeCoordinator::SetAutoStartPeerIndex(std::int32_t peer_index) {
    return m_peers.SetAutoStartPeerIndex(peer_index);
}

EffectBatch RuntimeCoordinator::Dispatch(const PeerEvent &event) {
    return m_peers.Dispatch(event);
}

bool RuntimeCoordinator::IsValidSelection(std::int32_t peer_index) const {
    return m_peers.IsValidSelection(peer_index);
}

const PeerRuntime *RuntimeCoordinator::PeerAt(PeerIndex peer_index) const {
    return m_peers.PeerAt(peer_index);
}

const PeerRuntimeInfo *RuntimeCoordinator::Lifecycle(std::size_t peer_index) const {
    const auto *peer = PeerAt(PeerIndex{static_cast<std::uint32_t>(peer_index)});
    return peer != nullptr ? std::addressof(peer->Lifecycle()) : nullptr;
}

const wgnx::PeerConfigEntry *RuntimeCoordinator::Configuration(std::size_t peer_index) const {
    const auto *peer = PeerAt(PeerIndex{static_cast<std::uint32_t>(peer_index)});
    return peer != nullptr ? std::addressof(peer->Configuration()) : nullptr;
}

UdpBinding::Snapshot RuntimeCoordinator::BindingSnapshot(std::size_t peer_index) const {
    const auto *peer = PeerAt(PeerIndex{static_cast<std::uint32_t>(peer_index)});
    return peer != nullptr ? peer->BindingSnapshot() : UdpBinding::Snapshot{};
}

PeerProtocolSnapshot RuntimeCoordinator::ProtocolSnapshot(std::size_t peer_index) const {
    const auto *peer = PeerAt(PeerIndex{static_cast<std::uint32_t>(peer_index)});
    return peer != nullptr ? peer->ProtocolSnapshot() : PeerProtocolSnapshot{};
}

wgnx::PeerInfo RuntimeCoordinator::BuildPeerInfo(
    std::size_t peer_index,
    wgnx::platform::ktime_t now) const {
    const auto *peer = PeerAt(PeerIndex{static_cast<std::uint32_t>(peer_index)});
    return peer != nullptr
        ? peer->BuildInfo(
              now,
              static_cast<std::int32_t>(peer_index) == m_peers.ActivePeerIndex(),
              static_cast<std::int32_t>(peer_index) == m_peers.AutoStartPeerIndex())
        : wgnx::PeerInfo{};
}

bool RuntimeCoordinator::HasRuntimeErrors() const {
    return m_peers.HasRuntimeErrors();
}

bool RuntimeCoordinator::IsActiveIdentity(const PeerIdentity &identity) const {
    const auto *peer = PeerAt(identity.peer_index);
    return peer != nullptr &&
           m_peers.ActivePeerIndex() == static_cast<std::int32_t>(identity.peer_index.Value()) &&
           peer->IsCurrentActivation(identity.activation_generation);
}

bool RuntimeCoordinator::IsActiveTransportIdentity(const PeerIdentity &identity) const {
    const auto *peer = PeerAt(identity.peer_index);
    return IsActiveIdentity(identity) && peer->IsInTransportState();
}

bool RuntimeCoordinator::IsActiveEstablishedIdentity(const PeerIdentity &identity) const {
    const auto *peer = PeerAt(identity.peer_index);
    return IsActiveIdentity(identity) &&
           peer->Lifecycle().state == wgnx::PeerRuntimeState::Active;
}

bool RuntimeCoordinator::SnapshotReceiveRuntime(ReceiveRuntimeSnapshot &out) const {
    if (m_peers.ActivePeerIndex() < 0) {
        return false;
    }
    const auto peer_index = PeerIndex{
        static_cast<std::uint32_t>(m_peers.ActivePeerIndex())};
    const auto *peer = PeerAt(peer_index);
    if (peer == nullptr || !peer->IsInTransportState()) {
        return false;
    }
    const auto binding = peer->BindingSnapshot();
    if (!binding.IsOpen()) {
        return false;
    }
    out = {
        .peer = {
            .peer_index = peer_index,
            .activation_generation = peer->Lifecycle().activation_generation,
        },
        .socket = binding.socket,
        .socket_generation = binding.generation,
    };
    return true;
}

bool RuntimeCoordinator::SnapshotDebugPeer(DebugPeerSnapshot &out) const {
    if (m_peers.ActivePeerIndex() < 0) {
        return false;
    }
    const auto peer_index = PeerIndex{
        static_cast<std::uint32_t>(m_peers.ActivePeerIndex())};
    const auto *peer = PeerAt(peer_index);
    if (peer == nullptr || peer->Lifecycle().state != wgnx::PeerRuntimeState::Active ||
        !peer->BindingSnapshot().IsOpen() || !peer->CanSendTransportNow()) {
        return false;
    }
    out.peer = {
        .peer_index = peer_index,
        .activation_generation = peer->Lifecycle().activation_generation,
    };
    out.source_address = peer->Configuration().address;
    return true;
}

bool RuntimeCoordinator::SnapshotPacketState(PeerPacketStateSnapshot &out) const {
    if (m_peers.ActivePeerIndex() < 0) {
        return false;
    }
    const auto peer_index = PeerIndex{
        static_cast<std::uint32_t>(m_peers.ActivePeerIndex())};
    const auto *peer = PeerAt(peer_index);
    if (peer == nullptr) {
        return false;
    }
    const auto protocol = peer->ProtocolSnapshot();
    out = {
        .identity = {
            .peer_index = peer_index,
            .activation_generation = peer->Lifecycle().activation_generation,
        },
        .state = peer->Lifecycle().state,
        .staged_packet_count = peer->StagedInnerPacketCount(),
        .protocol_instantiated = protocol.instantiated,
        .can_stage_packet = peer->CanStageInnerPacket(),
    };
    return true;
}

bool RuntimeCoordinator::SnapshotPendingDatagram(
    const PeerIdentity &identity,
    DatagramGeneration datagram_generation,
    PendingDatagramSnapshot &out) const {
    const auto *peer = PeerAt(identity.peer_index);
    return IsActiveIdentity(identity) && peer->SnapshotPendingDatagram(
        identity.activation_generation,
        datagram_generation,
        out);
}

bool RuntimeCoordinator::ViewDecryptedPacket(
    const PeerIdentity &identity,
    PacketGeneration packet_generation,
    DecryptedPacketView &out) const {
    const auto *peer = PeerAt(identity.peer_index);
    return IsActiveIdentity(identity) && peer->ViewDecryptedPacket(
        identity.activation_generation,
        packet_generation,
        out);
}

bool RuntimeCoordinator::IsCurrentTimerEffect(const ArmProtocolTimerEffect &effect) const {
    const auto *peer = PeerAt(effect.peer.peer_index);
    if (!IsActiveIdentity(effect.peer) || peer == nullptr) {
        return false;
    }
    const auto owner = peer->CurrentTimerOwner(effect.hook);
    return peer->IsTimerCurrent(effect.token, owner);
}

std::size_t RuntimeCoordinator::ClearStagedInnerPackets(PeerIndex peer_index) {
    return m_peers.ClearStagedInnerPackets(peer_index);
}

std::size_t RuntimeCoordinator::ClearAllStagedInnerPackets() {
    return m_peers.ClearAllStagedInnerPackets();
}

} // namespace wgnx::sysmodule::runtime
