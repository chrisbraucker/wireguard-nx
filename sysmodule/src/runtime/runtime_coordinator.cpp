#include "runtime/runtime_coordinator.hpp"

#include <memory>
#include <utility>

namespace wgnx::sysmodule::runtime {

bool RuntimeCoordinator::Configure(
    std::span<const wgnx::PeerConfigEntry> configured_peers,
    std::span<PeerConfigDerivedInfo> derived,
    std::int32_t auto_start_peer_index,
    wgnx::platform::ktime_t now) {
    if (configured_peers.size() > m_peers.m_peers.size() ||
        derived.size() != configured_peers.size() ||
        !IsValidPeerSelection(
            auto_start_peer_index,
            static_cast<std::uint32_t>(configured_peers.size()))) {
        return false;
    }

    ClearConfiguration(now);
    m_peers.m_count = static_cast<std::uint32_t>(configured_peers.size());
    for (std::size_t index = 0; index < configured_peers.size(); ++index) {
        m_peers.m_peers[index].Configure(
            PeerIndex{static_cast<std::uint32_t>(index)},
            configured_peers[index],
            std::move(derived[index]),
            now);
    }
    m_peers.m_auto_start_peer_index = auto_start_peer_index;
    return true;
}

void RuntimeCoordinator::ClearConfiguration(wgnx::platform::ktime_t now) {
    for (std::size_t index = 0; index < m_peers.m_count; ++index) {
        auto &peer = m_peers.m_peers[index];
        peer.m_binding.Reset();
        peer.Deactivate(now);
        peer.m_config = {};
        peer.m_derived = {};
    }
    m_peers.m_count = 0;
    m_peers.m_active_peer_index = -1;
    m_peers.m_auto_start_peer_index = -1;
}

bool RuntimeCoordinator::SetActivePeerIndex(std::int32_t peer_index) {
    if (!IsValidSelection(peer_index)) {
        return false;
    }
    m_peers.m_active_peer_index = peer_index;
    return true;
}

bool RuntimeCoordinator::SetAutoStartPeerIndex(std::int32_t peer_index) {
    if (!IsValidSelection(peer_index)) {
        return false;
    }
    m_peers.m_auto_start_peer_index = peer_index;
    return true;
}

EffectBatch RuntimeCoordinator::Dispatch(const PeerEvent &event) {
    const PeerIdentity identity = GetPeerIdentity(event);
    auto *peer = MutablePeerAt(identity.peer_index);
    if (peer == nullptr) {
        return {};
    }
    return peer->Handle(event);
}

bool RuntimeCoordinator::IsValidSelection(std::int32_t peer_index) const {
    return IsValidPeerSelection(peer_index, m_peers.m_count);
}

const PeerRuntime *RuntimeCoordinator::PeerAt(PeerIndex peer_index) const {
    return peer_index.Value() < m_peers.m_count
        ? std::addressof(m_peers.m_peers[peer_index.Value()])
        : nullptr;
}

PeerRuntime *RuntimeCoordinator::MutablePeerAt(PeerIndex peer_index) {
    return peer_index.Value() < m_peers.m_count
        ? std::addressof(m_peers.m_peers[peer_index.Value()])
        : nullptr;
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
              static_cast<std::int32_t>(peer_index) == m_peers.m_active_peer_index,
              static_cast<std::int32_t>(peer_index) == m_peers.m_auto_start_peer_index)
        : wgnx::PeerInfo{};
}

bool RuntimeCoordinator::HasRuntimeErrors() const {
    for (std::size_t index = 0; index < m_peers.m_count; ++index) {
        if (m_peers.m_peers[index].Lifecycle().state == wgnx::PeerRuntimeState::Error) {
            return true;
        }
    }
    return false;
}

bool RuntimeCoordinator::IsActiveIdentity(const PeerIdentity &identity) const {
    const auto *peer = PeerAt(identity.peer_index);
    return peer != nullptr &&
           m_peers.m_active_peer_index == static_cast<std::int32_t>(identity.peer_index.Value()) &&
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
    if (m_peers.m_active_peer_index < 0) {
        return false;
    }
    const auto peer_index = PeerIndex{
        static_cast<std::uint32_t>(m_peers.m_active_peer_index)};
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
    if (m_peers.m_active_peer_index < 0) {
        return false;
    }
    const auto peer_index = PeerIndex{
        static_cast<std::uint32_t>(m_peers.m_active_peer_index)};
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
    if (m_peers.m_active_peer_index < 0) {
        return false;
    }
    const auto peer_index = PeerIndex{
        static_cast<std::uint32_t>(m_peers.m_active_peer_index)};
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
    const auto *protocol_peer = peer->ProtocolPeer();
    const wgnx::wireguard::TimerOwner owner{
        .peer_index = effect.peer.peer_index.Value(),
        .activation_generation = effect.peer.activation_generation.Value(),
        .protocol_sequence =
            effect.hook == wgnx::wireguard::TimerHook::RetransmitHandshake &&
                    protocol_peer != nullptr
                ? protocol_peer->handshake_retry.sequence_count
                : 0,
    };
    return peer->IsTimerCurrent(effect.token, owner);
}

std::size_t RuntimeCoordinator::ClearStagedInnerPackets(PeerIndex peer_index) {
    auto *peer = MutablePeerAt(peer_index);
    return peer != nullptr ? peer->ClearStagedInnerPackets() : 0;
}

std::size_t RuntimeCoordinator::ClearAllStagedInnerPackets() {
    std::size_t cleared = 0;
    for (std::size_t index = 0; index < m_peers.m_count; ++index) {
        cleared += m_peers.m_peers[index].ClearStagedInnerPackets();
    }
    return cleared;
}

} // namespace wgnx::sysmodule::runtime
