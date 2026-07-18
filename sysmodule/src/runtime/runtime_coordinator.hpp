#pragma once

#include "runtime/peer_runtime.hpp"
#include "runtime/runtime_events.hpp"

namespace wgnx::sysmodule::runtime {

struct PeerPacketStateSnapshot {
    PeerIdentity identity{};
    wgnx::PeerRuntimeState state{wgnx::PeerRuntimeState::Inactive};
    std::size_t staged_packet_count{0};
    bool protocol_instantiated{false};
    bool can_stage_packet{false};
};

struct ReceiveRuntimeSnapshot {
    PeerIdentity peer{};
    wgnx::platform::socket_handle socket{wgnx::platform::InvalidSocket};
    SocketGeneration socket_generation{};
};

struct DebugPeerSnapshot {
    PeerIdentity peer{};
    std::array<char, sizeof(wgnx::PeerConfigEntry::address)> source_address{};
};

class RuntimeCoordinator {
public:
    explicit constexpr RuntimeCoordinator(PeerRegistry &peers) : m_peers(peers) {}

    [[nodiscard]] bool Configure(
        std::span<const wgnx::PeerConfigEntry> configured_peers,
        std::span<PeerConfigDerivedInfo> derived,
        std::int32_t auto_start_peer_index,
        wgnx::platform::ktime_t now);
    [[nodiscard]] EffectBatch ClearConfiguration(wgnx::platform::ktime_t now);
    [[nodiscard]] bool SetActivePeerIndex(std::int32_t peer_index);
    [[nodiscard]] bool SetAutoStartPeerIndex(std::int32_t peer_index);

    [[nodiscard]] EffectBatch Dispatch(const PeerEvent &event);

    std::uint32_t PeerCount() const { return m_peers.Count(); }
    bool Empty() const { return m_peers.Empty(); }
    bool IsValidSelection(std::int32_t peer_index) const;
    std::int32_t ActivePeerIndex() const { return m_peers.ActivePeerIndex(); }
    std::int32_t AutoStartPeerIndex() const { return m_peers.AutoStartPeerIndex(); }
    const PeerRuntimeInfo *Lifecycle(std::size_t peer_index) const;
    const wgnx::PeerConfigEntry *Configuration(std::size_t peer_index) const;
    UdpBinding::Snapshot BindingSnapshot(std::size_t peer_index) const;
    PeerProtocolSnapshot ProtocolSnapshot(std::size_t peer_index) const;
    wgnx::PeerInfo BuildPeerInfo(
        std::size_t peer_index,
        wgnx::platform::ktime_t now) const;
    bool HasRuntimeErrors() const;
    bool IsActiveIdentity(const PeerIdentity &peer) const;
    bool IsActiveTransportIdentity(const PeerIdentity &peer) const;
    bool IsActiveEstablishedIdentity(const PeerIdentity &peer) const;
    [[nodiscard]] bool SnapshotReceiveRuntime(ReceiveRuntimeSnapshot &out) const;
    [[nodiscard]] bool SnapshotDebugPeer(DebugPeerSnapshot &out) const;
    [[nodiscard]] bool SnapshotPacketState(PeerPacketStateSnapshot &out) const;
    [[nodiscard]] bool SnapshotPendingDatagram(
        const PeerIdentity &peer,
        DatagramGeneration datagram_generation,
        PendingDatagramSnapshot &out) const;
    [[nodiscard]] bool ViewDecryptedPacket(
        const PeerIdentity &peer,
        PacketGeneration packet_generation,
        DecryptedPacketView &out) const;
    bool IsCurrentTimerEffect(const ArmProtocolTimerEffect &effect) const;
    std::size_t ClearStagedInnerPackets(PeerIndex peer_index);
    std::size_t ClearAllStagedInnerPackets();

private:
    const PeerRuntime *PeerAt(PeerIndex peer_index) const;

    PeerRegistry &m_peers;
};

} // namespace wgnx::sysmodule::runtime
