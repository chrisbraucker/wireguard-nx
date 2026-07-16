#pragma once

#include "runtime/runtime_contracts.hpp"
#include "runtime/runtime_events.hpp"
#include "runtime/udp_binding.hpp"

#include "wgnx/config.hpp"
#include "wgnx/platform/clock.hpp"
#include "wireguard/crypto/primitives.hpp"
#include "wireguard/device.hpp"
#include "wireguard/data.hpp"
#include "wireguard/peer_controller.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace wgnx::sysmodule::runtime {

struct PeerConfigDerivedInfo {
    char derived_public_key[64]{};
    wgnx::wireguard::noise_private_key local_private_key{};
    wgnx::wireguard::noise_symmetric_key preshared_key{};
    bool has_derived_public_key{false};
    bool has_preshared_key{false};
    bool secrets_valid{false};
};

struct PeerRuntimeInfo {
    wgnx::PeerRuntimeState state{wgnx::PeerRuntimeState::Inactive};
    wgnx::PeerErrorStage error_stage{wgnx::PeerErrorStage::None};
    std::uint32_t last_error_code{0};
    std::uint16_t persistent_keepalive_interval{0};
    std::uint32_t state_ticks{0};
    std::uint32_t activation_generation{0};
    wgnx::platform::ktime_t state_changed_ns{0};
    wgnx::platform::ktime_t last_handshake_ns{0};
    wgnx::platform::ktime_t last_rx_ns{0};
    wgnx::platform::ktime_t last_tx_ns{0};
    wgnx::platform::ktime_t debug_probe_state_changed_ns{0};
    std::uint64_t rx_bytes{0};
    std::uint64_t tx_bytes{0};
    wgnx::DebugTriggerAction debug_probe_action{wgnx::DebugTriggerAction::None};
    wgnx::DebugProbeStatus debug_probe_status{wgnx::DebugProbeStatus::None};
    bool established{false};
};

struct PeerProtocolInfo {
    wgnx::wireguard::wg_device device{};
    bool instantiated{false};
};

constexpr inline std::size_t MaxEncryptedDatagramSize =
    wgnx::wireguard::TransportDataHeaderSize +
    wgnx::wireguard::GetPaddedTransportPayloadSize(wgnx::MaxInnerIpv4PacketSize) +
    wgnx::wireguard::NoiseMacSize;

enum class PendingDatagramKind : std::uint8_t {
    None = 0,
    HandshakeInitiation,
    TransportData,
    Keepalive,
};

constexpr const char *GetPendingDatagramKindName(PendingDatagramKind kind) {
    switch (kind) {
        case PendingDatagramKind::None: return "none";
        case PendingDatagramKind::HandshakeInitiation: return "handshake_initiation";
        case PendingDatagramKind::TransportData: return "transport_data";
        case PendingDatagramKind::Keepalive: return "keepalive";
    }
    return "unknown";
}

struct PendingDatagram {
    std::array<std::uint8_t, MaxEncryptedDatagramSize> bytes{};
    std::size_t size{0};
    std::uint32_t generation{0};
    std::uint64_t inner_packet_id{0};
    PendingDatagramKind kind{PendingDatagramKind::None};

    bool IsPending() const { return kind != PendingDatagramKind::None; }
};

struct PendingDatagramSnapshot {
    std::array<std::uint8_t, MaxEncryptedDatagramSize> bytes{};
    std::size_t size{0};
    std::uint64_t inner_packet_id{0};
    PendingDatagramKind kind{PendingDatagramKind::None};
    UdpBinding::SendSnapshot binding{};
};

class PeerRuntime {
public:
    void SetPeerIndex(std::uint32_t peer_index) { m_peer_index = peer_index; }
    const PeerRuntimeInfo &Lifecycle() const { return m_lifecycle; }

    void Deactivate(wgnx::platform::ktime_t now);
    std::uint32_t BeginActivation(wgnx::platform::ktime_t now);
    bool EnterHandshaking(std::uint32_t activation_generation, wgnx::platform::ktime_t now);
    bool EnterActive(std::uint32_t activation_generation, wgnx::platform::ktime_t now);
    void EnterError(
        wgnx::PeerErrorStage stage,
        wgnx::PeerErrorCode code,
        wgnx::platform::ktime_t now);

    bool IsCurrentActivation(std::uint32_t activation_generation) const;
    bool IsInTransportState() const;
    bool AcceptsInnerPacketSubmission() const;

    void RecordReceivedBytes(std::size_t byte_count, wgnx::platform::ktime_t now);
    void RecordTransmittedBytes(std::size_t byte_count, wgnx::platform::ktime_t now);
    bool SetDebugProbeState(
        wgnx::DebugTriggerAction action,
        wgnx::DebugProbeStatus status,
        wgnx::platform::ktime_t now);
    void ClearDebugProbeState();

    wgnx::PeerInfo BuildInfo(
        wgnx::platform::ktime_t now,
        bool is_active,
        bool is_auto_start) const;
    EffectBatch Handle(const PeerEvent &event);
    bool SnapshotPendingDatagram(
        std::uint32_t activation_generation,
        std::uint32_t datagram_generation,
        PendingDatagramSnapshot &out) const;
    bool CanStageInnerPacket() const;
    std::size_t ClearStagedInnerPackets();
    std::size_t StagedInnerPacketCount() const;

    wgnx::PeerConfigEntry config{};
    PeerConfigDerivedInfo derived{};
    UdpBinding binding{};
    PeerProtocolInfo protocol{};
    wgnx::wireguard::PeerController controller{};

private:
    void ResetLifecycle(
        wgnx::PeerRuntimeState state,
        std::uint32_t activation_generation,
        wgnx::platform::ktime_t now);
    wgnx::PeerErrorCode ValidateConfiguration() const;
    bool InstantiateProtocol();
    void ResetProtocol();
    wgnx::wireguard::wg_peer *ProtocolPeer();
    const wgnx::wireguard::wg_peer *ProtocolPeer() const;
    bool PrepareHandshakeInitiation(PendingDatagramKind kind);
    bool PrepareTransportDatagram(
        std::span<const std::uint8_t> payload,
        PendingDatagramKind kind,
        std::uint64_t inner_packet_id,
        wgnx::wireguard::TransportDataError &out_error);
    bool StartHandshake(
        const PeerIdentity &identity,
        wgnx::wireguard::TimerDeadline retry_deadline,
        EffectBatch &effects,
        bool retry);
    void ProcessOutboundQueue(
        const PeerIdentity &identity,
        wgnx::wireguard::TimerDeadline retry_deadline,
        wgnx::platform::ktime_t now,
        EffectBatch &effects);
    void HandlePendingDatagramCompletion(
        const PendingDatagramSentEvent &event,
        EffectBatch &effects);
    std::uint32_t AllocateSocketGeneration();
    std::uint32_t AllocateDatagramGeneration();
    void EnterActivationError(
        wgnx::PeerErrorStage stage,
        wgnx::PeerErrorCode code,
        wgnx::platform::ktime_t now,
        EffectBatch *effects);

    PeerRuntimeInfo m_lifecycle{};
    std::uint32_t m_next_activation_generation{1};
    std::uint32_t m_next_socket_generation{1};
    std::uint32_t m_next_datagram_generation{1};
    PendingDatagram m_pending_datagram{};
    wgnx::wireguard::InnerPacketRecord m_staging_record{};
    std::uint32_t m_peer_index{0};
};

class PeerRegistry {
public:
    constexpr std::uint32_t Count() const { return m_count; }
    constexpr bool Empty() const { return m_count == 0; }

    bool Assign(std::span<const wgnx::PeerConfigEntry> configured_peers) {
        if (configured_peers.size() > m_peers.size()) {
            return false;
        }

        m_count = static_cast<std::uint32_t>(configured_peers.size());
        for (std::size_t index = 0; index < configured_peers.size(); ++index) {
            m_peers[index].SetPeerIndex(static_cast<std::uint32_t>(index));
            m_peers[index].config = configured_peers[index];
        }
        m_active_peer_index = -1;
        m_auto_start_peer_index = -1;
        return true;
    }

    void ClearConfiguration() {
        m_count = 0;
        m_active_peer_index = -1;
        m_auto_start_peer_index = -1;
    }

    constexpr bool IsValidSelection(std::int32_t peer_index) const {
        return IsValidPeerSelection(peer_index, m_count);
    }

    constexpr PeerRuntime &operator[](std::size_t peer_index) {
        return m_peers[peer_index];
    }

    constexpr const PeerRuntime &operator[](std::size_t peer_index) const {
        return m_peers[peer_index];
    }

    constexpr std::int32_t ActivePeerIndex() const { return m_active_peer_index; }
    constexpr std::int32_t AutoStartPeerIndex() const { return m_auto_start_peer_index; }

    bool SetActivePeerIndex(std::int32_t peer_index) {
        if (!IsValidSelection(peer_index)) {
            return false;
        }
        m_active_peer_index = peer_index;
        return true;
    }

    bool SetAutoStartPeerIndex(std::int32_t peer_index) {
        if (!IsValidSelection(peer_index)) {
            return false;
        }
        m_auto_start_peer_index = peer_index;
        return true;
    }

private:
    std::array<PeerRuntime, wgnx::MaxPeers> m_peers{};
    std::uint32_t m_count{0};
    std::int32_t m_active_peer_index{-1};
    std::int32_t m_auto_start_peer_index{-1};
};

} // namespace wgnx::sysmodule::runtime
