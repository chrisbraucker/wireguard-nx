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
#include <utility>

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
    ActivationGeneration activation_generation{};
    wgnx::platform::ktime_t state_changed_ns{0};
    wgnx::platform::ktime_t last_handshake_ns{0};
    wgnx::platform::ktime_t last_rx_ns{0};
    wgnx::platform::ktime_t last_tx_ns{0};
    std::uint64_t rx_bytes{0};
    std::uint64_t tx_bytes{0};
    bool established{false};
};

struct PeerProtocolInfo {
    wgnx::wireguard::wg_device device{};
    bool instantiated{false};
};

struct PeerProtocolSnapshot {
    std::uint32_t current_keypair_index{0};
    std::uint32_t previous_keypair_index{0};
    bool instantiated{false};
    bool current_keypair_valid{false};
    bool next_keypair_valid{false};
    bool previous_keypair_valid{false};
};

constexpr inline std::size_t MaxEncryptedDatagramSize =
    wgnx::wireguard::TransportDataHeaderSize +
    wgnx::wireguard::GetPaddedTransportPayloadSize(wgnx::wireguard::MaxInnerIpPacketSize) +
    wgnx::wireguard::NoiseMacSize;

enum class PendingDatagramKind : std::uint8_t {
    None = 0,
    HandshakeInitiation,
    HandshakeResponse,
    TransportData,
    Keepalive,
};

constexpr const char *GetPendingDatagramKindName(PendingDatagramKind kind) {
    switch (kind) {
        case PendingDatagramKind::None: return "none";
        case PendingDatagramKind::HandshakeInitiation: return "handshake_initiation";
        case PendingDatagramKind::HandshakeResponse: return "handshake_response";
        case PendingDatagramKind::TransportData: return "transport_data";
        case PendingDatagramKind::Keepalive: return "keepalive";
    }
    return "unknown";
}

struct PendingDatagram {
    std::array<std::uint8_t, MaxEncryptedDatagramSize> bytes{};
    std::size_t size{0};
    DatagramGeneration generation{};
    PacketId inner_packet_id{};
    PendingDatagramKind kind{PendingDatagramKind::None};

    bool IsPending() const { return kind != PendingDatagramKind::None; }
};

struct PendingDatagramSnapshot {
    std::array<std::uint8_t, MaxEncryptedDatagramSize> bytes{};
    std::size_t size{0};
    PacketId inner_packet_id{};
    PendingDatagramKind kind{PendingDatagramKind::None};
    UdpBinding::SendSnapshot binding{};
};

struct DecryptedPacketView {
    std::span<const std::uint8_t> packet{};
    PacketGeneration generation{};
};

constexpr inline std::size_t MaxDecryptedPayloadSize =
    wgnx::wireguard::GetPaddedTransportPayloadSize(
        wgnx::wireguard::MaxInnerIpPacketSize);

struct DecryptedPacketSlot {
    std::array<std::uint8_t, MaxDecryptedPayloadSize> bytes{};
    std::size_t size{0};
    PacketGeneration generation{};
};

class RuntimeCoordinator;

class PeerRuntime {
public:
    const PeerRuntimeInfo &Lifecycle() const { return m_lifecycle; }
    const wgnx::PeerConfigEntry &Configuration() const { return m_config; }
    UdpBinding::Snapshot BindingSnapshot() const { return m_binding.StateSnapshot(); }
    PeerProtocolSnapshot ProtocolSnapshot() const;
    bool IsCurrentActivation(ActivationGeneration activation_generation) const;
    bool IsInTransportState() const;
    bool AcceptsInnerPacketSubmission() const;
    bool CanSendTransportNow() const;
    bool IsTimerCurrent(
        const wgnx::wireguard::TimerToken &token,
        const wgnx::wireguard::TimerOwner &owner) const;
    wgnx::PeerInfo BuildInfo(
        wgnx::platform::ktime_t now,
        bool is_active,
        bool is_auto_start) const;
    bool SnapshotPendingDatagram(
        ActivationGeneration activation_generation,
        DatagramGeneration datagram_generation,
        PendingDatagramSnapshot &out) const;
    bool ViewDecryptedPacket(
        ActivationGeneration activation_generation,
        PacketGeneration packet_generation,
        DecryptedPacketView &out) const;
    bool CanStageInnerPacket() const;
    std::size_t StagedInnerPacketCount() const;

private:
    friend class RuntimeCoordinator;

    void Configure(
        PeerIndex peer_index,
        const wgnx::PeerConfigEntry &config,
        PeerConfigDerivedInfo derived,
        wgnx::platform::ktime_t now);
    void Deactivate(wgnx::platform::ktime_t now);
    ActivationGeneration BeginActivation(wgnx::platform::ktime_t now);
    bool EnterHandshaking(ActivationGeneration activation_generation, wgnx::platform::ktime_t now);
    bool EnterActive(ActivationGeneration activation_generation, wgnx::platform::ktime_t now);
    void EnterError(
        wgnx::PeerErrorStage stage,
        wgnx::PeerErrorCode code,
        wgnx::platform::ktime_t now);
    void RecordReceivedBytes(std::size_t byte_count, wgnx::platform::ktime_t now);
    void RecordTransmittedBytes(std::size_t byte_count, wgnx::platform::ktime_t now);
    EffectBatch Handle(const PeerEvent &event);
    std::size_t ClearStagedInnerPackets();
    void ResetLifecycle(
        wgnx::PeerRuntimeState state,
        ActivationGeneration activation_generation,
        wgnx::platform::ktime_t now);
    wgnx::PeerErrorCode ValidateConfiguration() const;
    bool InstantiateProtocol();
    void ResetProtocol();
    wgnx::wireguard::wg_peer *ProtocolPeer();
    const wgnx::wireguard::wg_peer *ProtocolPeer() const;
    bool PrepareHandshakeInitiation(PendingDatagramKind kind);
    bool PrepareHandshakeResponse();
    bool PrepareTransportDatagram(
        std::span<const std::uint8_t> payload,
        PendingDatagramKind kind,
        PacketId inner_packet_id,
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
    void HandleEncryptedDatagram(
        const EncryptedDatagramReceivedEvent &event,
        EffectBatch &effects);
    void CompleteInitiatorSession(
        const EncryptedDatagramReceivedEvent &event,
        EffectBatch &effects);
    void HandleTransportData(
        const EncryptedDatagramReceivedEvent &event,
        EffectBatch &effects);
    void UpdateEndpointFromAuthenticatedPacket(
        const EncryptedDatagramReceivedEvent &event);
    SocketGeneration AllocateSocketGeneration();
    DatagramGeneration AllocateDatagramGeneration();
    PacketGeneration AllocateDecryptedPacketGeneration();
    void EnterActivationError(
        wgnx::PeerErrorStage stage,
        wgnx::PeerErrorCode code,
        wgnx::platform::ktime_t now,
        EffectBatch *effects);
    void FinalizeTimerEffects(EffectBatch &effects);
    void SuspendTransport(const PeerIdentity &identity, EffectBatch &effects);
    void RecoverTransport(
        const PeerIdentity &identity,
        wgnx::wireguard::TimerDeadline retry_deadline,
        wgnx::platform::ktime_t now,
        EffectBatch &effects);

    wgnx::PeerConfigEntry m_config{};
    PeerConfigDerivedInfo m_derived{};
    UdpBinding m_binding{};
    PeerProtocolInfo m_protocol{};
    wgnx::wireguard::PeerController m_controller{};
    PeerRuntimeInfo m_lifecycle{};
    ActivationGeneration m_next_activation_generation{1};
    SocketGeneration m_next_socket_generation{1};
    SocketGeneration m_pending_socket_generation{};
    UdpBindPurpose m_pending_bind_purpose{UdpBindPurpose::Activation};
    DatagramGeneration m_next_datagram_generation{1};
    PendingDatagram m_pending_datagram{};
    wgnx::wireguard::InnerPacketRecord m_staging_record{};
    DecryptedPacketSlot m_decrypted_packet{};
    PacketGeneration m_next_decrypted_packet_generation{1};
    PeerIndex m_peer_index{};
};

class PeerRegistry {
public:
    constexpr std::uint32_t Count() const { return m_count; }
    constexpr bool Empty() const { return m_count == 0; }

    constexpr bool IsValidSelection(std::int32_t peer_index) const {
        return IsValidPeerSelection(peer_index, m_count);
    }

    constexpr std::int32_t ActivePeerIndex() const { return m_active_peer_index; }
    constexpr std::int32_t AutoStartPeerIndex() const { return m_auto_start_peer_index; }

private:
    friend class RuntimeCoordinator;

    std::array<PeerRuntime, wgnx::MaxPeers> m_peers{};
    std::uint32_t m_count{0};
    std::int32_t m_active_peer_index{-1};
    std::int32_t m_auto_start_peer_index{-1};
};

} // namespace wgnx::sysmodule::runtime
