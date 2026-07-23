#pragma once

#include "runtime/runtime_contracts.hpp"
#include "runtime/runtime_events.hpp"
#include "runtime/udp_binding.hpp"
#include "wgnx/resource_budget.hpp"

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

class PeerRuntime {
public:
    const PeerRuntimeInfo &Lifecycle() const { return m_lifecycle; }
    const wgnx::PeerConfigEntry &Configuration() const { return m_config; }
    UdpBinding::Snapshot BindingSnapshot() const { return m_binding.StateSnapshot(); }
    PeerProtocolSnapshot ProtocolSnapshot() const;
    bool IsCurrentActivation(ActivationGeneration activation_generation) const;
    bool IsCurrentPathRequest(
        ActivationGeneration activation_generation,
        PathRequestGeneration path_generation) const;
    bool IsInTransportState() const;
    bool AcceptsInnerPacketSubmission() const;
    bool CanSendTransportNow() const;
    bool IsTimerCurrent(
        const wgnx::wireguard::TimerToken &token,
        const wgnx::wireguard::TimerOwner &owner) const;
    wgnx::wireguard::TimerOwner CurrentTimerOwner(
        wgnx::wireguard::TimerHook hook) const;
    wgnx::PeerInfo BuildInfo(
        wgnx::platform::ktime_t now,
        bool is_active,
        bool is_auto_start) const;
    bool SnapshotPendingDatagram(
        ActivationGeneration activation_generation,
        DatagramGeneration datagram_generation,
        PendingDatagramSnapshot &out) const;
    bool HasPendingDatagram(
        ActivationGeneration activation_generation,
        DatagramGeneration datagram_generation) const;
    bool ViewDecryptedPacket(
        ActivationGeneration activation_generation,
        PacketGeneration packet_generation,
        DecryptedPacketView &out) const;
    bool CanStageInnerPacket() const;
    std::size_t StagedInnerPacketCount() const;

    // Closed owner transitions used by PeerRegistry. These mutate only
    // peer-owned state and return any platform work as explicit effects.
    void Configure(
        PeerIndex peer_index,
        const wgnx::PeerConfigEntry &config,
        PeerConfigDerivedInfo derived,
        wgnx::platform::ktime_t now);
    [[nodiscard]] wgnx::platform::socket_handle ClearConfiguration(
        wgnx::platform::ktime_t now);
    [[nodiscard]] EffectBatch Handle(const PeerEvent &event);
    std::size_t ClearStagedInnerPackets();

private:
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
        const TimerFacts &timer_facts,
        EffectBatch &effects,
        bool retry);
    void ProcessOutboundQueue(
        const PeerIdentity &identity,
        const TimerFacts &timer_facts,
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
    wgnx::wireguard::TimerDeadline HandshakeRetryDeadline(
        const TimerFacts &timer_facts) const;
    wgnx::wireguard::TimerDeadline KeepaliveDeadline(
        const TimerFacts &timer_facts) const;
    wgnx::wireguard::TimerDeadline NewHandshakeDeadline(
        const TimerFacts &timer_facts) const;
    wgnx::wireguard::TimerDeadline PersistentKeepaliveDeadline(
        const TimerFacts &timer_facts) const;
    wgnx::wireguard::TimerDeadline ZeroKeyMaterialDeadline(
        const TimerFacts &timer_facts) const;
    void OnAuthenticatedPacketTraversal(
        const PeerIdentity &identity,
        const TimerFacts &timer_facts,
        EffectBatch &effects);
    void OnAuthenticatedPacketSent(const PeerIdentity &identity, EffectBatch &effects);
    void OnAuthenticatedPacketReceived(const PeerIdentity &identity, EffectBatch &effects);
    void OnDataPacketSent(
        const PeerIdentity &identity,
        const TimerFacts &timer_facts,
        EffectBatch &effects);
    void OnDataPacketReceived(
        const PeerIdentity &identity,
        const TimerFacts &timer_facts,
        EffectBatch &effects);
    void OnSessionDerived(
        const PeerIdentity &identity,
        const TimerFacts &timer_facts,
        EffectBatch &effects);
    void OnHandshakeComplete(const PeerIdentity &identity, EffectBatch &effects);
    void SuspendTransport(const PeerIdentity &identity, EffectBatch &effects);
    void RecoverTransport(
        const PeerIdentity &identity,
        const TimerFacts &timer_facts,
        wgnx::platform::ktime_t now,
        EffectBatch &effects);
    [[nodiscard]] EffectBatch HandleEvent(const ActivationRequestedEvent &event);
    [[nodiscard]] EffectBatch HandleEvent(const DeactivationRequestedEvent &event);
    [[nodiscard]] EffectBatch HandleEvent(const NetworkPathRequestStartedEvent &event);
    [[nodiscard]] EffectBatch HandleEvent(
        const NetworkPathAvailabilityChangedEvent &event);
    [[nodiscard]] EffectBatch HandleEvent(const TransportFailureEvent &event);
    [[nodiscard]] EffectBatch HandleEvent(const EndpointResolvedEvent &event);
    [[nodiscard]] EffectBatch HandleEvent(const UdpBindOpenedEvent &event);
    [[nodiscard]] EffectBatch HandleEvent(const UdpRebindRequestedEvent &event);
    [[nodiscard]] EffectBatch HandleEvent(const EncryptedDatagramReceivedEvent &event);
    [[nodiscard]] EffectBatch HandleEvent(const PendingDatagramSentEvent &event);
    [[nodiscard]] EffectBatch HandleEvent(const InnerPacketStagedEvent &event);
    [[nodiscard]] EffectBatch HandleEvent(const ProcessOutboundQueueEvent &event);
    [[nodiscard]] EffectBatch HandleEvent(const ProtocolTimerExpiredEvent &event);

    wgnx::PeerConfigEntry m_config{};
    PeerConfigDerivedInfo m_derived{};
    UdpBinding m_binding{};
    PeerProtocolInfo m_protocol{};
    wgnx::wireguard::PeerController m_controller{};
    PeerRuntimeInfo m_lifecycle{};
    ActivationGeneration m_next_activation_generation{1};
    PathRequestGeneration m_next_path_request_generation{1};
    PathRequestGeneration m_path_request_generation{};
    wgnx::platform::network_path_availability m_path_availability{
        wgnx::platform::network_path_availability::unknown};
    wgnx::platform::network_path_observation m_last_path_observation{};
    bool m_has_path_observation{false};
    // An indeterminate NIFM observation cannot suspend a known-good binding,
    // but it can follow a local-path transition which invalidated it.
    bool m_rebind_on_path_confirmation{false};
    bool m_waiting_for_local_path{false};
    bool m_endpoint_resolution_started{false};
    bool m_receive_started{false};
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
    static constexpr std::size_t Capacity = wgnx::resource_budget::PeerSlots;

    constexpr std::uint32_t Count() const { return m_count; }
    constexpr bool Empty() const { return m_count == 0; }

    constexpr bool IsValidSelection(std::int32_t peer_index) const {
        return IsValidPeerSelection(peer_index, m_count);
    }

    constexpr std::int32_t ActivePeerIndex() const { return m_active_peer_index; }
    constexpr std::int32_t AutoStartPeerIndex() const { return m_auto_start_peer_index; }

    [[nodiscard]] bool Configure(
        std::span<const wgnx::PeerConfigEntry> configured_peers,
        std::span<PeerConfigDerivedInfo> derived,
        std::int32_t auto_start_peer_index,
        wgnx::platform::ktime_t now);
    [[nodiscard]] EffectBatch ClearConfiguration(wgnx::platform::ktime_t now);
    [[nodiscard]] bool SetActivePeerIndex(std::int32_t peer_index);
    [[nodiscard]] bool SetAutoStartPeerIndex(std::int32_t peer_index);

    [[nodiscard]] EffectBatch Dispatch(const PeerEvent &event);
    [[nodiscard]] const PeerRuntime *PeerAt(PeerIndex peer_index) const;
    [[nodiscard]] bool HasRuntimeErrors() const;
    std::size_t ClearStagedInnerPackets(PeerIndex peer_index);
    std::size_t ClearAllStagedInnerPackets();

private:
    std::array<PeerRuntime, wgnx::resource_budget::PeerSlots> m_peers{};
    std::uint32_t m_count{0};
    std::int32_t m_active_peer_index{-1};
    std::int32_t m_auto_start_peer_index{-1};
};

static_assert(
    sizeof(PeerRuntime) <= wgnx::resource_budget::MaximumPeerRuntimeBytes);
static_assert(
    sizeof(PeerRegistry) <= wgnx::resource_budget::MaximumPeerRegistryBytes);
static_assert(PeerRegistry::Capacity <= EffectBatch::Capacity);

} // namespace wgnx::sysmodule::runtime
