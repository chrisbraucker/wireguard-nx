#pragma once

#include "runtime/domain_types.hpp"
#include "runtime/runtime_events.hpp"
#include "wgnx/config.hpp"
#include "wgnx/platform/clock.hpp"
#include "wgnx/tunnel_protocol.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace wgnx::sysmodule::runtime {

struct TunnelClientId {
    std::uint8_t slot{0xFF};
    std::uint32_t generation{0};

    [[nodiscard]] constexpr bool IsValid() const {
        return slot < wgnx::tunnel::MaximumClientContexts && generation != 0;
    }

    friend constexpr bool operator==(TunnelClientId, TunnelClientId) = default;
};

struct TunnelPolicyInput {
    const wgnx::PeerConfigEntry* configuration{nullptr};
    PeerIdentity peer{};
    bool selected{false};
};

struct TunnelTransportAvailability {
    bool protocol_available{false};
    bool staging_available{false};
};

enum class TunnelInboundDisposition : std::uint8_t {
    NotClaimed = 0,
    Delivered,
    DroppedMalformed,
    DroppedUnknown,
    DroppedStale,
    DroppedQueueFull,
};

struct TunnelInboundOutcome {
    TunnelInboundDisposition disposition{TunnelInboundDisposition::NotClaimed};
    std::size_t payload_size{0};
    TunnelClientId client{};
    wgnx::tunnel::FlowHandle flow{};
};

struct PreparedTunnelDatagram {
    wgnx::tunnel::ProtocolStatus status{wgnx::tunnel::ProtocolStatus::MalformedInput};
    PeerIdentity peer{};
    std::span<const std::uint8_t> packet{};
    std::uint8_t slab_slot{0xFF};
    wgnx::tunnel::FlowHandle flow{};

    [[nodiscard]] constexpr bool HasPacket() const {
        return slab_slot != 0xFF && !packet.empty();
    }
};

struct TunnelCompletionDrainOutcome {
    wgnx::tunnel::ProtocolStatus status{wgnx::tunnel::ProtocolStatus::QueueEmpty};
    std::uint32_t count{0};
};

class TunnelFlowPlane {
  public:
    using CompletionNotifier = void (*)(void* context);

    static constexpr wgnx::platform::ktime_t ReverseTupleQuarantineNs = 60 * wgnx::platform::NSEC_PER_SEC;

    [[nodiscard]] TunnelClientId CreateClient(CompletionNotifier notifier, void* notifier_context);
    void DestroyClient(TunnelClientId client, wgnx::platform::ktime_t now);

    void RefreshPolicy(const TunnelPolicyInput& input, wgnx::platform::ktime_t now);
    [[nodiscard]] wgnx::tunnel::Capabilities GetCapabilities() const;
    [[nodiscard]] wgnx::tunnel::RoutingPolicySnapshot CopyRoutingPolicy(std::span<wgnx::tunnel::RouteRecord> out) const;

    [[nodiscard]] wgnx::tunnel::OpenConnectedUdpFlowResult OpenConnectedUdpFlow(
        TunnelClientId client,
        const wgnx::tunnel::OpenConnectedUdpFlowRequest& request,
        wgnx::platform::ktime_t now,
        TunnelTransportAvailability availability = {
            .protocol_available = true,
            .staging_available = true,
        }
    );
    [[nodiscard]] PreparedTunnelDatagram PrepareSend(
        TunnelClientId client,
        const wgnx::tunnel::DatagramDescriptor& descriptor,
        std::span<const std::uint8_t> payload,
        TunnelTransportAvailability availability,
        wgnx::platform::ktime_t now
    );
    void CompleteSend(const PreparedTunnelDatagram& datagram, wgnx::tunnel::ProtocolStatus completion_status);
    void ReleasePreparedDatagram(const PreparedTunnelDatagram& datagram);
    void NotifyOutboundCapacityAvailable(const PeerIdentity& peer);
    [[nodiscard]] std::uint32_t SignalAllClientCompletionEvents() const;

    [[nodiscard]] TunnelCompletionDrainOutcome ReceiveCompletions(
        TunnelClientId client, std::span<wgnx::tunnel::CompletionRecord> records, std::span<std::uint8_t> payload
    );
    [[nodiscard]] bool HasCompletions(TunnelClientId client) const;
    [[nodiscard]] wgnx::tunnel::FlowStateResult GetFlowState(TunnelClientId client, wgnx::tunnel::FlowHandle flow) const;
    [[nodiscard]] wgnx::tunnel::ProtocolStatus CloseFlow(TunnelClientId client, wgnx::tunnel::FlowHandle flow, wgnx::platform::ktime_t now);

    [[nodiscard]] TunnelInboundOutcome DeliverDecryptedIpv4Packet(
        const PeerIdentity& peer, std::span<const std::uint8_t> packet, wgnx::platform::ktime_t now
    );
    void InvalidatePeerActivation(const PeerIdentity& peer, wgnx::tunnel::FlowTerminalReason reason, wgnx::platform::ktime_t now);

  private:
    static constexpr std::size_t DataCompletionCapacity =
        wgnx::tunnel::CompletionQueueCapacity - (1 + (2 * wgnx::tunnel::MaximumFlowsPerClient));

    struct NormalizedRoute {
        std::array<std::uint8_t, 4> network{};
        std::uint8_t prefix_length{0};
        std::uint64_t route_identifier{0};

        friend constexpr bool operator==(const NormalizedRoute&, const NormalizedRoute&) = default;
    };

    struct OutboundSlab {
        std::array<std::uint8_t, wgnx::MaxInnerIpv4PacketSize> bytes{};
        bool allocated{false};
    };

    struct InboundSlab {
        std::array<std::uint8_t, wgnx::tunnel::MaximumUdpPayloadStorageBytes> bytes{};
        std::uint16_t size{0};
        bool allocated{false};
    };

    struct CompletionEntry {
        wgnx::tunnel::CompletionRecord record{};
        std::uint8_t inbound_slab_slot{0xFF};
    };

    struct FlowSlot {
        bool allocated{false};
        bool closed{false};
        std::uint8_t client_slot{0xFF};
        std::uint32_t client_generation{0};
        std::uint32_t allocation_generation{0};
        PeerIdentity peer{};
        std::uint32_t policy_generation{0};
        wgnx::tunnel::Ipv4Endpoint remote{};
        std::array<std::uint8_t, 4> tunnel_source{};
        std::uint16_t virtual_source_port{0};
        std::uint16_t inbound_occupancy{0};
        wgnx::platform::ktime_t created_at{0};
        wgnx::platform::ktime_t last_activity_at{0};
        std::uint64_t diagnostic_tag{0};
        wgnx::tunnel::FlowTerminalReason terminal_reason{wgnx::tunnel::FlowTerminalReason::None};
        bool writable_waiter{false};
        std::uint64_t send_attempts{};
        std::uint64_t send_admitted{};
        std::uint64_t send_queue_full{};
        std::uint64_t inbound_delivered{};
        std::uint64_t inbound_dropped{};
    };

    struct ClientSlot {
        bool allocated{false};
        std::uint32_t generation{0};
        CompletionNotifier notifier{nullptr};
        void* notifier_context{nullptr};
        std::array<CompletionEntry, wgnx::tunnel::CompletionQueueCapacity> completions{};
        std::uint8_t completion_head{0};
        std::uint8_t completion_count{0};
        std::uint8_t data_completion_count{0};
    };

    struct ReverseTupleTombstone {
        bool occupied{false};
        std::array<std::uint8_t, 4> tunnel_destination{};
        std::uint16_t tunnel_destination_port{0};
        wgnx::tunnel::Ipv4Endpoint remote{};
        wgnx::platform::ktime_t expires_at{0};
    };

    [[nodiscard]] ClientSlot* FindClient(TunnelClientId client);
    [[nodiscard]] const ClientSlot* FindClient(TunnelClientId client) const;
    [[nodiscard]] FlowSlot* FindFlow(TunnelClientId client, wgnx::tunnel::FlowHandle flow);
    [[nodiscard]] const FlowSlot* FindFlow(TunnelClientId client, wgnx::tunnel::FlowHandle flow) const;
    [[nodiscard]] wgnx::tunnel::FlowHandle MakeFlowHandle(std::size_t flow_slot, const FlowSlot& flow) const;
    [[nodiscard]] bool DecodeFlowHandle(
        wgnx::tunnel::FlowHandle handle,
        std::size_t* out_slot,
        std::uint32_t* out_generation,
        std::uint8_t* out_client_slot,
        std::uint32_t* out_client_generation
    ) const;

    void ClearExpiredTombstones(wgnx::platform::ktime_t now);
    [[nodiscard]] bool HasTombstoneReservation(wgnx::platform::ktime_t now);
    [[nodiscard]] std::uint32_t AllocateFlowGeneration();
    [[nodiscard]] bool AllocateVirtualTuple(const wgnx::tunnel::Ipv4Endpoint& remote, std::uint16_t* out_port, wgnx::platform::ktime_t now);
    void QuarantineTuple(const FlowSlot& flow, wgnx::platform::ktime_t now);
    [[nodiscard]] bool IsTombstoned(
        const std::array<std::uint8_t, 4>& tunnel_destination,
        std::uint16_t tunnel_destination_port,
        const wgnx::tunnel::Ipv4Endpoint& remote,
        wgnx::platform::ktime_t now
    ) const;

    [[nodiscard]] std::uint8_t AllocateOutboundSlab();
    [[nodiscard]] std::uint8_t AllocateInboundSlab();
    void ReleaseInboundSlab(std::uint8_t slot);
    void RemoveFlowCompletions(std::size_t flow_slot, ClientSlot& client);
    void CloseFlowSlot(std::size_t flow_slot, wgnx::tunnel::FlowTerminalReason reason, wgnx::platform::ktime_t now, bool notify);

    [[nodiscard]] bool EnqueueDataCompletion(std::size_t flow_slot, std::uint8_t inbound_slab_slot);
    void EnqueueControlCompletion(TunnelClientId client, const wgnx::tunnel::CompletionRecord& completion);
    void EnqueuePolicyChanged();
    void NotifyIfNeeded(ClientSlot& client, bool was_empty);
    [[nodiscard]] bool RemoveCompletionFront(ClientSlot& client, CompletionEntry* out);
    [[nodiscard]] CompletionEntry* CompletionAt(ClientSlot& client, std::size_t index);
    [[nodiscard]] const CompletionEntry* CompletionAt(const ClientSlot& client, std::size_t index) const;

    [[nodiscard]] bool ParseAndNormalizePolicy(const TunnelPolicyInput& input);
    [[nodiscard]] static bool ParseIpv4Cidr(const char* text, std::array<std::uint8_t, 4>* out_address, std::uint8_t* out_prefix);
    [[nodiscard]] static bool ParseIpv4Endpoint(
        std::span<const std::uint8_t> packet,
        std::size_t ipv4_header_size,
        wgnx::tunnel::Ipv4Endpoint* out_source,
        std::array<std::uint8_t, 4>* out_destination,
        std::uint16_t* out_destination_port,
        std::span<const std::uint8_t>* out_payload
    );
    [[nodiscard]] static bool RouteMatches(const NormalizedRoute& route, const std::uint8_t address[4]);
    [[nodiscard]] const NormalizedRoute* SelectRoute(const wgnx::tunnel::Ipv4Endpoint& remote) const;
    [[nodiscard]] static std::uint16_t ComputeInternetChecksum(std::span<const std::uint8_t> bytes);
    [[nodiscard]] static std::uint16_t ComputeUdpChecksum(
        const std::uint8_t source[4], const std::uint8_t destination[4], std::span<const std::uint8_t> udp
    );
    [[nodiscard]] bool BuildUdpPacket(FlowSlot& flow, std::span<const std::uint8_t> payload, OutboundSlab& out, std::size_t* out_size);

    std::array<ClientSlot, wgnx::tunnel::MaximumClientContexts> m_clients{};
    std::array<FlowSlot, wgnx::tunnel::MaximumFlows> m_flows{};
    std::array<OutboundSlab, wgnx::tunnel::OutboundPacketSlabCount> m_outbound_slabs{};
    std::array<InboundSlab, wgnx::tunnel::InboundPacketSlabCount> m_inbound_slabs{};
    std::array<ReverseTupleTombstone, wgnx::tunnel::ReverseTupleQuarantineCapacity> m_tombstones{};
    std::array<NormalizedRoute, wgnx::tunnel::MaximumPolicyRoutes> m_routes{};
    std::array<std::uint8_t, 4> m_tunnel_source{};
    PeerIdentity m_policy_peer{};
    std::uint32_t m_policy_generation{1};
    std::uint32_t m_next_policy_generation{2};
    std::uint32_t m_route_count{0};
    std::uint32_t m_next_client_generation{1};
    std::uint32_t m_next_flow_generation{1};
    std::uint16_t m_next_virtual_source_port{49152};
    std::uint16_t m_next_ipv4_identification{1};
    std::uint16_t m_effective_inner_mtu{wgnx::tunnel::DefaultEffectiveInnerMtu};
    bool m_policy_available{false};
    bool m_policy_leak_protection{false};
};

} // namespace wgnx::sysmodule::runtime
