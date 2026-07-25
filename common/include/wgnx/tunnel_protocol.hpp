#pragma once

#include "wgnx/protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace wgnx::tunnel {

constexpr inline char ServiceName[] = "wgnx:tun";
constexpr inline std::uint32_t TunApiVersion = 1;

constexpr inline std::size_t MaximumClientContexts = 4;
constexpr inline std::size_t MaximumFlowsPerClient = 4;
constexpr inline std::size_t MaximumFlows = MaximumClientContexts * MaximumFlowsPerClient;
constexpr inline std::size_t MaximumUdpPayloadBytes = MaxInnerIpv4PacketSize - 20 - 8;
constexpr inline std::size_t OutboundPacketSlabCount = 16;
constexpr inline std::size_t InboundPacketSlabCount = 16;
constexpr inline std::size_t MaximumInboundDatagramsPerFlow = 4;
constexpr inline std::size_t CompletionQueueCapacity = 16;
constexpr inline std::size_t MaximumBatchEntries = 8;
constexpr inline std::size_t MaximumPolicyRoutes = 16;
constexpr inline std::size_t KernelHandlesPerClient = 1;
constexpr inline std::size_t ReverseTupleQuarantineCapacity = MaximumFlows;

enum class RootCommandId : std::uint32_t {
    GetTunApiVersion = 0,
    OpenTunnelClient = 1,
};

enum class ClientCommandId : std::uint32_t {
    GetCapabilities = 0,
    GetRoutingPolicySnapshot = 1,
    GetCompletionEvent = 2,
    OpenConnectedUdpFlow = 3,
    SendUdpDatagram = 4,
    SendUdpDatagramBatch = 5,
    ReceiveCompletions = 6,
    GetFlowState = 7,
    CloseFlow = 8,
};

enum class Capability : std::uint32_t {
    ConnectedIpv4Udp = 1U << 0,
    DatagramBatches = 1U << 1,
    CompletionEvent = 1U << 2,
    RoutingPolicySnapshot = 1U << 3,
    FlowStateQuery = 1U << 4,
};

constexpr std::uint32_t CapabilityMask(Capability capability) {
    return static_cast<std::uint32_t>(capability);
}

constexpr inline std::uint32_t SupportedCapabilityMask =
    CapabilityMask(Capability::ConnectedIpv4Udp) | CapabilityMask(Capability::DatagramBatches) |
    CapabilityMask(Capability::CompletionEvent) | CapabilityMask(Capability::RoutingPolicySnapshot) |
    CapabilityMask(Capability::FlowStateQuery);

enum class ProtocolStatus : std::uint32_t {
    Success = 0,
    MalformedInput = 1,
    UnsupportedOperation = 2,
    IncompatibleApiVersion = 3,
    RouteNotCovered = 4,
    PeerUnavailable = 5,
    TransportUnavailable = 6,
    FlowQuotaExhausted = 7,
    DatagramTooLarge = 8,
    QueueFull = 9,
    StaleHandle = 10,
    FlowClosed = 11,
    QueueEmpty = 12,
    OutputBufferTooSmall = 13,
    ReverseTupleExhausted = 14,
};

enum class FlowState : std::uint32_t {
    Open = 0,
    Suspended = 1,
    Closing = 2,
    Closed = 3,
};

enum class FlowTerminalReason : std::uint32_t {
    None = 0,
    ClientClosed = 1,
    PeerDeactivated = 2,
    PeerActivationChanged = 3,
    PolicyInvalidated = 4,
    SysmoduleShutdown = 5,
};

enum class CompletionType : std::uint32_t {
    InboundDatagram = 0,
    FlowStateChanged = 1,
    PolicyChanged = 2,
    Writable = 3,
};

struct FlowHandle {
    std::uint64_t value;
};

struct Ipv4Endpoint {
    std::uint8_t address[4];
    std::uint16_t port;
    std::uint16_t reserved;
};

struct Capabilities {
    std::uint32_t api_version;
    std::uint32_t capability_mask;
    std::uint32_t effective_inner_mtu;
    std::uint32_t maximum_udp_payload_bytes;
    std::uint32_t maximum_client_contexts;
    std::uint32_t maximum_flows_per_client;
    std::uint32_t maximum_flows;
    std::uint32_t outbound_packet_slab_count;
    std::uint32_t inbound_packet_slab_count;
    std::uint32_t maximum_inbound_datagrams_per_flow;
    std::uint32_t completion_queue_capacity;
    std::uint32_t maximum_batch_entries;
    std::uint32_t maximum_policy_routes;
    std::uint32_t kernel_handles_per_client;
    std::uint32_t reverse_tuple_quarantine_capacity;
    std::uint32_t reserved;
};

struct OpenConnectedUdpFlowRequest {
    Ipv4Endpoint remote;
    std::uint64_t diagnostic_tag;
};

struct OpenConnectedUdpFlowResult {
    ProtocolStatus status;
    FlowHandle flow;
    std::uint32_t peer_activation_generation;
    std::uint32_t routing_policy_generation;
};

struct DatagramDescriptor {
    FlowHandle flow;
    std::uint32_t payload_offset;
    std::uint32_t payload_size;
    std::uint64_t client_tag;
};

struct DatagramDisposition {
    std::uint64_t client_tag;
    ProtocolStatus status;
    std::uint32_t reserved;
};

struct CompletionRecord {
    CompletionType type;
    ProtocolStatus status;
    FlowHandle flow;
    Ipv4Endpoint remote;
    std::uint32_t payload_offset;
    std::uint32_t payload_size;
    std::uint32_t peer_activation_generation;
    std::uint32_t routing_policy_generation;
    FlowState flow_state;
    FlowTerminalReason terminal_reason;
};

struct FlowStateResult {
    ProtocolStatus status;
    FlowState state;
    FlowTerminalReason terminal_reason;
    std::uint32_t peer_activation_generation;
    std::uint32_t routing_policy_generation;
    Ipv4Endpoint advertised_local;
    std::uint64_t diagnostic_tag;
};

struct RoutingPolicySnapshot {
    std::uint32_t policy_generation;
    std::uint32_t route_count;
};

struct RouteRecord {
    std::uint8_t address_family;
    std::uint8_t prefix_length;
    std::uint16_t reserved;
    std::uint8_t network_address[16];
    std::uint64_t route_identifier;
};

static_assert(std::is_trivially_copyable_v<FlowHandle>);
static_assert(std::is_trivially_copyable_v<Ipv4Endpoint>);
static_assert(std::is_trivially_copyable_v<Capabilities>);
static_assert(std::is_trivially_copyable_v<OpenConnectedUdpFlowRequest>);
static_assert(std::is_trivially_copyable_v<OpenConnectedUdpFlowResult>);
static_assert(std::is_trivially_copyable_v<DatagramDescriptor>);
static_assert(std::is_trivially_copyable_v<DatagramDisposition>);
static_assert(std::is_trivially_copyable_v<CompletionRecord>);
static_assert(std::is_trivially_copyable_v<FlowStateResult>);
static_assert(std::is_trivially_copyable_v<RoutingPolicySnapshot>);
static_assert(std::is_trivially_copyable_v<RouteRecord>);
static_assert(sizeof(FlowHandle) == 8);
static_assert(sizeof(Ipv4Endpoint) == 8);
static_assert(sizeof(Capabilities) == 64);
static_assert(sizeof(OpenConnectedUdpFlowRequest) == 16);
static_assert(sizeof(OpenConnectedUdpFlowResult) == 24);
static_assert(sizeof(DatagramDescriptor) == 24);
static_assert(sizeof(DatagramDisposition) == 16);
static_assert(sizeof(CompletionRecord) == 48);
static_assert(sizeof(FlowStateResult) == 40);
static_assert(sizeof(RoutingPolicySnapshot) == 8);
static_assert(sizeof(RouteRecord) == 32);

} // namespace wgnx::tunnel
