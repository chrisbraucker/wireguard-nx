#pragma once

#include "wgnx/protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace wgnx::tunnel {

constexpr inline char ServiceName[] = "wgnx:tun";
constexpr inline std::uint32_t TunApiVersion = 4;

constexpr inline std::size_t MaximumClientContexts = 4;
constexpr inline std::size_t MaximumFlowsPerClient = 4;
constexpr inline std::size_t MaximumFlows = MaximumClientContexts * MaximumFlowsPerClient;
constexpr inline std::size_t Ipv4HeaderBytes = 20;
constexpr inline std::size_t UdpHeaderBytes = 8;
constexpr inline std::size_t TcpHeaderBytes = 20;
// This is the conventional WireGuard interface MTU for a 1500-byte Ethernet path.
constexpr inline std::uint16_t DefaultEffectiveInnerMtu = 1420;
constexpr inline std::uint16_t MinimumEffectiveInnerMtu = 576;
constexpr inline std::uint16_t MaximumEffectiveInnerMtu = static_cast<std::uint16_t>(MaxInnerIpv4PacketSize);
// This is backing-store capacity, not the active per-peer transmission limit.
constexpr inline std::size_t MaximumUdpPayloadStorageBytes = MaxInnerIpv4PacketSize - Ipv4HeaderBytes - UdpHeaderBytes;
constexpr inline std::size_t MaximumTcpWriteStorageBytes = MaxInnerIpv4PacketSize - Ipv4HeaderBytes - TcpHeaderBytes;
constexpr inline std::size_t OutboundPacketSlabCount = 16;
constexpr inline std::size_t InboundPacketSlabCount = 16;
constexpr inline std::size_t MaximumInboundDatagramsPerFlow = 4;
constexpr inline std::size_t CompletionQueueCapacity = 16;
constexpr inline std::size_t MaximumBatchEntries = 8;
constexpr inline std::size_t MaximumPolicyRoutes = 16;
constexpr inline std::size_t KernelHandlesPerClient = 1;
constexpr inline std::size_t ReverseTupleQuarantineCapacity = MaximumFlows;

[[nodiscard]] constexpr bool IsValidEffectiveInnerMtu(std::uint16_t mtu) {
    return mtu >= MinimumEffectiveInnerMtu && mtu <= MaximumEffectiveInnerMtu;
}

[[nodiscard]] constexpr std::uint16_t ResolveEffectiveInnerMtu(std::uint16_t configured_mtu) {
    return configured_mtu == 0 ? DefaultEffectiveInnerMtu : configured_mtu;
}

[[nodiscard]] constexpr std::size_t MaximumUdpPayloadForInnerMtu(std::uint16_t mtu) {
    return IsValidEffectiveInnerMtu(mtu) ? static_cast<std::size_t>(mtu) - Ipv4HeaderBytes - UdpHeaderBytes : 0;
}

enum class RootCommandId : std::uint32_t {
    GetCapabilities = 0,
    OpenTunnelClient = 1,
};

enum class ClientCommandId : std::uint32_t {
    GetCapabilities = 0,
    GetRoutingPolicySnapshot = 1,
    GetCompletionEvent = 2,
    OpenConnectedUdpFlow = 3,
    SendUdpDatagramBatch = 4,
    ReceiveCompletions = 5,
    GetFlowState = 6,
    CloseFlow = 7,
    OpenConnectedTcpFlow = 8,
    WriteTcpStream = 9,
    ShutdownTcpWrite = 10,
};

enum class Capability : std::uint32_t {
    ConnectedIpv4Udp = 1U << 0,
    ConnectedIpv4Tcp = 1U << 1,
};

constexpr std::uint32_t CapabilityMask(Capability capability) {
    return static_cast<std::uint32_t>(capability);
}

constexpr inline std::uint32_t SupportedCapabilityMask =
    CapabilityMask(Capability::ConnectedIpv4Udp) | CapabilityMask(Capability::ConnectedIpv4Tcp);

enum class ProtocolStatus : std::uint32_t {
    Success = 0,
    MalformedInput = 1,
    UnsupportedOperation = 2,
    IncompatibleApiVersion = 3,
    RouteNotCovered = 4,
    PeerUnavailable = 5,
    TransportUnavailable = 6,
    FlowQuotaExhausted = 7,
    PayloadTooLarge = 8,
    QueueFull = 9,
    StaleHandle = 10,
    FlowClosed = 11,
    QueueEmpty = 12,
    OutputBufferTooSmall = 13,
    ReverseTupleExhausted = 14,
    TunnelBlockedByPolicy = 15,
    WrongFlowKind = 16,
    NotConnected = 17,
    LocalWriteClosed = 18,
};

enum class FlowState : std::uint32_t {
    Connecting = 0,
    Open = 1,
    Closing = 2,
    Closed = 3,
};

enum class FlowKind : std::uint32_t {
    Udp = 0,
    Tcp = 1,
};

enum FlowStreamFlag : std::uint32_t {
    FlowStreamFlagNone = 0,
    FlowStreamFlagLocalWriteOpen = 1U << 0,
    FlowStreamFlagRemoteWriteOpen = 1U << 1,
};

enum class FlowTerminalReason : std::uint32_t {
    None = 0,
    ClientClosed = 1,
    PeerDeactivated = 2,
    PeerActivationChanged = 3,
    PolicyInvalidated = 4,
    SysmoduleShutdown = 5,
    RemoteClosed = 6,
    ResetDuringConnect = 7,
    ResetAfterConnect = 8,
    ConnectTimedOut = 9,
    RouteLost = 10,
    LocalResourceFailure = 11,
};

enum class CompletionType : std::uint32_t {
    InboundUdpDatagram = 0,
    InboundTcpStream = 1,
    FlowStateChanged = 2,
    PolicyChanged = 3,
    Writable = 4,
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
    std::uint32_t maximum_tcp_write_bytes;
    std::uint32_t maximum_client_contexts;
    std::uint32_t maximum_flows_per_client;
    std::uint32_t maximum_flows;
    std::uint32_t completion_queue_capacity;
    std::uint32_t maximum_batch_entries;
    std::uint32_t maximum_policy_routes;
    std::uint32_t reserved;
};

struct OpenConnectedFlowRequest {
    Ipv4Endpoint remote;
    std::uint64_t diagnostic_tag;
};

struct OpenConnectedFlowResult {
    ProtocolStatus status;
    FlowHandle flow;
    std::uint32_t peer_activation_generation;
    std::uint32_t routing_policy_generation;
};

struct PayloadRange {
    FlowHandle flow;
    std::uint32_t payload_offset;
    std::uint32_t payload_size;
    std::uint64_t client_tag;
};

struct PayloadResult {
    std::uint64_t client_tag;
    ProtocolStatus status;
    std::uint32_t accepted_bytes;
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
    FlowKind flow_kind;
};

struct CompletionDrainResult {
    std::uint32_t count;
    ProtocolStatus status;
};

struct FlowStateResult {
    ProtocolStatus status;
    FlowState state;
    FlowTerminalReason terminal_reason;
    FlowKind flow_kind;
    std::uint32_t peer_activation_generation;
    std::uint32_t routing_policy_generation;
    Ipv4Endpoint advertised_local;
    std::uint64_t diagnostic_tag;
    std::uint32_t stream_flags;
    std::uint32_t reserved;
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
static_assert(std::is_trivially_copyable_v<OpenConnectedFlowRequest>);
static_assert(std::is_trivially_copyable_v<OpenConnectedFlowResult>);
static_assert(std::is_trivially_copyable_v<PayloadRange>);
static_assert(std::is_trivially_copyable_v<PayloadResult>);
static_assert(std::is_trivially_copyable_v<CompletionRecord>);
static_assert(std::is_trivially_copyable_v<CompletionDrainResult>);
static_assert(std::is_trivially_copyable_v<FlowStateResult>);
static_assert(std::is_trivially_copyable_v<RoutingPolicySnapshot>);
static_assert(std::is_trivially_copyable_v<RouteRecord>);
static_assert(sizeof(FlowHandle) == 8);
static_assert(sizeof(Ipv4Endpoint) == 8);
static_assert(sizeof(Capabilities) == 48);
static_assert(sizeof(OpenConnectedFlowRequest) == 16);
static_assert(sizeof(OpenConnectedFlowResult) == 24);
static_assert(sizeof(PayloadRange) == 24);
static_assert(sizeof(PayloadResult) == 16);
static_assert(sizeof(CompletionRecord) == 56);
static_assert(sizeof(CompletionDrainResult) == 8);
static_assert(sizeof(FlowStateResult) == 48);
static_assert(sizeof(RoutingPolicySnapshot) == 8);
static_assert(sizeof(RouteRecord) == 32);

} // namespace wgnx::tunnel
