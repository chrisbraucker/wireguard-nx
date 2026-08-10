#pragma once

#include "wgnx/lwip_budget.h"
#include "wgnx/protocol.hpp"

#include <cstddef>

namespace wgnx::resource_budget {

constexpr std::size_t KiB(std::size_t value) {
    return value * 1024;
}

// Fixed runtime cardinalities.
constexpr inline std::size_t PeerSlots = wgnx::MaxPeers;
constexpr inline std::size_t ActivePeerSlots = 1;
constexpr inline std::size_t IpcServerPorts = 2;
constexpr inline std::size_t IpcSessions = 8;
// These queues have independent producers, consumers, and pressure policy.
// Keep their capacities separate so one does not accidentally tune the other.
constexpr inline std::size_t PeerOutboundStagingSlots = 8;
constexpr inline std::size_t LegacyPacketChannelReceiveSlots = 8;
constexpr inline std::size_t EffectBatchSlots = 8;
// WireGuard owns independent retransmit, delayed-keepalive, liveness,
// stale-key cleanup, and persistent-keepalive deadlines.
constexpr inline std::size_t ProtocolTimerSlots = 5;
constexpr inline std::size_t OrderedWorkqueueSlots = 5;
constexpr inline std::size_t ResolveWorkSlots = 1;
constexpr inline std::size_t SubmissionWorkSlots = 2;
constexpr inline std::size_t TransmitWorkSlots = 1;
constexpr inline std::size_t ReceiveWorkSlots = 1;
constexpr inline std::size_t TimerWorkSlots = ProtocolTimerSlots + 1;
constexpr inline std::size_t EndpointRequestSlots = 1;
constexpr inline std::size_t UdpRebindRequestSlots = 1;
constexpr inline std::size_t UserspaceIpAdapterOperationSlots = 1;
constexpr inline std::size_t SocketConcurrency = 2;

// Fixed buffers and platform arenas.
constexpr inline std::size_t MaximumInnerPacketBytes = wgnx::MaxInnerIpv4PacketSize;
constexpr inline std::size_t EncryptedReceiveBytes = KiB(4);
constexpr inline std::size_t ResolverScratchBytes = KiB(16);
constexpr inline std::size_t FilesystemHeapBytes = KiB(32);
constexpr inline std::size_t SocketAllocatorBytes = KiB(128);
constexpr inline std::size_t SocketArenaBytes = KiB(304);
constexpr inline std::size_t WorkqueuePoolBytes = KiB(120);
constexpr inline std::size_t TimerManagerBytes = KiB(24);
// CMIF child service objects are served from a dedicated bounded heap rather
// than the optional global SF allocator.
constexpr inline std::size_t TunnelClientServiceAllocatorBytes = KiB(4);

// Runtime work contexts use 16 KiB stacks.
// CMIF dispatch receives map-alias buffers and creates child service objects, so
// it has an independent 32 KiB bounded stack.
constexpr inline std::size_t MainThreadStackBytes = KiB(16);
constexpr inline std::size_t WorkqueueThreadStackBytes = KiB(16);
constexpr inline std::size_t TimerThreadStackBytes = KiB(16);
constexpr inline std::size_t NifmPathThreadStackBytes = KiB(16);
constexpr inline std::size_t IpcServerThreadStackBytes = KiB(32);

// Layout ceilings turn otherwise silent fixed-footprint growth into a review gate.
constexpr inline std::size_t MaximumInnerPacketRecordBytes = 1536;
constexpr inline std::size_t MaximumPeerOutboundStagingBytes = KiB(13);
constexpr inline std::size_t MaximumLegacyPacketChannelBytes = MaximumPeerOutboundStagingBytes + 128;
constexpr inline std::size_t MaximumEffectBatchBytes = 2304;
constexpr inline std::size_t MaximumPeerRuntimeBytes = KiB(24);
constexpr inline std::size_t MaximumPeerRegistryBytes = KiB(192);
constexpr inline std::size_t MaximumTimerSchedulerBytes = 1600;
// The direct-flow plane owns bounded IPv4/UDP and completion slabs.
constexpr inline std::size_t MaximumDaemonRuntimeBytes = KiB(288);
constexpr inline std::size_t MaximumEndpointResolverBytes = 512;
constexpr inline std::size_t MaximumUdpRebindQueueBytes = 96;
constexpr inline std::size_t MaximumHorizonDispatcherBytes = 512;
constexpr inline std::size_t MaximumEncryptedReceivePumpBytes = KiB(8);
constexpr inline std::size_t MaximumTunnelFlowPlaneBytes = KiB(80);
constexpr inline std::size_t MaximumUserspaceIpAdapterOwnerBytes = KiB(16);
constexpr inline std::size_t LwipMemoryBytes = WGNX_LWIP_MEM_SIZE;
constexpr inline std::size_t LwipUdpPcbSlots = WGNX_LWIP_UDP_PCBS;
constexpr inline std::size_t LwipTcpPcbSlots = WGNX_LWIP_TCP_PCBS;
constexpr inline std::size_t LwipTcpSegmentSlots = WGNX_LWIP_TCP_SEGMENTS;
constexpr inline std::size_t LwipTcpMss = WGNX_LWIP_TCP_MSS;
constexpr inline std::size_t LwipTcpWindowBytes = WGNX_LWIP_TCP_WINDOW;
constexpr inline std::size_t LwipTcpSendBufferBytes = WGNX_LWIP_TCP_SEND_BUFFER;
constexpr inline std::size_t LwipReassemblySlots = WGNX_LWIP_REASSEMBLIES;
constexpr inline std::size_t LwipReassemblyPbufSlots = WGNX_LWIP_REASSEMBLY_PBUFS;
constexpr inline std::size_t LwipFragmentPbufSlots = WGNX_LWIP_FRAGMENT_PBUFS;
constexpr inline std::size_t LwipPbufPoolSlots = WGNX_LWIP_PBUF_POOL_SIZE;
constexpr inline std::size_t LwipPbufPoolBufferBytes = WGNX_LWIP_PBUF_POOL_BUFSIZE;

static_assert(PeerSlots > 0);
static_assert(ActivePeerSlots == 1);
static_assert(IpcServerPorts == 2);
static_assert(TunnelClientServiceAllocatorBytes >= KiB(4));
static_assert(PeerOutboundStagingSlots > 0);
static_assert(LegacyPacketChannelReceiveSlots > 0);
static_assert(EffectBatchSlots > 0);
static_assert(OrderedWorkqueueSlots == 5);
static_assert(ResolveWorkSlots + SubmissionWorkSlots + TransmitWorkSlots + ReceiveWorkSlots + TimerWorkSlots == 11);
static_assert(MainThreadStackBytes == WorkqueueThreadStackBytes);
static_assert(WorkqueueThreadStackBytes == TimerThreadStackBytes);
static_assert(NifmPathThreadStackBytes == WorkqueueThreadStackBytes);
static_assert(IpcServerThreadStackBytes >= MainThreadStackBytes);
static_assert(LwipPbufPoolSlots > 2 * LwipReassemblyPbufSlots);
static_assert(LwipTcpPcbSlots == 1);
static_assert(LwipTcpSegmentSlots >= 2);
static_assert(LwipTcpMss <= MaximumInnerPacketBytes - 40);
static_assert(LwipTcpWindowBytes >= LwipTcpMss);
static_assert(LwipTcpSendBufferBytes >= LwipTcpMss);

} // namespace wgnx::resource_budget
