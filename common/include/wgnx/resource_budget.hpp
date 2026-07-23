#pragma once

#include "wgnx/protocol.hpp"

#include <cstddef>

namespace wgnx::resource_budget {

constexpr std::size_t KiB(std::size_t value) {
    return value * 1024;
}

// Fixed runtime cardinalities.
constexpr inline std::size_t PeerSlots = wgnx::MaxPeers;
constexpr inline std::size_t ActivePeerSlots = 1;
constexpr inline std::size_t IpcServerPorts = 1;
constexpr inline std::size_t IpcSessions = 8;
constexpr inline std::size_t PacketQueueSlots = 8;
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

// Every runtime-owned execution context currently has a 16 KiB stack.
constexpr inline std::size_t MainThreadStackBytes = KiB(16);
constexpr inline std::size_t WorkqueueThreadStackBytes = KiB(16);
constexpr inline std::size_t TimerThreadStackBytes = KiB(16);
constexpr inline std::size_t NifmPathThreadStackBytes = KiB(16);

// Layout ceilings turn otherwise silent fixed-footprint growth into a review gate.
constexpr inline std::size_t MaximumInnerPacketRecordBytes = 1536;
constexpr inline std::size_t MaximumPacketQueueBytes = KiB(13);
constexpr inline std::size_t MaximumPacketChannelBytes =
    MaximumPacketQueueBytes + 128;
constexpr inline std::size_t MaximumEffectBatchBytes = 2304;
constexpr inline std::size_t MaximumPeerRuntimeBytes = KiB(24);
constexpr inline std::size_t MaximumPeerRegistryBytes = KiB(192);
constexpr inline std::size_t MaximumTimerSchedulerBytes = 1600;
constexpr inline std::size_t MaximumDaemonRuntimeBytes = KiB(216);
constexpr inline std::size_t MaximumEndpointResolverBytes = 512;
constexpr inline std::size_t MaximumUdpRebindQueueBytes = 96;
constexpr inline std::size_t MaximumHorizonDispatcherBytes = 512;
constexpr inline std::size_t MaximumEncryptedReceivePumpBytes = KiB(8);

static_assert(PeerSlots > 0);
static_assert(ActivePeerSlots == 1);
static_assert(IpcServerPorts == 1);
static_assert(PacketQueueSlots > 0);
static_assert(EffectBatchSlots > 0);
static_assert(OrderedWorkqueueSlots == 5);
static_assert(
    ResolveWorkSlots + SubmissionWorkSlots + TransmitWorkSlots +
        ReceiveWorkSlots + TimerWorkSlots ==
    11);
static_assert(MainThreadStackBytes == WorkqueueThreadStackBytes);
static_assert(WorkqueueThreadStackBytes == TimerThreadStackBytes);
static_assert(NifmPathThreadStackBytes == WorkqueueThreadStackBytes);

} // namespace wgnx::resource_budget
