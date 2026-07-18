# Runtime Resource And Concurrency Budgets

`common/include/wgnx/resource_budget.hpp` is the source of truth for fixed
sysmodule capacities. These are hard bounds for the current runtime, not sizing
recommendations for future transparent transport integration. Any increase
must be reviewed against the Switch system-module memory budget and accompanied
by updated target footprint and stack reports.

## Fixed Storage

| Resource | Capacity | Compile-time ceiling |
| --- | ---: | ---: |
| Configured peer slots | 8 | 192 KiB `PeerRegistry` |
| Active tunnel peers | 1 | selection invariant |
| IPC service sessions | 8 on 1 service port | fixed server manager |
| One `PeerRuntime` | 1 | 24 KiB |
| Peer outbound packet queue | 8 x 1500-byte packets | 13 KiB |
| IPC receive packet queue | 8 x 1500-byte packets | 13 KiB |
| Runtime effect batch | 8 effects | 2304 bytes |
| Encrypted receive scratch | 1 x 4096-byte datagram | 4096 bytes |
| Endpoint request slot | 1 latest request | 512-byte owner |
| UDP rebind request slot | 1 latest request | 96-byte owner |
| Protocol timer slots | 4 | 1536-byte scheduler |
| Ordered work queues | 4 | 96 KiB static pool |
| Socket arena | 2 concurrent sockets | 304 KiB |
| Resolver scratch | 1 operation | 16 KiB |
| Filesystem heap | 1 arena | 32 KiB |
| Composed daemon | 1 | 216 KiB |

The four ordered lanes admit at most one resolver request, two submission
requests, one receive request, and six timer actions. Each queue has one 16 KiB
worker stack. The separate timer thread and the sysmodule main thread also have
16 KiB stacks. The 96 KiB workqueue pool includes queue metadata and four
preallocated stacks; the 24 KiB timer manager includes its metadata and stack.

These figures describe static owners. They do not include loader mappings,
Atmosphere service state, thread metadata, or other process overhead.

## Pressure And Drop Accounting

- `InnerPacketQueue` records high-water depth, full rejection, every pop
  disposition, and a derived total drop count. Full queues reject the new
  packet; they never evict an older packet.
- `EndpointResolver` and `UdpRebindQueue` retain the latest request in one
  slot. Replacing an unconsumed request is an explicit result and increments
  the replacement counter.
- Horizon ordered work queues report queued, rerun, already-pending,
  capacity-exhausted, and unavailable outcomes. Their statistics expose
  current depth, high water, coalescing, capacity rejection, unavailable
  rejection, and completion counts.
- `EffectBatch::Add` is an invariant operation and terminates on exhaustion.
  `TryAdd` and `TryAppend` return explicit capacity exhaustion for recoverable
  admission. Every peer event has a compile-time maximum that fits the
  eight-effect budget.
- Debug-probe admission reports `Busy` rather than replacing an active probe.

All protocol, packet, timer, and transport hot paths remain allocation-free.
Future transport queues must use bounded ownership and join the same accounting
model before they are admitted to the runtime.

## Locking

The lock hierarchy is deliberately shallow:

1. `DaemonRuntime::m_state_mutex` serializes `PeerRegistry`,
   `RuntimeCoordinator`, `PacketDataPlane`, `PacketChannel`,
   `EndpointResolver`, `DebugProbeRunner`, and the pending UDP-rebind slot.
2. `TimerScheduler::m_operation_mutex` serializes physical timer changes. It
   may acquire the scheduler state mutex, never the reverse.
3. Platform timer-manager, workqueue, socket-runtime, workqueue-pool, and
   logger locks are independent adapter locks. No callback runs while a
   platform timer-manager or workqueue lock is held.

The daemon state mutex is released before endpoint resolution, UDP open/send/
receive/close, concrete timer operations, work submission, and effect
execution. Runtime completion paths reacquire it only to validate identity and
commit a factual event.

Methods named `ClearInnerPacketStateLocked`,
`QueuePayloadSubmissionRequestLocked`, `QueueRebindLocked`, and
`PublishDecryptedPacketLocked` require the daemon state mutex. Mutable
`RuntimeCoordinator`, `PacketDataPlane`, `EndpointResolver`,
`DebugProbeRunner`, and `UdpRebindQueue` operations have the same requirement
even when their names omit the suffix. `TimerScheduler` owns its locks and must
not be called while the daemon mutex is held.

All lock ownership is scoped through `std::scoped_lock`, `std::unique_lock`, or
`wgnx::platform::MutexGuard`; early returns cannot strand a held mutex.

## Worker Contexts

- `wgnx-resolve`: endpoint resolution and activation completion.
- `wgnx-submit`: serialized debug and IPC inner-packet submission.
- `wgnx-recv`: blocking encrypted UDP receive, rebind processing, inbound
  protocol dispatch, and generated effects.
- `wgnx-timer-act`: generation-tagged protocol timer delivery, debug timeout,
  and NIFM observation.
- `wgnx-timer`: physical timer expiry only; it queues runtime timer work and
  does not execute peer policy.

The worker loop removes one item under its queue mutex, releases the mutex,
executes the callback, and reacquires it only for completion accounting and a
possible single rerun. Queue locks therefore never nest with daemon or protocol
locks during runtime work.

## Automated Reports

`make -C sysmodule resource-report` builds the target and runs:

- `tools/check_stack_usage.py`, which checks every compiler `.su` record
  against the 8 KiB frame limit and sums the known resolver/receive callback
  chains against their 16 KiB stacks with at least 1 KiB margin.
- `tools/report_footprint.py`, which reports ELF `text`, `data`, `bss`, static
  total, NSO, and NSP deltas against the named corrected Chunk 13 baseline and
  rejects the documented absolute image budgets.

The stack-chain configuration and footprint baseline live under
`tools/baselines/`. Updating either is a reviewed budget change, not routine
build churn.
