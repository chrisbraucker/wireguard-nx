# Runtime Architecture

The sysmodule runtime is split by ownership rather than by call direction. The
IPC and WireGuard wire contracts remain unchanged; the separation is internal.

## Components

- `ipc_service.cpp` adapts CMIF buffers and process IDs to typed runtime
  operations and owns service registration. It does not own peer state,
  sockets, queues, or lifecycle policy.
- `runtime/daemon_runtime.cpp` owns the single state mutex and executes
  generation-checked platform effects. Inbound packet processing, concrete
  timer scheduling, debug probes, and auxiliary path observation remain
  transitional procedures for later extraction chunks.
- `runtime/peer_runtime.hpp` defines the fixed-capacity `PeerRegistry`. Each
  `PeerRuntime` slot is the structural owner of one peer's configuration,
  derived secrets, lifecycle and metrics state, UDP binding, protocol device,
  and peer controller. Lifecycle state is private; activation generations,
  transitions, metrics, errors, status projection, activation, and outbound
  queue/handshake policy are peer-owned. Each peer also owns one bounded pending
  encrypted datagram so effects never carry large packet buffers.
- `runtime/runtime_events.hpp` defines the closed event/effect vocabulary and
  bounded effect storage. `runtime/runtime_coordinator.*` resolves event peer
  identity and dispatches into `PeerRuntime`. Activation, endpoint and bind
  completion, outbound packet staging, send completion, protocol timer expiry,
  transport rebound, and authenticated session completion use this path.
- `runtime/endpoint_resolver.*` owns the bounded pending endpoint-resolution
  request. Resolution runs on its Horizon work queue and returns a typed,
  activation-tagged completion instead of mutating daemon-owned request state.
- `runtime/horizon_dispatcher.*` owns Atmosphere work queues and concrete timer
  objects. It captures timer tokens and delivers typed callbacks; it does not
  decide protocol transitions.
- `runtime/udp_binding.*` is the move-only owner of one resolved endpoint and
  UDP socket lifetime. It also owns socket generation and suspension state.
- `runtime/packet_channel.hpp` owns development packet-API PID identity,
  receive queueing, and packet IDs. Peer-owned outbound staging remains in the
  protocol peer.
- `wireguard/peer_controller.*` owns platform-independent staged-send,
  handshake retry, and timer-token transitions. Each `PeerRuntime` owns one
  controller; production and deterministic host tests invoke the same
  operations.

## Concurrency Rule

The daemon keeps one state mutex during this refactor. Blocking endpoint
resolution, UDP socket opening and sends, and UDP receive use the established
three-step pattern:

1. snapshot peer, activation, socket generation, and socket under the mutex;
2. release the mutex for blocking platform I/O;
3. reacquire it and commit only if every generation and identity still match.

`UdpBinding::Matches` centralizes the socket half of this validation. Timer work
is similarly guarded by peer, activation, retry-sequence, and arm-generation
tokens before a controller transition is applied.

Event handlers mutate memory and return effects only. The daemon releases the
state mutex before executing an effect, then revalidates its peer and activation
identity before scheduling work. Stale effects are discarded.

Effect execution is iterative. Completion events may produce another bounded
batch, but the platform adapter drains those batches without recursively
retaining prior batches on a Horizon worker stack. Blocking UDP bind and send
handlers are non-inlined stack boundaries so their I/O snapshots cannot be
coalesced into the executor frame.

The ordered receive work queue owns one process-lifetime 4 KiB datagram scratch
buffer. `ReceiveWorkMain` places only a small `packet_buffer` view on its worker
stack. Work for the same receive item cannot execute concurrently, so this
storage is exclusive without requiring one allocation per peer. Received bytes
are consumed synchronously before the next socket read and are never retained
through the scratch view.

The single mutex is intentionally retained until on-device regression testing
confirms this ownership refactor. Narrower locks can be considered later from
measured contention, without weakening generation-checked commits.

## Test Boundary

The host suite links the production `PeerRegistry`, `PeerRuntime`,
`RuntimeCoordinator`, `EndpointResolver`, `UdpBinding`, `PeerController`,
`TimerCoordinator`, and `PacketChannel`. Its 24 deterministic cases characterize
selection, activation, lifecycle transitions, status projection, stale event
rejection, bounded effects, generation matching, per-peer ownership, and the
outbound send lifecycle. Its production-runtime recovery workflow drives:

`stage -> 20 fresh unanswered sends -> exhaust/drop -> stage later packet ->
fresh handshake -> derive session -> release packet`

Horizon work-queue scheduling, synchronous timer cancellation, BSD socket
lifetime, and real callback races remain on-device validation responsibilities.

## Stack Budget

The sysmodule main thread has a 16 KiB stack. `wg_device` and `wg_peer` include
bounded packet storage and are therefore themselves roughly 16 KiB objects.
Their reset and initialization paths reconstruct existing storage in place;
they must never use aggregate assignment that materializes a full temporary.
Target C++ builds enforce an 8 KiB maximum frame as a compile-time regression
guard. This limit is necessary but does not detect cumulative nested frames: a
Chunk 4 activation regression retained resolver, effect-batch, bind-completion,
and send-snapshot frames through recursive effect execution and overflowed the
16 KiB resolver stack. The executor is now iterative, with target frames of
3,152 bytes for resolver work, 4,560 bytes for effect iteration, 2,528 bytes for
bind opening, and 4,048 bytes for datagram send. Host ASan/UBSan coverage
verifies object lifetime and bounded effect chaining, while generated target
code verifies each constrained frame.

An on-device fatal after Chunk 5 exposed another cumulative-stack case on the
receive worker: its 4 KiB local datagram buffer remained live while inbound
processing generated and executed a pending datagram send. The resulting call
chain exhausted the 16 KiB worker stack in `udp_send`, even though every
individual frame passed the 8 KiB compiler guard. The receive bytes now live in
the ordered worker's persistent scratch storage, reducing the receive frame
from 6,816 bytes to 160 bytes without increasing any thread stack or changing
packet capacity. Including the 2,608-byte inbound commit, 4,560-byte effect
executor, 4,048-byte datagram-send effect, and 160-byte UDP adapter frames, the
measured target path now consumes about 11.6 KiB before small workqueue frames
instead of exceeding the 16 KiB worker stack.
