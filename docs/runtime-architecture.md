# Runtime Architecture

The sysmodule runtime is split by ownership rather than by call direction. The
IPC and WireGuard wire contracts remain unchanged; the separation is internal.

## Components

- `ipc_service.cpp` adapts CMIF buffers and process IDs to typed runtime
  operations and owns service registration. It does not own peer state,
  sockets, queues, or lifecycle policy.
- `runtime/daemon_runtime.cpp` composes one `DaemonRuntime` instance. It owns
  the single state mutex, routes external commands, aggregates status, and
  coordinates generation-checked platform effects. CMIF-facing free functions
  are narrow adapters to that instance; no peer, packet, timer, probe, or
  pending-request state exists in independent daemon globals.
- `runtime/peer_runtime.hpp` defines the fixed-capacity `PeerRegistry`. Each
  `PeerRuntime` slot is the structural owner of one peer's configuration,
  derived secrets, lifecycle and metrics state, UDP binding, protocol device,
  and peer controller. Lifecycle state is private; activation generations,
  transitions, metrics, errors, status projection, activation, and inbound and
  outbound protocol policy are peer-owned. Each peer owns one bounded pending
  encrypted datagram and one bounded generation-tagged plaintext slot, so
  events and effects never carry owned packet buffers.
- `runtime/runtime_coordinator.*` is the only mutable entry point to the peer
  registry and peer policy. Peer configuration, derived secrets, binding,
  protocol device, controller, generations, and lifecycle are private. Runtime
  adapters receive immutable lifecycle, binding, packet, timer, or protocol
  snapshots scoped to one operation; they cannot obtain a mutable peer.
- `runtime/runtime_events.hpp` defines the closed event/effect vocabulary and
  bounded effect storage. `runtime/runtime_coordinator.*` resolves event peer
  identity and dispatches into `PeerRuntime`. Activation, endpoint and bind
  completion, outbound packet staging, send completion, encrypted datagram
  receipt, protocol timer expiry, transport rebind, transport failure,
  deactivation, and decrypted-packet publication use this path. UDP transport
  failures cross this boundary as socket- and generation-tagged facts. The peer
  decides whether an error is nonterminal, whether send failure suspends
  transport, which timers must be canceled, and whether successful rebinding
  resumes with a keepalive or a handshake. Rebind opens are tagged by purpose
  and generation: failed opens preserve the old socket, stale completions close
  only their candidate, and successful completion atomically adopts the
  replacement before recovery effects are emitted.
- `runtime/endpoint_resolver.*` owns the bounded pending endpoint-resolution
  request. Resolution runs on its Horizon work queue and returns a typed,
  activation-tagged completion instead of mutating daemon-owned request state.
- `runtime/horizon_dispatcher.*` owns Atmosphere ordered work queues only. It
  executes work supplied by runtime components and contains no timer or peer
  policy.
- `runtime/timer_scheduler.*` owns concrete Horizon protocol and auxiliary
  timers. `runtime/timer_schedule.*` tracks bounded physical arm and queued
  delivery state independently of Horizon. Expirations retain their complete
  token until delivered through the coordinator; the scheduler contains no
  peer policy. Arm and cancellation effects likewise retain the token allocated
  under the runtime lock, preventing delayed platform work from changing a
  newer physical schedule.
- `runtime/udp_binding.*` is the move-only owner of one resolved endpoint and
  UDP socket lifetime. It also owns socket generation and suspension state.
- `runtime/packet_transport.hpp` defines the protocol-neutral complete-IP
  packet boundary. It does not expose CMIF types or contained IP protocols.
- `runtime/packet_data_plane.*` owns IPv4/IPv6 envelope validation, active-peer
  routing, packet IDs, consumer transfer, outbound submission, decrypted
  packet delivery, receive staleness, and queue disposition. The public API v4
  adapter intentionally retains its IPv4-only contract.
- `runtime/packet_channel.hpp` implements `PacketTransport` for the development
  CMIF packet API. Its explicit IPv4-only capability preserves the API v4
  receive contract while future transports can accept IPv6. PID ownership and
  the bounded receive queue end at this adapter; PID identity does not enter
  peer events or WireGuard packet records. Peer-owned outbound staging remains
  in the protocol peer.
- `runtime/debug_probe_runner.*` owns synthetic probe commands, status, packet
  construction, reply classification, and timeout state. It submits through
  the internal-producer side of `PacketDataPlane`, preserving the CMIF packet
  consumer while using the same peer staging and effect path.
- `runtime/network_path_observer.*` owns NIFM observation sequencing and
  fingerprint comparison. The Horizon UDP adapter produces a stateless
  `NetworkPathSnapshot`; observation remains policy-free and cannot mutate a
  peer or trigger rebinding.
- `runtime/peer_configuration.*` loads a configuration snapshot, derives
  move-only private and preshared key material before peer assignment, resolves
  the autostart selection, and scrubs encoded secret fields.
- `runtime/udp_binding.hpp` also defines the bounded single-item
  `UdpRebindQueue`, which owns manual path-transition requests until the
  receive worker can safely replace the socket.
- `wireguard/peer_controller.*` owns platform-independent staged-send,
  handshake retry, initiator/responder session derivation, responder-session
  confirmation, and timer-token transitions. Each `PeerRuntime` owns one
  controller; production and deterministic host tests invoke the same paths.

Inbound endpoint roaming occurs only after handshake or transport
authentication. A responder-derived keypair enters the `next` slot and does not
replace the current session until its first authenticated transport packet;
that promotion moves the old current keypair to `previous`. Invalid MACs,
non-increasing initiation timestamps, initiations inside the upstream 20 ms
flood interval, transport replays, and unknown receiver indices do not update
endpoint or authenticated byte counters.

## Concurrency Rule

The daemon keeps one state mutex. Blocking endpoint
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
buffer and one 2,184-byte effect batch. `ReceiveWorkMain` places only a small
`packet_buffer` view on its worker stack. Work for the same receive item cannot
execute concurrently, so this storage is exclusive without requiring one
allocation per peer. Received bytes are consumed synchronously before the next
socket read and are never retained through the scratch view. The non-inlined
commit boundary returns before the static batch enters effect execution, so its
frame cannot accumulate with UDP send effects.

The single mutex is intentionally retained through the first post-refactor
on-device regression. Narrower locks can be considered later from
measured contention, without weakening generation-checked commits.

## Test Boundary

The host suite links the production `PeerRegistry`, `PeerRuntime`,
`RuntimeCoordinator`, `EndpointResolver`, `UdpBinding`, `PeerController`,
`TimerCoordinator`, `TimerSchedule`, `PacketDataPlane`, `PacketChannel`,
`DebugProbeRunner`, `NetworkPathObserver`, and `UdpRebindQueue`.
Its 28 deterministic cases characterize selection, activation, lifecycle
transitions, status projection, stale event rejection, timer
arming/replacement/cancellation, queued stale delivery,
bounded effects, generation matching, per-peer ownership, packet IDs, PID
consumer transfer, IPv4/IPv6 envelope handling, packet queue overflow and
staleness, and the outbound send lifecycle. Its production-runtime recovery
workflow drives:

`stage -> 20 fresh unanswered sends -> exhaust/drop -> stage later packet ->
fresh handshake -> derive session -> release packet`

The same runtime test then drives peer-originated rotation:

`authenticated initiation -> preserve current/install next -> send response ->
authenticated transport -> promote next/preserve previous -> publish plaintext`

It also verifies initiation admission, malformed input, transport replay,
unknown receiver indices, and unauthenticated endpoint-roaming rejection.

Horizon work-queue execution, synchronous platform timer cancellation, BSD
socket lifetime, and real callback races remain on-device validation
responsibilities.

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

Chunk 6's first shape retained the inbound commit's effect batch while entering
effect execution and reached roughly 13 KiB before workqueue frames. Receive
effects now use the ordered worker's persistent batch and cross a non-inlined
commit boundary that returns before execution.

The first Chunk 6 device run exposed a separate activation-path regression.
The compiler had inlined the plaintext-publication effect's validation and
logging locals into the shared variant visitor, increasing every executor
frame from 4,560 to 6,144 bytes. The initial outbound handshake then overflowed
the resolver worker during formatted logging before any inbound packet was
handled. Plaintext publication now crosses a dedicated 192-byte non-inlined
adapter. Target frames are again 3,168 bytes for resolver work, 4,560 bytes for
effect iteration, 2,544 bytes for bind opening, and 4,064 bytes for datagram
send. This restores the proven pre-Chunk-6 activation shape while keeping the
publication path generation-checked under the daemon mutex.
