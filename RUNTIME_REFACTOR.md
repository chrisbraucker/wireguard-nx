# Sysmodule Runtime Refactor Plan

## Purpose

The first runtime extraction established a narrow CMIF adapter and moved
resource ownership for Horizon dispatch, UDP bindings, and the development
packet channel into dedicated types. It did not complete the intended runtime
decomposition: `runtime/daemon_runtime.cpp` still coordinates peer activation,
endpoint resolution, transport, protocol transitions, timers, packet routing,
debug probes, NIFM observation, status projection, and most error handling
through shared global state.

This document defines an incremental refactor from that transitional shape to
components with explicit state ownership and interfaces. Every chunk must leave
the sysmodule buildable and preserve the existing WireGuard and IPC vertical
slices. The goal is not to distribute the current procedures among more files;
it is to make the type that owns state also own the transitions applied to it.

Internal source compatibility is not a constraint during this refactor. IPC API
v4, WireGuard interoperability, and observable runtime behavior remain intact
unless a later, intentional contract change is documented and versioned.

## Target Component Model

```text
CMIF adapter
    |
DaemonRuntime facade
    |
RuntimeCoordinator
    |
    +-- PeerRegistry
    |     +-- PeerRuntime[N]
    |           +-- PeerController
    |           +-- WireGuard protocol state
    |           +-- WireGuardUdpBind
    |
    +-- EndpointResolver
    +-- PacketTransport
    +-- TimerScheduler
    +-- PacketDataPlane
    +-- DebugProbeRunner
```

### CMIF Adapter

Adapts CMIF buffers, process IDs, and result codes to operations on
`DaemonRuntime`. It owns service registration but no peer, protocol, transport,
timer, or packet state.

### DaemonRuntime

Acts as the application facade. It owns the coordinator and platform services,
routes external commands, selects the active peer, and returns immutable status
snapshots. It contains no protocol, socket, packet, or timer algorithms.

### RuntimeCoordinator

Serializes access to mutable peer state. It dispatches typed events to a
`PeerRuntime`, collects the resulting effects, releases the state lock before
executing Horizon I/O, and dispatches generation-tagged completion events.

### PeerRegistry And PeerRuntime

`PeerRegistry` owns the fixed-capacity peer collection, active-peer selection,
and autostart selection. Each `PeerRuntime` is the sole owner of one peer's
configuration-derived state, activation generation, lifecycle and error state,
metrics, `PeerController`, WireGuard protocol device, and `WireGuardUdpBind`.

A peer consumes a closed `PeerEvent` and produces a bounded `EffectBatch`:

```cpp
EffectBatch PeerRuntime::Handle(const PeerEvent &event);
```

Events represent completed facts such as activation requests, endpoint
resolution, received datagrams, send outcomes, timer expiration, submitted
inner packets, and network-path changes. Effects request work such as endpoint
resolution, datagram transmission, timer changes, receive scheduling, and inner
packet delivery.

### Packet And Platform Services

- `EndpointResolver` resolves configured endpoint names and returns typed,
  generation-tagged completion events.
- `PacketTransport` is the protocol-neutral plaintext packet boundary. It
  accepts and delivers complete IPv4 or IPv6 packets without interpreting TCP,
  UDP, ICMP, or another contained IP protocol. The development IPC packet
  channel is its initial adapter; later Horizon integration can provide a
  system-facing implementation without changing the WireGuard protocol core.
- `WireGuardUdpBind` owns the encrypted outer WireGuard UDP carrier: Horizon
  socket lifetime, endpoint datagram send and receive, rebinding, and conversion
  of platform errors into closed outcomes. It does not interpret inner packets
  or mutate protocol state.
- `TimerScheduler` owns concrete Horizon timers and returns tokenized expiration
  events. It contains no peer policy.
- `PacketDataPlane` owns inner-IP validation, active-peer routing, queueing, and
  movement between `PacketTransport` and WireGuard peers.
- `DebugProbeRunner` generates synthetic development traffic through the same
  packet-transport path as other packet producers.

## Required Invariants

- One `PeerRuntime` owns all mutable lifecycle and protocol state for one peer.
- No parallel arrays rely on a shared peer index as an implicit ownership link.
- Only `RuntimeCoordinator` mediates mutable access to the peer registry.
- Horizon resolution, socket, and other blocking I/O never run while the state
  lock is held.
- Every asynchronous request and completion identifies the peer and applicable
  activation, socket, retry-sequence, or timer generation.
- Stale completions are harmless and deterministically rejected.
- Event and outcome types do not permit contradictory states.
- Effect and queue storage is bounded and suitable for sysmodule memory limits.
- `PacketTransport` carries complete IP packets without depending on their TCP,
  UDP, ICMP, or other contained protocol.
- Queue removal always records an explicit disposition.
- UDP path failure remains independent from cryptographic peer lifetime unless
  protocol policy explicitly requires a transition.
- CMIF types and process details do not cross into protocol or transport policy.
- There is one source of truth during every migration chunk; temporary adapters
  may delegate but must not duplicate mutable state.

## Frozen Runtime Contracts

These contracts describe the observable behavior at the start of the refactor.
They remain review gates for later chunks unless an intentional behavior or IPC
change is documented separately.

### Command And Status Behavior

- Peer selection accepts `-1` to disable selection or an index in
  `[0, peer_count)`. Every other value is rejected.
- Selecting the already-active peer is idempotent. Selecting another peer first
  tears down the old active peer; selecting `-1` leaves no active tunnel.
- Autostart selection follows the same index rules and changes in-memory state
  only after persistence succeeds.
- Daemon status is always ready after initialization. Tunnel-active depends
  only on having an active selection; the error flag is set when any configured
  peer is in the error state.
- Peer status flags independently project active selection, autostart
  selection, established state, error state, and resolved-endpoint presence.
- Status queries are observational and do not advance protocol or timer state.

### Event And Effect Vocabulary

The current daemon procedures are classified using the vocabulary that later
chunks will make explicit:

- **Events** are completed facts delivered under the runtime lock: activation
  requested, deactivation requested, endpoint resolved or failed, datagram
  received, datagram send completed or failed, timer expired, inner packet
  submitted, packet consumer changed, and network path observed.
- **Effects** request work outside peer policy: resolve endpoint, open/close or
  rebind UDP, send or receive a datagram, arm/cancel a timer, queue or deliver an
  inner packet, persist autostart selection, and schedule Horizon work.
- A request being queued is not a completed event. Horizon I/O results return as
  events and must pass identity and generation checks before mutation.

### Generation Rules

- Generation zero is never allocated and never identifies current work.
- Activation generation changes whenever a peer activation starts. Work from a
  previous activation cannot affect the current activation.
- Socket generation changes whenever a UDP socket is opened or rebound. A
  receive completion is current only when peer, activation generation, socket
  generation, and socket handle all match.
- Handshake retry sequence identifies one unanswered initiation sequence.
  Retry timer delivery must match that sequence as well as peer and activation.
- Timer arm generation changes on each arm. Cancellation or replacement makes
  already-queued expiration work stale.
- Counters wrap past zero to one. Equality of every applicable identity is
  required; partial matches are rejected without side effects.

### Locking And Ownership Policy

- The daemon mutex serializes all mutable peer, selection, packet-channel, and
  pending-request state during this migration.
- Endpoint resolution and blocking UDP receive use snapshot, unlock, perform
  I/O, relock, validate, commit. No blocking Horizon I/O is permitted while the
  daemon mutex is held.
- Timer callbacks enqueue tokenized work; protocol transitions occur only after
  the token is validated under the daemon mutex.
- Queue insertion, removal, clearing, and ownership transfer occur under the
  daemon mutex, and every removal records a disposition.

## Incremental Refactor

### Chunk 0: Freeze Contracts And Invariants

**Status:** Complete. The frozen contracts are documented above and covered by
the `runtime.frozen-contracts` host characterization test.

Document the component interfaces, event/effect vocabulary, generation rules,
locking policy, and current observable behavior. Add characterization tests for
important behavior that is currently encoded only in daemon procedures.

**Definition of done:** the current target build, host tests, and sanitizer tests
pass without production behavior changes, and later chunks have explicit
invariants against which they can be reviewed.

### Chunk 1: Consolidate Peer State

**Status:** Complete. `PeerRegistry` now owns the fixed-capacity collection,
peer count, active selection, and autostart selection. Each `PeerRuntime` slot
owns its configuration, derived secrets, lifecycle/metrics state, UDP binding,
protocol device, and peer controller. Subsequent chunks now encapsulate that
lifecycle state and route session establishment through the coordinator.

Replace the parallel per-peer arrays in daemon state with fixed-capacity
`PeerRuntime` slots. Introduce `PeerRegistry` for peer count, active-peer
selection, and autostart selection. Existing procedural helpers may initially
operate through these objects to keep this chunk mechanical.

**Definition of done:** every per-peer field has one structural owner, no
index-correlated state arrays remain, and behavior and scheduling are unchanged.

### Chunk 2: Encapsulate Lifecycle State

**Status:** Complete. `PeerRuntime` privately owns activation allocation and
validation, lifecycle transitions, metrics, debug-probe state, errors, and
`PeerInfo` projection. Deterministic coverage exercises valid and stale
transitions, deactivation, metrics, and active/error snapshots.

Move inactive, resolving, handshaking, active, and error transitions into
`PeerRuntime`. Move generation allocation and validation, metrics updates,
runtime error handling, and peer-status projection behind that boundary.

**Definition of done:** code outside `PeerRuntime` cannot directly mutate peer
lifecycle state. Deterministic tests cover valid transitions, stale generations,
deactivation, and status snapshots.

### Chunk 3: Introduce Events And Effects

**Status:** Complete. Closed variant-based `PeerEvent` and `RuntimeEffect`
vocabularies, a fixed-capacity `EffectBatch`, and `RuntimeCoordinator` are in
production. Authenticated session completion now dispatches a
`EncryptedDatagramReceivedEvent`; authenticated session completion and the
resulting packet-submission effects are peer-owned, while platform effects
execute after the daemon lock is released and revalidate peer identity.

The first on-device load regression exposed a pre-existing aggregate-reset
hazard in this build during peer initialization: assigning `{}` to the roughly
16 KiB `wg_device` and `wg_peer` objects caused GCC to materialize full
temporaries on the 16 KiB main-thread stack. These resets now destroy and
reconstruct the objects in place, preserving secret scrubbing while keeping
their target stack frames bounded. Target C++ builds reject frames larger than
8 KiB so this failure mode cannot silently return. The corrected binary passed
on-device loading, repeated requester traffic, and Wi-Fi/flight-mode/Wi-Fi
transition testing.

Define closed `PeerEvent` and `RuntimeEffect` types and a fixed-capacity
`EffectBatch`. Introduce `RuntimeCoordinator::Dispatch()` and route a small,
non-I/O lifecycle slice through it while retaining adapters for unmigrated
paths.

**Definition of done:** the production coordinator dispatches at least one
complete transition; invalid event combinations are unrepresentable; no event
handler performs Horizon I/O while holding the state lock.

### Chunk 4: Extract Peer Activation

**Status:** Complete. The production coordinator owns the generation-tagged
`activate -> resolve -> bind -> instantiate -> handshake` path. A dedicated
`EndpointResolver` owns pending resolution work, while endpoint resolution and
UDP socket opening execute outside the runtime lock and return typed completion
events. Stale resolution and bind completions are deterministic no-ops, with
stale opened sockets explicitly closed.

The first on-device connection attempt exposed cumulative stack growth in the
platform effect adapter: bind and datagram-send completions recursively invoked
the effect executor while retaining their caller's bounded batches. The fatal
reported stack overflow in the first handshake send on the 16 KiB resolver
worker stack. Effect execution now drains bounded batches iteratively, and the
two I/O-heavy handlers have explicit non-inlined stack boundaries. The target
frames are 3,152 bytes for resolver work, 4,560 bytes for effect iteration,
2,528 bytes for bind opening, and 4,048 bytes for datagram send. The corrected
path subsequently passed real-peer activation and repeated requester traffic
on-device.

Move the complete activation path to events and effects: configuration
validation, endpoint-resolution request and completion, `WireGuardUdpBind`
creation, protocol instantiation, and initial handshake startup. Make endpoint
resolution a platform service rather than daemon-owned pending state.

**Definition of done:**
`activate -> resolve -> bind -> instantiate -> handshake` is deterministic in
host tests, including stale completion and failure paths. A real-peer on-device
connection regression passes.

### Chunk 5: Extract Outbound Lifecycle

**Status:** Complete for the outbound lifecycle. Inner-packet staging,
encrypted datagram construction, send outcomes, initial and replacement
handshakes, retransmission, exhaustion, keepalive/rekey
decisions, session derivation, and queue retirement now run through
`PeerRuntime` events. Encrypted bytes remain in one bounded peer-owned pending
slot; post-lock send effects carry only peer and datagram generations.

The deterministic production-runtime test covers the complete recovery shape:
`stage -> 20 unanswered fresh sends -> exhaust/drop -> stage later packet ->
fresh handshake -> derive session -> confirmation keepalive -> encrypt/send ->
retire packet`. The target build and all 24 host and ASan/UBSan cases pass.

The corrected on-device regression established one real-peer session and ran
three requester submissions without a crash. All three plaintext packets were
staged, encrypted, sent, and retired; the first two completed bidirectional
round trips. The third received no echo before its requester timeout. The next
encrypted inbound packet was a peer-originated handshake initiation, which the
current inbound path explicitly rejected as unsupported. That does not identify
an outbound queue or send-completion failure: responder-initiated handshake and
session rotation belong to Chunk 6 and are recorded there as an explicit
real-peer requirement.

Move inner-packet staging, initiation creation, encrypted transport creation,
send outcomes, replacement handshakes, retries, exhaustion, and keepalive
decisions into `PeerRuntime` and `PeerController`. Encrypted datagram submission
through `WireGuardUdpBind` becomes an effect and returns a closed completion
event.

**Definition of done:** the production event path covers
`stage -> 20 unanswered fresh sends -> exhaust/drop -> stage later packet ->
fresh handshake -> derive session -> release packet`. No queue or handshake
mutation remains in daemon orchestration. A repeated-requester real-peer test
passes.

### Chunk 6: Extract Inbound Lifecycle

**Status:** Implementation complete; corrected real-peer on-device regression
pending. The first Chunk 6 target reached peer activation but overflowed the
16 KiB resolver-worker stack during initial handshake logging. Target
disassembly traced this to inbound publication logic being inlined into the
shared effect executor even though that effect was not active. Publication now
crosses a dedicated non-inlined adapter, restoring the executor's pre-Chunk-6
frame size without changing protocol behavior.

The receive worker now emits one generation-tagged
`EncryptedDatagramReceivedEvent`. `PeerRuntime` owns message admission,
handshake response creation, initiator and responder session derivation,
current/next/previous key rotation, transport replay filtering, authenticated
endpoint roaming, and plaintext validation. A single bounded peer-owned
plaintext slot backs a generation-tagged publication effect, so neither events
nor effects copy packet-sized buffers.

Responder admission now verifies MAC1, rejects non-increasing TAI64N
timestamps, and enforces wireguard-go's 20 ms initiation flood interval. A
deterministic real-protocol runtime workflow establishes an initiator session,
accepts a peer-originated replacement initiation while preserving the current
session, emits and consumes the response, promotes the next keypair on first
authenticated transport, and publishes the decrypted IPv4 packet. The same
workflow rejects malformed input, duplicate transport counters, unknown
receiver indices, and replayed initiations without changing authenticated
counters or the roaming endpoint. All 25 host and ASan/UBSan cases and the
target build pass.

The Chunk 5 real-peer regression captured a peer-originated handshake
initiation after multiple successful requests. The current daemon accepts a
handshake response and transport data but rejects an incoming initiation. The
extracted inbound lifecycle must consume authenticated initiations, create and
send responses, install the resulting responder session, and preserve any
valid previous session during rotation.

Make `WireGuardUdpBind` receive return encrypted datagram events. Move handshake
parsing and responses, session installation and rotation, replay protection,
transport-data decryption, authenticated-activity handling, endpoint roaming
decisions, and decrypted-packet publication behind the peer boundary.

**Definition of done:** `WireGuardUdpBind` owns outer UDP sockets and datagrams
only; all protocol and key decisions are peer-owned; malformed, replayed, and
stale-session packets are covered; bidirectional real-peer traffic still
passes. The implementation and deterministic portions are complete; the final
real-peer condition remains the next on-device gate.

### Chunk 7: Formalize Scheduling

Reduce `HorizonDispatcher` to work execution and move timer ownership behind
`TimerScheduler`. Every expiration enters the coordinator as a typed event with
the identity needed to reject stale queued work.

**Definition of done:** dispatcher and scheduler code contain no peer policy;
timer arming, replacement, cancellation, and stale delivery have deterministic
coverage; real timer callbacks pass an on-device regression.

### Chunk 8: Extract The Packet Data Plane

Introduce `PacketTransport` as the generic inner IPv4/IPv6 packet boundary.
Move inner-packet validation, active-peer routing, outbound submission, and
decrypted-packet delivery into `PacketDataPlane`. Adapt `PacketChannel` to the
initial development IPC implementation of `PacketTransport`; CMIF packet
commands delegate through that adapter.

**Definition of done:** the protocol core is independent of the source or sink
of plaintext IP packets and does not inspect their contained IP protocol. CMIF
and protocol code no longer manipulate packet-channel ownership or queues.
Packet IDs, PID ownership, capacity, and overflow behavior retain deterministic
coverage.

### Chunk 9: Separate Auxiliary Workflows

Move synthetic ICMP, HTTP, and other probe behavior into `DebugProbeRunner`.
Isolate NIFM observation and future rebinding policy. Separate configuration
loading and secret derivation from live peer mutation.

**Definition of done:** probes and network-path observation use runtime commands
and events instead of touching peer internals; disabling development probes does
not alter the production tunnel lifecycle.

### Chunk 10: Collapse The Facade

Replace free-function access to hidden globals with an actual `DaemonRuntime`
instance. Remove migration adapters, daemon-owned pending-request structures,
obsolete global buffers, and procedural helpers that have moved to their state
owners. Update the architecture documentation to describe the final code rather
than the transition.

**Definition of done:** `daemon_runtime.cpp` contains construction, command
routing, effect execution coordination, and status aggregation only. It contains
no protocol, socket, timer, packet, resolver, probe, or NIFM algorithms.

## Verification Gates

Target builds enforce an 8 KiB maximum C++ stack frame. The sysmodule main
thread has a 16 KiB stack, so large owned protocol and packet-storage objects
must be reset or initialized in place rather than copied through aggregate
temporaries.

The Chunk 5 on-device regression also caught cumulative receive-worker stack
usage that the per-frame guard cannot detect. `ReceiveWorkMain` kept a 4 KiB
datagram buffer live while inbound processing synchronously executed generated
send effects. The ordered receive queue now owns one process-lifetime 4 KiB
scratch buffer and the callback keeps only a small packet view on its stack.
This preserves bounded storage and serialized ownership without increasing the
worker stack. Generated target code measures the corrected receive frame at 160
bytes, down from 6,816 bytes in the crashing build; the complete measured
receive-to-send path is about 11.6 KiB before small workqueue frames.

Chunk 6 initially retained its 2,184-byte receive effect batch in the inbound
commit frame while synchronously entering the effect executor and UDP send
adapter. Target disassembly showed roughly 13 KiB of explicit frames before
workqueue overhead. The ordered receive worker now owns that batch next to its
datagram scratch, and the inbound commit is a non-inlined boundary that returns
before effect execution.

The first Chunk 6 device run then overflowed during the initial outbound
handshake, before any inbound packet was handled. The fatal chain was resolver
work -> effect execution -> UDP bind completion -> handshake initiation ->
logging. The new plaintext-publication branch had been fully inlined into the
variant visitor, increasing every effect-execution frame from 4,560 to 6,144
bytes. A dedicated non-inlined publication adapter now holds the lock,
generation checks, packet view, and publication path. Generated target code
measures 3,168 bytes for resolver work, 4,560 bytes for effect iteration, 2,544
bytes for bind opening, and 192 bytes for the publication adapter. This removes
1,584 bytes from the crashing activation chain and keeps publication-only
locals out of unrelated effects. The corrected target still requires the next
real-peer device pass.

Every chunk must pass:

- the devkitA64/Atmosphere target build
- all deterministic host tests
- ASan/UBSan host tests
- `git diff --check`
- review that `common/include/wgnx/protocol.hpp` and the CMIF contract remain
  unchanged unless an API change is intentional

Run focused on-device regressions after chunks 4, 5, 6, 7, and 10. At minimum,
these runs should cover tunnel activation against a known-good peer, repeated
requester round trips under one continuously active sysmodule, clean teardown,
and the path-outage scenario applicable to the migrated lifecycle.

## Completion Criteria

The runtime refactor is complete when:

- source-file boundaries correspond to state and lifecycle ownership
- `DaemonRuntime` is a small facade rather than the implementation of every
  subsystem
- one peer's complete activation, handshake, transport, timer, recovery, and
  teardown lifecycle can be driven deterministically through production event
  handlers
- Horizon services can be substituted by host fakes without reproducing daemon
  policy in tests
- the existing real-peer and development packet-API behavior remains intact
- the resulting boundaries can accept later Horizon system-integration work
  without routing that work through another global runtime module
