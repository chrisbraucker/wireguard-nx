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

## Incremental Refactor

### Chunk 0: Freeze Contracts And Invariants

Document the component interfaces, event/effect vocabulary, generation rules,
locking policy, and current observable behavior. Add characterization tests for
important behavior that is currently encoded only in daemon procedures.

**Definition of done:** the current target build, host tests, and sanitizer tests
pass without production behavior changes, and later chunks have explicit
invariants against which they can be reviewed.

### Chunk 1: Consolidate Peer State

Replace the parallel per-peer arrays in daemon state with fixed-capacity
`PeerRuntime` slots. Introduce `PeerRegistry` for peer count, active-peer
selection, and autostart selection. Existing procedural helpers may initially
operate through these objects to keep this chunk mechanical.

**Definition of done:** every per-peer field has one structural owner, no
index-correlated state arrays remain, and behavior and scheduling are unchanged.

### Chunk 2: Encapsulate Lifecycle State

Move inactive, resolving, handshaking, active, and error transitions into
`PeerRuntime`. Move generation allocation and validation, metrics updates,
runtime error handling, and peer-status projection behind that boundary.

**Definition of done:** code outside `PeerRuntime` cannot directly mutate peer
lifecycle state. Deterministic tests cover valid transitions, stale generations,
deactivation, and status snapshots.

### Chunk 3: Introduce Events And Effects

Define closed `PeerEvent` and `RuntimeEffect` types and a fixed-capacity
`EffectBatch`. Introduce `RuntimeCoordinator::Dispatch()` and route a small,
non-I/O lifecycle slice through it while retaining adapters for unmigrated
paths.

**Definition of done:** the production coordinator dispatches at least one
complete transition; invalid event combinations are unrepresentable; no event
handler performs Horizon I/O while holding the state lock.

### Chunk 4: Extract Peer Activation

Move the complete activation path to events and effects: configuration
validation, endpoint-resolution request and completion, `WireGuardUdpBind`
creation, protocol instantiation, and initial handshake startup. Make endpoint
resolution a platform service rather than daemon-owned pending state.

**Definition of done:**
`activate -> resolve -> bind -> instantiate -> handshake` is deterministic in
host tests, including stale completion and failure paths. A real-peer on-device
connection regression passes.

### Chunk 5: Extract Outbound Lifecycle

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

Make `WireGuardUdpBind` receive return encrypted datagram events. Move handshake
parsing and responses, session installation and rotation, replay protection,
transport-data decryption, authenticated-activity handling, endpoint roaming
decisions, and decrypted-packet publication behind the peer boundary.

**Definition of done:** `WireGuardUdpBind` owns outer UDP sockets and datagrams
only; all protocol and key decisions are peer-owned; malformed, replayed, and
stale-session packets are covered; bidirectional real-peer traffic still
passes.

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
