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

`PeerRegistry` owns the fixed-capacity peer collection, fixed-slot
configuration/clearing, active-peer selection, and autostart selection. Each
`PeerRuntime` is the sole owner of one peer's configuration-derived state,
activation generation, lifecycle and error state, metrics, `PeerController`,
WireGuard protocol device, and `WireGuardUdpBind`.

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
- `RuntimeCoordinator` mediates runtime-facing peer transitions through the
  closed `PeerRegistry` interface; no caller receives mutable peer storage.
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
- Configuration loading and autostart persistence run outside the daemon mutex.
  Autostart requests are separately serialized and carry a monotonic request
  generation; persistence succeeds before the corresponding selection is
  committed, and a stale request is discarded before and after filesystem I/O.
- Timer callbacks enqueue tokenized work; protocol transitions occur only after
  the token is validated under the daemon mutex.
- Platform adapters provide sampled `TimerFacts`; `PeerRuntime` derives every
  WireGuard retry, keepalive, rekey, and key-erasure deadline from those facts.
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

**Status:** Complete. The corrected implementation passed a long-running
real-peer session with eleven successful requester round trips, local timer
rekeys, peer-initiated replacement handshakes, authenticated key promotion,
and clean teardown. The first Chunk 6 target reached peer activation but
overflowed the 16 KiB resolver-worker stack during initial handshake logging.
Target disassembly traced this to inbound publication logic being inlined into the
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
passes. The implementation, deterministic coverage, and real-peer condition
are complete.

### Chunk 7: Formalize Scheduling

**Status:** Complete. `TimerScheduler` now owns every concrete Horizon protocol and
auxiliary timer, while `HorizonDispatcher` owns ordered work execution only. A
platform-independent `TimerSchedule` captures physical arm, replacement,
cancellation, and queued-delivery state. Protocol expirations carry their full
peer, activation, retry-sequence, and arm-generation token into
`RuntimeCoordinator`; `PeerRuntime` is the final stale-delivery authority and
owns zero-key-material expiry policy. Timer arm and cancellation effects retain
the token allocated under the coordinator lock, so delayed platform work cannot
replace or cancel a newer generation. All 26 host and ASan/UBSan cases and the
target build pass. A sustained on-device session completed repeated packet
round trips across keepalive, local rekey, peer-initiated rekey, and clean
activation teardown and restart cycles.

Reduce `HorizonDispatcher` to work execution and move timer ownership behind
`TimerScheduler`. Every expiration enters the coordinator as a typed event with
the identity needed to reject stale queued work.

**Definition of done:** dispatcher and scheduler code contain no peer policy;
timer arming, replacement, cancellation, and stale delivery have deterministic
coverage; real timer callbacks pass an on-device regression.

### Chunk 8: Extract The Packet Data Plane

**Status:** Complete. `PacketDataPlane` now owns IP-envelope validation, active-peer
selection, packet-ID allocation, PID consumer transfer, outbound staging,
decrypted-packet delivery, receive staleness, and queue retirement.
`PacketTransport` is the protocol-neutral inner-packet boundary, with explicit
IP-version capabilities and the bounded, IPv4-only `PacketChannel` as its
current CMIF adapter. The public API v4 remains IPv4-only, while the internal
data plane and decrypted protocol path validate complete IPv4 and IPv6 packets
without inspecting their contained protocol. PID identity no longer crosses
into peer events or WireGuard queue records.
All host and ASan/UBSan cases and the target build pass. Five consecutive
requester processes completed against a real peer across a peer stop/start
cycle, with monotonic packet IDs, clean ownership transfer, and no queue loss.

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

**Status:** Implementation complete; focused on-device regression pending.
`DebugProbeRunner` now owns probe commands, status, packet construction, reply
classification, and timeout state without mutating `PeerRuntime`.
The original polling `NetworkPathObserver` was subsequently retired in favor
of an activation-owned NIFM request service. The Horizon adapter owns one raw
NIFM request and publishes typed availability changes; the transport runtime
retains sole ownership of UDP descriptors. `PeerConfigurationLoader` derives move-only
key material and scrubs encoded secrets before configuration is assigned to
live peers. Synthetic traffic enters through the internal producer side of
`PacketDataPlane`, so it neither bypasses the data plane nor claims the CMIF
packet consumer.

Move synthetic ICMP, HTTP, and other probe behavior into `DebugProbeRunner`.
Isolate NIFM local-path facts and rebinding policy. Separate configuration
loading and secret derivation from live peer mutation.

**Definition of done:** probes and NIFM local-path facts use runtime commands
and events instead of touching peer internals; disabling development probes does
not alter the production tunnel lifecycle.

### Chunk 10: Collapse The Facade

**Status:** Implementation and local verification complete; focused on-device
regression pending. One `DaemonRuntime` instance now owns and composes the peer
registry, coordinator, platform services, packet plane, auxiliary workflows,
scratch storage, and bounded request owners. CMIF-facing free functions are
narrow compatibility adapters. The last ad hoc bind-bump request was replaced
by `UdpRebindQueue`; no independent daemon-state globals or daemon-owned
pending-request records remain. Deactivation and fatal transport failure now
enter `PeerRuntime` as typed events, removing the last facade-owned protocol
reset and key-scrubbing procedures.

Replace free-function access to hidden globals with an actual `DaemonRuntime`
instance. Remove migration adapters, daemon-owned pending-request structures,
obsolete global buffers, and procedural helpers that have moved to their state
owners. Update the architecture documentation to describe the final code rather
than the transition.

**Definition of done:** `daemon_runtime.cpp` contains construction, command
routing, effect execution coordination, and status aggregation only. It contains
no protocol, socket, timer, packet, resolver, probe, or NIFM algorithms.

## Post-Refactor Hardening Extension

Chunks 0 through 10 establish the target component model, but the resulting
implementation still permits several forms of accidental coupling that the
model intends to prevent. The following chunks close those remaining ownership
gaps and make the architecture enforceable through types, bounded-resource
contracts, and build tooling. They remain part of the runtime refactor rather
than introducing new tunnel or IPC behavior.

IPC API v4, WireGuard interoperability, and the frozen runtime contracts remain
unchanged throughout this extension. Modern C++ features are introduced where
they improve ownership, lifetime, error, or resource semantics; adopting a
language feature without one of those concrete benefits is not a goal.

### Chunk 11: Seal Peer Ownership

**Status:** Complete.

Make configuration, derived secrets, UDP binding, protocol state, and the peer
controller private implementation details of `PeerRuntime`. Remove unrestricted
mutable peer access from `PeerRegistry`; mutable lifecycle transitions must pass
through `RuntimeCoordinator`, while platform executors receive only the narrow
snapshots needed to perform one effect. Move the remaining nonterminal
transport-failure, suspension, recovery, and timer-cancellation decisions out
of `DaemonRuntime` and into peer events and effects.

This chunk changes internal interfaces freely but does not introduce additional
state owners or divide one peer's lifecycle across components.

**Definition of done:** code outside `PeerRuntime` cannot directly mutate peer
configuration-derived, protocol, controller, binding, generation, or lifecycle
state; `RuntimeCoordinator` is the only mutable peer-policy entry point; socket
and timer executors report facts instead of choosing peer policy; all existing
host, sanitizer, target, and real-peer behavior remains intact.

**Implementation:** `PeerRuntime` now keeps configuration, derived secrets, UDP
binding, protocol device, controller, generations, and lifecycle private.
`PeerRegistry` exposes closed collection operations for configuration,
clearing, selection, event dispatch, and bounded packet retirement. It invokes
the relevant `PeerRuntime` transition but does not expose mutable slots.
`RuntimeCoordinator` remains the runtime-facing mediator, while the daemon and
packet data plane consume immutable, purpose-specific snapshots rather than
peer references.

UDP receive failures are reported as socket- and generation-tagged facts.
Only explicit would-block, timeout, and interruption conditions are retried; a
negative receive with no classified socket condition is terminal rather than a
busy-loop. The diagnostic I/O-failure suspension policy cancels peer timers,
detaches the socket, and emits platform effects entirely inside the peer event
path while preserving peer and protocol state. Manual rebinding similarly
produces a peer-owned open request; failed
opens preserve the old socket, stale completions close only their candidate,
and a successful completion atomically adopts the new generation before the
peer chooses keepalive or handshake recovery. Host tests cover those policies,
including delayed rebind completion rejection.

Local validation passes 28 deterministic host cases, ASan/UBSan, the target
build, the target frame guard, and the unchanged API v4 protocol header. An
extended real-peer requester run completed successfully with the resulting
runtime, closing the focused on-device regression gate.

### Chunk 12: Extract Runtime I/O Execution

**Status:** Complete.

Extract the concrete effect visitor and Horizon completion bridge into a
`RuntimeEffectExecutor`. Extract encrypted UDP receive scheduling, receive
scratch ownership, and completion publication into an
`EncryptedReceivePump`. These components execute requests already chosen by
peer policy and return generation-tagged events; they do not interpret
WireGuard messages, alter peer lifecycle, or select recovery policy.

`DaemonRuntime` remains the composition root and application facade. It wires
commands to the coordinator, starts and stops platform services, and aggregates
status without implementing socket, receive-loop, timer, resolver, packet, or
protocol procedures.

**Definition of done:** `daemon_runtime.cpp` contains construction,
initialization, command routing, effect-drain coordination, and status
aggregation only; blocking Horizon I/O remains outside the state lock; receive
scratch has one bounded owner; stale I/O completions remain harmless; target
stack measurements and focused activation, traffic, teardown, and outage
regressions pass.

**Implementation:** `RuntimeEffectExecutor` owns the iterative effect visitor
and the concrete completion bridges for endpoint resolution, UDP bind and send,
protocol timers, outbound submission, decrypted packet publication, debug
probe timeout, and network-path observation. It receives immutable work or
generation-tagged completion facts and re-enters peer policy only through
`RuntimeCoordinator`.

`EncryptedReceivePump` owns the ordered receive scheduling surface, manual
rebind request, one process-lifetime 4 KiB datagram scratch buffer, and one
bounded completion batch. Its receive loop snapshots a peer identity, socket,
and generations under the shared mutex, performs blocking receive without the
mutex, and publishes either an authenticated-datagram event or a factual
transport-failure event after revalidation. `DaemonRuntime` now composes and
routes callbacks to these components; it contains no socket, receive-loop,
timer, resolver, or packet-completion procedure.

Local validation passes 28 deterministic host cases, the same 28 cases under
ASan/UBSan, the devkitA64 target build, the 8 KiB target frame guard, and
`git diff --check`. IPC API v4 and `common/include/wgnx/protocol.hpp` remain
unchanged. Generated target frames measure 3,168 bytes for endpoint completion,
4,448 bytes for effect iteration, 2,560 bytes for bind opening, 4,064 bytes for
datagram send, 2,752 bytes for receive commit, and 144 bytes for the receive
loop. The focused real-peer on-device regression subsequently passed repeated
requester traffic and clean teardown. Path recovery remained at its known
pre-refactor limitation and did not expose a Chunk 12 regression.

### Chunk 13: Strengthen Domain Contracts

**Status:** Complete locally and validated by the corrected focused real-peer
regression.

Replace interchangeable integer identities with small, trivially copyable
domain types for peer indices, activation generations, socket generations,
datagram generations, packet generations, packet IDs, and process IDs. Convert
to and from fixed-width IPC and platform values only at their boundaries.

Replace ambiguous boolean results with closed outcomes where callers must
distinguish stale work, malformed input, invalid state, capacity exhaustion,
and platform failure. Make fallible results `[[nodiscard]]`. Split bounded
insertion into invariant-preserving and recoverable operations so
`EffectBatch` capacity exhaustion cannot silently discard work. Formalize the
lifetime rule for synchronous borrowed packet views and require owned bounded
storage plus an identity token for asynchronous work.

Use `std::expected` where the target standard library supports it without an
unacceptable footprint; otherwise use a small project-local equivalent with the
same explicit value-or-error semantics.

The first contract slice replaces the ambiguous UDP receive error plus output
parameters with a `[[nodiscard]]` closed result. It distinguishes a datagram,
including a legitimate zero-length datagram, from a retryable native wakeup and
a terminal platform failure. The Horizon adapter normalizes `EAGAIN`,
`EWOULDBLOCK`, `ETIMEDOUT`, `EINTR`, and the observed negative
`RecvFrom`/`ESuccess` anomaly while retaining the raw native result and error for
diagnostics. The anomaly is a separately tagged, paced local retry: it does not
publish a peer transport failure or imply a network-path transition. Retry
outcomes do not publish peer transport failures; terminal outcomes retain the
existing generation-checked failure path.

The completed chunk adds compiler-distinct `PeerIndex`,
`ActivationGeneration`, `SocketGeneration`, `DatagramGeneration`,
`PacketGeneration`, `PacketId`, and `ProcessId` values. Raw fixed-width values
are converted explicitly at CMIF, platform, WireGuard-record, timer, status,
and logging boundaries. Cross-domain comparisons and implicit raw conversions
are rejected by the compiler, while every domain value remains trivially
copyable and the same size as its representation.

`EffectBatch` now separates invariant insertion (`Add`/`Append`, which terminate
on a violated capacity invariant) from recoverable insertion
(`TryAdd`/`TryAppend`, which returns a closed capacity result). Every peer event
declares a compile-time maximum effect count, each maximum fits the fixed
eight-effect batch, and coordinator dispatch checks the declared event budget.
Endpoint resolution, manual rebind, debug-probe admission, packet submission,
delivery, and receive surfaces expose closed outcomes rather than ambiguous
booleans.

Borrowed packet bytes are represented by `SynchronousPacketView` only on
synchronous event paths. Effects cannot be constructed from the borrowed view;
work that crosses an asynchronous boundary is copied into existing bounded,
identity-tagged peer or data-plane storage before the event returns. The target
standard library does not require a project-local `expected` for this chunk:
the closed enums, variants, and `optional` results express all current
value-or-error contracts without additional storage or machinery.

**Definition of done:** the compiler rejects cross-domain identity comparisons;
no fallible effect insertion is ignored; tests exercise each typed rejection
and the maximum effect count of every event path; borrowed packet data cannot be
retained by an asynchronous queue; IPC layout and API v4 remain unchanged.

### Chunk 14: Enforce Resource And Concurrency Budgets

**Status:** Locally complete. Focused long-lived repeated-connection validation
has passed; the remaining path-transition cases continue under the corrective
validation matrix.

Centralize the fixed capacities and memory budgets for peer state, packet
slots, effect batches, work queues, socket storage, and thread stacks. Add
compile-time size checks and runtime high-water, overflow, and explicit drop
accounting for bounded queues. Preserve allocation-free protocol, packet,
timer, and transport hot paths unless a later bounded allocator is introduced
with an explicit global budget.

Replace manual platform mutex lock/unlock pairs with an RAII lock guard and
document the lock order, lock-required methods, and worker execution contexts.
Automate target stack-usage inspection with compiler stack-usage output so the
known cumulative callback chains are checked in addition to the existing 8 KiB
per-frame guard. Add reproducible ELF/NSO and `text`, `data`, and `bss` delta
reporting against a named baseline.

The completed local implementation centralizes peer, packet, effect, pending
request, timer, workqueue, socket, scratch, arena, and thread-stack capacities
in `common/include/wgnx/resource_budget.hpp`. Compile-time layout ceilings guard
the peer registry, peer runtime, packet records and queues, effect batch,
pending request owners, scheduler, dispatcher, receive pump, composed daemon,
socket arena, timer manager, and workqueue pool.

Packet queues retain reject-new overflow semantics and expose a derived drop
total. Endpoint and UDP-rebind single-slot owners expose admission,
replacement, consumption, cancellation, depth, and high-water statistics.
Endpoint replacement is a distinct closed result. Ordered workqueues have
per-lane pending capacities and expose queued, rerun, coalesced,
capacity-exhausted, and unavailable outcomes plus pressure and completion
statistics. Their admission policy has deterministic host coverage.

All remaining manual runtime and work/timer backend lock pairs use scoped lock
ownership. The lock hierarchy, lock-required methods, and worker contexts are
specified in `docs/runtime-resource-budgets.md`. Compiler stack-usage output is
retained and `tools/check_stack_usage.py` checks every target frame plus four
known cumulative callback chains. `tools/report_footprint.py` reports target
image deltas against the named corrected Chunk 13 baseline and enforces
absolute static-image, NSO, and NSP ceilings. Both checks are available through
`make -C sysmodule resource-report`.

**Definition of done:** every bounded queue exposes capacity pressure and a
drop disposition; lock release cannot be skipped by an early return; known
worker chains fit their assigned stacks with documented margin; static and
binary footprint regressions are reported automatically; path-transition and
long-lived real-peer regressions pass.

### Chunk 15: Establish Maintenance Gates

**Status:** Corrective lock, timer-policy, peer-ownership, persistence, and
host-supported composition/failure hardening are locally complete. Logging now
uses a bounded in-memory producer and explicit post-lock flushing, so
state-owner paths do not perform debug or filesystem I/O. The 35-case host
suite exercises the production iterative effect drain with multi-batch
completion, cancelled resolver work and stale shutdown completion, resolver
and UDP-open failure, and deactivated pending rebind/timer work. Horizon-bound
composition, fuzzing, permissive-host ThreadSanitizer execution, and the
remaining corrective on-device matrix cases remain pending. Repeated
connections and requester traffic have passed prolonged on-device validation.

Split large implementation and test translation units along existing cohesive
behavior without creating new state owners. In particular, separate
`PeerRuntime` activation, outbound, inbound, timer, and projection
implementations while retaining one class and one ownership boundary; split
host tests by protocol and runtime subsystem.

Add host fuzz targets for configuration and endpoint parsing, WireGuard message
admission, and inner-IP validation. Add deterministic platform-failure
injection for resolution, socket open, send, receive, timer scheduling, and
persistence. Establish project-owned formatting and first-party warning/static
analysis profiles, excluding vendored Atmosphere and Monocypher sources. Stage
additional warnings so existing diagnostics are reviewed rather than hidden by
broad suppressions.

**Definition of done:** source and test files follow subsystem boundaries;
parsers and hostile byte boundaries run under sanitizer-backed fuzz harnesses;
startup, steady-state, and teardown platform failures have deterministic
coverage; formatting, warnings, tests, sanitizers, stack budgets, target build,
and footprint reporting form one documented local verification command; the
final focused on-device regression passes without IPC or runtime behavior
changes.

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
locals out of unrelated effects. The corrected target passed a sustained
real-peer session with repeated packet traffic and both local and
peer-initiated session rotation.

Every chunk must pass:

- the devkitA64/Atmosphere target build
- all deterministic host tests
- ASan/UBSan host tests
- `git diff --check`
- review that `common/include/wgnx/protocol.hpp` and the CMIF contract remain
  unchanged unless an API change is intentional

The current local gate contains 35 deterministic host cases, the same 35 cases
under ASan/UBSan, the devkitA64 target build, the 8 KiB frame guard, and
`git diff --check`. Chunk 14 adds cumulative stack-chain and named-baseline
footprint gates. IPC API v4 and `common/include/wgnx/protocol.hpp` are unchanged.

## Footprint Comparison

The target was rebuilt with the same toolchain and linked Atmosphere library at
three points. GNU `size` reports loadable code/read-only data as `text`, writable
initialized storage as `data`, and zero-initialized static storage as `bss`.
The sum is a static image indicator, not total Horizon process memory: thread
stacks, allocator state, service sessions, and runtime mappings require an
on-device measurement.

| Build | Text | Data | BSS | Static total | NSO |
| --- | ---: | ---: | ---: | ---: | ---: |
| Pre-refactor `862ef32` | 282,258 | 205,608 | 504,016 | 991,882 | 192,616 |
| After Chunk 8 `6650af9` | 295,330 | 242,600 | 508,112 | 1,046,042 | 202,431 |
| After Chunk 10 | 295,722 | 50,088 | 712,912 | 1,058,722 | 201,824 |
| After Chunk 11 | 296,714 | 50,088 | 712,912 | 1,059,714 | 202,979 |
| After Chunk 12 | 304,960 | 50,776 | 713,304 | 1,069,040 | 206,979 |
| Chunk 13 receive contract | 304,992 | 50,776 | 713,304 | 1,069,072 | 207,141 |
| After Chunk 13 correction | 305,152 | 50,776 | 713,304 | 1,069,232 | 207,203 |
| Chunk 14 local | 306,160 | 50,776 | 713,304 | 1,070,240 | 208,322 |
| Post-Chunk 14 corrective current | 308,160 | 50,776 | 721,496 | 1,080,432 | 209,777 |

The data-to-BSS shift after Chunk 8 is caused primarily by composing prior
independent globals into the zero-initialized `DaemonRuntime`; compare
`data + bss`, not either column alone. Chunks 0 through 10 add 66,840 bytes of
static image footprint over `862ef32`. Chunks 9 and 10 add 12,680 bytes over
Chunk 8, while the compressed NSO decreases by 607 bytes. The fixed 304 KiB BSD
socket arena, 96 KiB workqueue-slot pool, and 16 KiB main-thread stack are
unchanged. After Chunk 10 the composed daemon object is 209,392 bytes,
replacing the separate peer state, packet channel, scheduler, dispatcher,
resolver, and receive scratch globals.

Chunk 12 adds 9,326 bytes of static image footprint and 4,000 bytes to the
compressed NSO over Chunk 11. Most of that cost is executable code from making
the concrete completion bridges externally defined component methods rather
than anonymous-daemon procedures. The composed daemon object grows by 160 bytes
to 209,552 bytes: the existing receive scratch and effect batch move into
`EncryptedReceivePump`, while the pump and executor add their explicit
dependency references. No queue, packet, socket-arena, or thread-stack capacity
increases.

The first Chunk 13 receive-contract slice adds 32 bytes to the static image and
162 bytes to the compressed NSO. Returning the diagnostic result by value grows
the receive-loop frame from 144 to 208 bytes; the UDP receive adapter remains
192 bytes and the generation-checked failure completion is 4,752 bytes. The
failure completion starts only after the adapter returns, so these frames do
not accumulate.

The corrected Chunk 13 contract work adds 160 bytes to the static image and
62 bytes to the compressed NSO over the receive-contract slice; initialized
data and BSS are unchanged. Generated target frames remain within the proven
shape: 208 bytes for receive scheduling, 2,752 bytes for receive commit,
4,752 bytes for receive failure publication, 16 bytes for coordinator dispatch,
2,560 bytes for bind opening, 4,064 bytes for datagram send, and
4,448 bytes for effect execution.

The first Chunk 13 device activation overflowed the 16 KiB resolver worker
during handshake-transition logging. The failure chain was endpoint resolution
-> effect execution -> UDP bind completion -> coordinator dispatch -> peer bind
handling -> handshake creation -> logging. The new event-budget assertion had
changed coordinator dispatch from a direct return into a named `EffectBatch`,
materializing another 2,240-byte frame in that already constrained chain.
Budget validation now runs in `PeerRuntime::Handle` after timer-effect
finalization, where the returned batch already exists, and coordinator dispatch
again uses a direct return. Target disassembly confirms its frame is 16 bytes
while the peer handler remains 80 bytes, removing 2,224 bytes from the crashing
chain without weakening the effect-count invariant. The corrected build then
sustained one real-peer connection for more than 15 minutes and completed
several requester round trips without instability, satisfying the focused
Chunk 13 device regression.

Chunk 14 adds 1,008 bytes to the static image and 1,119 bytes to the compressed
NSO over the corrected Chunk 13 baseline. Initialized data and BSS are
unchanged: queue statistics preserve the fixed 96 KiB workqueue pool and the
small pending-slot accounting growth is absorbed by existing section
alignment. The composed daemon is 209,664 bytes and the current NSP is 209,382
bytes.

The current post-Chunk 14 corrective build reports 645 target functions, all
within the 8 KiB per-frame limit. The platform-neutral iterative drain is an
explicit 4,464-byte frame and is included in every executor chain. The
conservative resolver -> activation -> handshake -> logging chain totals
13,840 bytes and retains 2,544 bytes on its 16 KiB worker. Receive commit,
generated send, and failure-publication chains total 7,680, 9,648, and 10,336
bytes, retaining 8,704, 6,736, and 6,048 bytes.
These sums include explicitly configured nested frames and intentionally leave
unmeasured ABI/runtime overhead inside the reported margin.

The corrective pass currently adds 11,264 bytes of static image and 2,751 bytes
of compressed NSO over the corrected Chunk 13 baseline. Initialized data is
unchanged; BSS increases by 8 KiB for the bounded diagnostic producer queue.
The resulting NSP is 211,014 bytes. The remaining code growth covers post-lock
persistence, debug-timer effects, peer-owned deadline derivation, the closed
`PeerRegistry` ownership interface, and the platform-neutral effect drain; it
does not add a packet, queue, or stack capacity.

Run focused on-device regressions after chunks 4, 5, 6, 7, 10, 12, 13, 14, and 15.
At minimum, these runs should cover tunnel activation against a known-good
peer, repeated requester round trips under one continuously active sysmodule,
clean teardown, and the path-outage scenario applicable to the migrated
lifecycle. Chunk 12 specifically revalidates activation and encrypted receive
execution; Chunk 13 revalidates typed identity conversion and packet ownership
across repeated requester processes; Chunk 14 additionally requires a
long-lived session and network-path transition; Chunk 15 is the final refactor
acceptance run.

## Completion Criteria

The runtime refactor is complete when:

- source-file boundaries correspond to state and lifecycle ownership
- `DaemonRuntime` is a small facade rather than the implementation of every
  subsystem
- one peer's complete activation, handshake, transport, timer, recovery, and
  teardown lifecycle can be driven deterministically through production event
  handlers
- peer and generation identities cannot be mixed accidentally, asynchronous
  work cannot retain borrowed packet storage, and bounded effect insertion
  cannot fail silently
- stack, static-memory, queue-capacity, and binary-size budgets are explicit and
  reproducibly checked
- Horizon services can be substituted by host fakes without reproducing daemon
  policy in tests
- the existing real-peer and development packet-API behavior remains intact
- the resulting boundaries can accept later Horizon system-integration work
  without routing that work through another global runtime module
