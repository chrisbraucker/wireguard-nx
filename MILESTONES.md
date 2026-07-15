# WireGuard-NX Implementation Roadmap

This document guides the next development phase: bring the userspace
WireGuard implementation to protocol and peer-lifecycle parity with upstream
before expanding transparent Horizon integration.

The completed proof-of-concept roadmap is retained in
[POC_MILESTONES.md](POC_MILESTONES.md). It records how the project reached its
current state and is not the implementation plan for this phase.

## Refactor Approach

This roadmap treats the current implementation as a validated proof of concept,
not as a compatibility contract. Until this refactor establishes a stable
foundation, preserving existing internal APIs, source layout, development IPC
shapes, or incidental runtime behavior is subordinate to producing a coherent,
testable, and maintainable implementation.

In practical terms, work in these milestones may:

- rename, move, split, or remove types, functions, and source files
- replace internal interfaces and data representations rather than layer new
  behavior over weak ownership or lifecycle boundaries
- update in-tree clients together with a development IPC change instead of
  retaining compatibility adapters
- remove obsolete proof-of-concept paths when their replacement is covered and
  demonstrably working

The compatibility exception is the behavior that defines the product: WireGuard
protocol correctness and interoperability with upstream peers must remain
intact. Each milestone should also end with its deterministic tests passing and
the applicable on-device vertical slice working. Development IPC changes must
continue to increment the API version so incompatible binaries fail explicitly
rather than communicating under a misleading shared version.

This approach accepts larger diffs, temporary API instability, coordinated
changes across components, and reduced usefulness of out-of-tree consumers
during development. In return, it avoids preserving accidental complexity,
allows ownership and lifecycle boundaries to be corrected at their source, and
reduces the long-term cost and risk of building upstream lifecycle behavior and
Horizon integration on the proof-of-concept structure. Compatibility policy and
security guarantees must be defined before the service is presented as stable
or public.

## Current Baseline

The sysmodule can establish a tunnel with a real WireGuard peer and exchange
synthetic inner IPv4 packets through its development IPC API. Confirmed traffic
includes ICMP, HTTP, and UDP request/response flows.

The remaining protocol gap is primarily long-lived peer behavior rather than
basic cryptography or transport encryption. In particular, peer recovery after
a prolonged uplink outage does not yet follow upstream keypair, packet-staging,
handshake-retry, and timer semantics.

Transparent routing of ordinary Horizon application traffic remains the
product goal. Deeper system integration is deferred until the userspace tunnel
can recover reliably without peer reactivation.

## Target Architecture

Keep these responsibilities distinct as the implementation evolves:

- **Protocol core:** peers, handshakes, keypairs, replay protection, packet
  staging, and protocol timers.
- **Transport:** UDP binding lifetime, endpoint selection, send/receive,
  rebinding, and endpoint roaming.
- **Runtime:** clocks, randomness, work queues, synchronization, logging, and
  bounded memory resources.
- **Horizon integration:** NIFM observation, IPC services, and the eventual
  system-owned packet path.
- **Development packet API:** controlled inner-packet submission and reception
  used for protocol validation.

`wireguard-go` is the primary behavioral reference because its userspace state
machine maps cleanly to this project. BoringTun is a useful independent
userspace reference. Platform-specific device plumbing from either project is
not part of the parity target.

## Implementation Guidelines

### Preserve Working Vertical Slices

- Refactor incrementally instead of replacing the engine in one operation.
- Keep handshake and packet round trips working at each milestone.
- Separate behavioral changes from broad mechanical cleanup where practical.
- Add or improve tests before changing state transitions that are already
  known to work on-device.

### Modernize Ownership Boundaries

- Use `std::span` for borrowed packet, key, and serialization buffers.
- Use `std::array` for fixed-size protocol and cryptographic material.
- Use owning containers only where ownership is explicit; use `std::vector`
  for genuinely variable storage outside allocation-sensitive hot paths.
- Make packet queues bounded and define their overflow policy explicitly.
- Prefer RAII for sockets, sessions, locks, timers, and sensitive-memory
  cleanup.
- Prefer scoped enums, typed state structures, `std::chrono` durations, and
  explicit result types over integer states, sentinel values, and mixed time
  units.
- Replace unchecked pointer arithmetic with checked parsing and serialization
  helpers.
- Make ownership-bearing protocol objects move-only where copying would be
  ambiguous or unsafe.

Modernization should follow the ownership boundary being changed. Untouched
code does not need to be converted merely to make a milestone look complete.

### Respect The Target Runtime

C++23 availability does not remove Horizon's memory and runtime constraints.
New code must remain compatible with the project's devkitA64, libnx, and
Atmosphere toolchain configuration. Do not require exceptions, RTTI, unbounded
allocation, or standard-library facilities that the target runtime cannot
support predictably.

### Treat Upstream Behavior As The Specification

- Match WireGuard protocol constants and timer relationships unless a Horizon
  constraint requires a documented deviation.
- Drive timers from authenticated send/receive and handshake events as
  upstream does, not from a synthetic connected flag.
- Keep peer configuration, UDP binding state, handshake state, and keypair
  state as separate lifecycles.
- Document intentional deviations next to the affected behavior and in the
  relevant design note.

## Milestone 1: Deterministic Protocol Test Foundation

**Status:** Host foundation implemented; real-peer on-device regression confirmed.

### Goal

Make protocol-core behavior testable without requiring an on-device run for
every state-machine change.

### Scope

- isolate deterministic clock, randomness, transport, and work scheduling
  inputs needed by the protocol core
- cover the currently working handshake and transport-data path
- add state-transition tests for key creation, packet counters, and basic timer
  scheduling
- retain on-device interoperability tests as the final validation layer

### Definition Of Done

- protocol tests run on the development host with deterministic inputs
- successful handshake and bidirectional transport-data behavior are covered
- failures identify the peer state or transition that diverged
- the existing real-peer on-device round trip still succeeds

## Milestone 2: Typed Protocol And Ownership Model

**Status:** Implementation complete; real-peer on-device regression confirmed.

### Goal

Establish maintainable C++ boundaries for packets, keypairs, peer state, and
timers before adding more lifecycle complexity.

### Scope

- introduce typed, checked packet parsing and serialization boundaries
- make packet and key-material ownership explicit
- represent keypair birth time, validity, counters, and replay state directly
- replace mixed timer units and loosely coupled state fields in touched paths
- keep queues bounded and observable

### Definition Of Done

- protocol code no longer relies on ambiguous raw-buffer ownership in the
  handshake and transport-data paths
- malformed or undersized messages fail before field access
- keypair age and validity can be evaluated without consulting UI/runtime state
- all Milestone 1 tests and the on-device round trip remain passing

## Milestone 3: Key Validity And Outbound Packet Staging

**Status:** Implementation complete; real-peer on-device regression confirmed.

### Goal

Stop using expired keypairs and preserve outbound work while a usable session
is being established.

### Scope

- enforce upstream send-counter and `RejectAfterTime` limits
- stage outbound packets when no usable current keypair exists
- initiate a fresh handshake when staged traffic requires a session
- release staged packets after successful key derivation
- define bounded-queue overflow and peer-deactivation behavior

### Definition Of Done

- no transport packet is emitted with an expired or exhausted keypair
- outbound traffic without a usable keypair causes a handshake initiation
- staged traffic is sent after the handshake succeeds
- queue overflow and peer shutdown cannot leak memory or retain stale traffic
- a test covers outbound submission after the previous keypair has expired

## Milestone 4: Handshake Retry And Recovery Lifecycle

**Status:** Implementation and production-controller host coverage complete;
outage-recovery on-device validation pending.

### Goal

Recover from a silent path outage without restarting the peer.

### Scope

- align retransmission timing and retry duration with upstream behavior
- distinguish one retry sequence from a later, newly triggered handshake
- permit later outbound traffic to restart handshaking after an exhausted
  attempt window
- schedule stale ephemeral/key-material cleanup as upstream requires
- keep UDP binding replacement independent from cryptographic recovery
- keep CMIF adaptation, daemon state, Horizon dispatch, UDP binding ownership,
  packet-channel ownership, and protocol lifecycle policy at explicit
  operation-level boundaries

### Definition Of Done

- an unanswered handshake stops retrying according to the configured upstream
  limits without leaving an impossible peer state
- later outbound traffic can begin a new handshake attempt
- the uplink-loss test exceeding `RejectAfterTime` recovers after connectivity
  returns without peer deactivation/reactivation
- manual binding replacement is not required when the existing socket remains
  usable
- deterministic coverage drives the production controller through retry
  exhaustion and later session recovery rather than reproducing its policy in
  a test-only model

## Milestone 5: Authenticated-Activity Timers

### Goal

Bring rekey, keepalive, liveness, and cleanup scheduling in line with upstream
WireGuard event semantics.

### Scope

- implement timer hooks for authenticated packet sent and received events
- implement handshake completion and session-derived timer transitions
- align rekey-after-time, rekey-after-messages, keepalive, and persistent
  keepalive behavior
- cancel and reschedule timers coherently across peer and keypair transitions

### Definition Of Done

- timer behavior is driven by protocol events rather than polling or a broad
  active-state check
- rekey occurs by both age and message-count thresholds
- keepalive behavior does not create duplicate or runaway timer work
- deterministic tests cover cancellation, rescheduling, and stale callbacks

## Milestone 6: Endpoint And Transport Recovery

### Goal

Make peer protocol state survive ordinary UDP path and endpoint changes.

### Scope

- learn endpoint changes only from authenticated peer traffic
- preserve protocol state across generation-safe UDP rebinding
- recover from surfaced BSD send/receive failures without making them terminal
- validate Wi-Fi loss, uplink-only loss, and Wi-Fi/Ethernet transitions
- retain NIFM as path information, not as proof of peer reachability

### Definition Of Done

- authenticated roaming updates the endpoint and subsequent sends use it
- stale socket-generation results cannot mutate current transport state
- temporary transport failure does not discard peer configuration or valid
  protocol state
- the transition test matrix recovers without OS stalls or peer restart

## Milestone 7: Interoperability And Lifecycle Hardening

### Goal

Establish a defensible userspace WireGuard conformance floor before system
integration increases concurrency and traffic volume.

### Scope

- compare observable behavior against `wireguard-go` and BoringTun peers
- exercise packet loss, delayed responses, duplicate packets, replay attempts,
  malformed messages, key rotation, and prolonged silence
- validate bounded memory use and teardown under repeated peer lifecycles
- remove temporary diagnostics or workarounds that alter protocol behavior

### Definition Of Done

- repeated long-running tests do not require peer or sysmodule restart
- malformed and replayed traffic is rejected without corrupting peer state
- packet queues, keypairs, and timers remain bounded across repeated outages
- documented behavior matches upstream or records a justified Horizon-specific
  deviation
- the on-device outage and network-transition matrix passes consistently

## Milestone 8: Cryptographic And Parsing Hardening

### Goal

Modernize and audit the remaining legacy cryptographic, packet-parsing,
serialization, and sensitive-memory code after lifecycle behavior has a stable
test baseline.

### Scope

- replace remaining ambiguous raw buffers and C-style ownership
- use fixed-size types and `std::span` consistently at cryptographic and packet
  boundaries
- centralize checked message parsing and serialization
- review secret zeroization, copying, comparison, and lifetime
- remove obsolete compatibility code and duplicated helpers
- validate behavior against protocol test vectors and interoperability tests
- prefer typed wrappers around proven cryptographic primitives rather than
  rewriting the primitives themselves
- audit the entirety of `sysmodule/src/wireguard/crypto/primitives.cpp`, not
  only the routines changed by the lifecycle refactor, including primitive
  implementations, state transitions, parameter validation, return-value
  handling, and sensitive-memory behavior
- establish and document the provenance, version, license compatibility, and
  expected algorithm variant for every primitive implementation; in
  particular, reconcile the local BLAKE2s implementation with a traceable,
  established upstream implementation rather than treating project-local code
  as implicitly trusted
- independently verify primitive behavior with authoritative vectors and
  differential tests covering keyed and unkeyed operation, supported digest
  sizes, incremental updates, block boundaries, malformed parameters, and
  WireGuard-specific hash, MAC, and KDF constructions

### Definition Of Done

- all externally supplied packets are validated before field access
- cryptographic material has explicit ownership and cleanup semantics
- every implementation in `wireguard/crypto/primitives.cpp` has recorded
  provenance or an explicit justification for retention, and the complete file
  has been reviewed against its public API and all production call sites
- the primitive test suite covers normal operation, boundary conditions, and
  rejected API misuse using results independent of the implementation under
  test
- the established protocol lifecycle suite detects no behavioral regressions
- handshake and transport outputs still match known vectors and interoperate
  with upstream peers
- remaining low-level C-style code is removed or documented as intentional

## Milestone 9: Resume Horizon Integration

### Goal

Use the stabilized tunnel as the data plane for transparent system traffic.

### Scope

- return to the system-owned packet ingress/egress research in
  `nx-reversing.git`
- select the narrowest viable transparent traffic class
- keep the development packet API as a diagnostic boundary
- distinguish integration failures from protocol and transport failures using
  the tests and state visibility established above

### Definition Of Done

- a defined class of ordinary application traffic traverses the tunnel without
  app-specific WireGuard IPC calls
- protocol lifecycle tests remain passing under the additional traffic and IPC
  load
- integration limitations and the next expansion target are documented

## Immediate Order

Proceed through the milestones consecutively. Milestones 1 and 2 establish the
refactoring foundation; Milestones 3 through 6 deliver the missing upstream
peer lifecycle; Milestone 7 establishes the conformance baseline; and
Milestone 8 hardens the remaining cryptographic and parsing code before
transparent Horizon integration resumes in Milestone 9.

The current validation target is Milestone 4: exhaust one unanswered retry
sequence without making the peer terminal, restore reachability, and confirm
that later outbound traffic starts a new sequence and releases after session
derivation without peer restart or UDP rebinding.
