# WireGuard-NX Implementation Roadmap

This document guides the next development phase: bring the userspace WireGuard implementation to protocol and peer-lifecycle parity with upstream before expanding transparent Horizon integration.

The completed proof-of-concept roadmap is retained in [POC_MILESTONES.md](POC_MILESTONES.md).
It records how the project reached its current state and is not the implementation plan for this phase.

## Refactor Approach

This roadmap treats the current implementation as a validated proof of concept, not as a compatibility contract.
Until this refactor establishes a stable foundation, preserving existing internal APIs, source layout, development IPC shapes, or incidental runtime behavior is subordinate to producing a coherent, testable, and maintainable implementation.

In practical terms, work in these milestones may:

- rename, move, split, or remove types, functions, and source files
- replace internal interfaces and data representations rather than layer new behavior over weak ownership or lifecycle boundaries
- update in-tree clients together with a development IPC change instead of retaining compatibility adapters
- remove obsolete proof-of-concept paths when their replacement is covered and demonstrably working

The compatibility exception is the behavior that defines the product: WireGuard protocol correctness and interoperability with upstream peers must remain intact.
Each milestone should also end with its deterministic tests passing and the applicable on-device vertical slice working.
Development IPC changes must continue to increment the API version so incompatible binaries fail explicitly rather than communicating under a misleading shared version.

This approach accepts larger diffs, temporary API instability, coordinated changes across components, and reduced usefulness of out-of-tree consumers during development.
In return, it avoids preserving accidental complexity, allows ownership and lifecycle boundaries to be corrected at their source, and reduces the long-term cost and risk of building upstream lifecycle behavior and Horizon integration on the proof-of-concept structure.
Compatibility policy and security guarantees must be defined before the service is presented as stable or public.

## Current Baseline

The sysmodule can establish a tunnel with a real WireGuard peer and exchange synthetic inner IPv4 packets through its development IPC API.
Confirmed traffic includes ICMP, HTTP, and UDP request/response flows.

The remaining protocol gap is primarily long-lived peer behavior rather than basic cryptography or transport encryption.
In particular, peer recovery after a prolonged uplink outage does not yet follow upstream keypair, packet-staging, handshake-retry, and timer semantics.

Transparent routing of ordinary Horizon application traffic remains the product goal.
Deeper system integration is deferred until the userspace tunnel can recover reliably without peer reactivation.

## Target Architecture

Keep these responsibilities distinct as the implementation evolves:

- **Protocol core:** peers, handshakes, keypairs, replay protection, packet staging, and protocol timers.
- **Transport:** UDP binding lifetime, endpoint selection, send/receive, rebinding, and endpoint roaming.
- **Runtime:** clocks, randomness, work queues, synchronization, logging, and bounded memory resources.
- **Horizon integration:** NIFM observation, IPC services, and the eventual system-owned packet path.
- **Development packet API:** controlled inner-packet submission and reception used for protocol validation.

`wireguard-go` is the primary behavioral reference because its userspace state machine maps cleanly to this project.
BoringTun is a useful independent userspace reference.
Platform-specific device plumbing from either project is not part of the parity target.

## Implementation Guidelines

### Preserve Working Vertical Slices

- Refactor incrementally instead of replacing the engine in one operation.
- Keep handshake and packet round trips working at each milestone.
- Separate behavioral changes from broad mechanical cleanup where practical.
- Add or improve tests before changing state transitions that are already known to work on-device.

### Modernize Ownership Boundaries

- Use `std::span` for borrowed packet, key, and serialization buffers.
- Use `std::array` for fixed-size protocol and cryptographic material.
- Use owning containers only where ownership is explicit.
  Use `std::vector` for genuinely variable storage outside allocation-sensitive hot paths.
- Make packet queues bounded and define their overflow policy explicitly.
- Prefer RAII for sockets, sessions, locks, timers, and sensitive-memory cleanup.
- Prefer scoped enums, typed state structures, `std::chrono` durations, and explicit result types over integer states, sentinel values, and mixed time units.
- Replace unchecked pointer arithmetic with checked parsing and serialization helpers.
- Make ownership-bearing protocol objects move-only where copying would be ambiguous or unsafe.

Modernization should follow the ownership boundary being changed.
Untouched code does not need to be converted merely to make a milestone look complete.

### Respect The Target Runtime

C++23 availability does not remove Horizon's memory and runtime constraints.
New code must remain compatible with the project's devkitA64, libnx, and Atmosphere toolchain configuration.
Do not require exceptions, RTTI, unbounded allocation, or standard-library facilities that the target runtime cannot support predictably.

### Treat Upstream Behavior As The Specification

- Match WireGuard protocol constants and timer relationships unless a Horizon constraint requires a documented deviation.
- Drive timers from authenticated send/receive and handshake events as upstream does, not from a synthetic connected flag.
- Keep peer configuration, UDP binding state, handshake state, and keypair state as separate lifecycles.
- Document intentional deviations next to the affected behavior and in the relevant design note.

## Milestone 1: Deterministic Protocol Test Foundation

**Status:** Host foundation implemented; real-peer on-device regression confirmed.

### Goal

Make protocol-core behavior testable without requiring an on-device run for every state-machine change.

### Scope

- isolate deterministic clock, randomness, transport, and work scheduling inputs needed by the protocol core
- cover the currently working handshake and transport-data path
- add state-transition tests for key creation, packet counters, and basic timer scheduling
- retain on-device interoperability tests as the final validation layer

### Definition Of Done

- protocol tests run on the development host with deterministic inputs
- successful handshake and bidirectional transport-data behavior are covered
- failures identify the peer state or transition that diverged
- the existing real-peer on-device round trip still succeeds

## Milestone 2: Typed Protocol And Ownership Model

**Status:** Implementation complete; real-peer on-device regression confirmed.

### Goal

Establish maintainable C++ boundaries for packets, keypairs, peer state, and timers before adding more lifecycle complexity.

### Scope

- introduce typed, checked packet parsing and serialization boundaries
- make packet and key-material ownership explicit
- represent keypair birth time, validity, counters, and replay state directly
- replace mixed timer units and loosely coupled state fields in touched paths
- keep queues bounded and observable

### Definition Of Done

- protocol code no longer relies on ambiguous raw-buffer ownership in the handshake and transport-data paths
- malformed or undersized messages fail before field access
- keypair age and validity can be evaluated without consulting UI/runtime state
- all Milestone 1 tests and the on-device round trip remain passing

## Milestone 3: Key Validity And Outbound Packet Staging

**Status:** Implementation complete; real-peer on-device regression confirmed.

### Goal

Stop using expired keypairs and preserve outbound work while a usable session is being established.

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

**Status:** Implementation, production-controller host coverage, and prolonged outage-recovery on-device validation complete.

### Goal

Recover from a silent path outage without restarting the peer.

### Scope

- align retransmission timing and retry duration with upstream behavior
- distinguish one retry sequence from a later, newly triggered handshake
- permit later outbound traffic to restart handshaking after an exhausted attempt window
- schedule stale ephemeral/key-material cleanup as upstream requires
- keep UDP binding replacement independent from cryptographic recovery
- keep CMIF adaptation, daemon state, Horizon dispatch, UDP binding ownership, packet-channel ownership, and protocol lifecycle policy at explicit operation-level boundaries

### Definition Of Done

- an unanswered handshake stops retrying according to the configured upstream limits without leaving an impossible peer state
- later outbound traffic can begin a new handshake attempt
- the uplink-loss test exceeding `RejectAfterTime` recovers after connectivity returns without peer deactivation/reactivation
- manual binding replacement is not required when the existing socket remains usable
- deterministic coverage drives the production controller through retry exhaustion and later session recovery rather than reproducing its policy in a test-only model

## Milestone 5: Authenticated-Activity Timers

**Status:** Host implementation and deterministic regression coverage complete; real-peer on-device validation complete.

### Goal

Bring rekey, keepalive, liveness, and cleanup scheduling in line with upstream WireGuard event semantics.

### Scope

- implement timer hooks for authenticated packet sent and received events
- implement handshake completion and session-derived timer transitions
- align rekey-after-time, rekey-after-messages, keepalive, and persistent keepalive behavior
- cancel and reschedule timers coherently across peer and keypair transitions

### Definition Of Done

- timer behavior is driven by protocol events rather than polling or a broad active-state check
- rekey occurs by both age and message-count thresholds
- keepalive behavior does not create duplicate or runaway timer work
- deterministic tests cover cancellation, rescheduling, and stale callbacks

## Milestone 6: Endpoint And Transport Recovery

**Status:** Authenticated endpoint roaming, generation-safe rebinding, nonterminal BSD failure handling, and the NIFM local-path gate are implemented.
Successful request states `Pending` and `OnHold` now suspend local socket ownership, while `Available` permits normal recovery.
Focused device validation confirms Wi-Fi-to-Wi-Fi recovery, including an intervening flight-mode interval, without peer restart or OS stalls.
The remaining physical-interface and roaming matrix is deferred until suitable test hardware and peer control are available.

### Deferred Validation

- Wi-Fi-to-Ethernet and Ethernet-to-Wi-Fi transitions require a compatible Ethernet adapter.
- A DHCP-less attachment requires a controllable access point or equivalent network setup.
  Prior device observations indicate NIFM reports `Available` only after Layer-3 initialization.
- Authenticated endpoint roaming requires a peer whose authenticated source endpoint can be changed during an active session.
- A peer on the same local segment without Internet uplink remains a useful future confirmation: NIFM may remain `Available`, while WireGuard itself must establish reachability to that local peer.

The observed local-only-network behavior is intentional: NIFM remains `Available` once the attachment has Layer-3 connectivity, but a remote peer outside that network fails through normal WireGuard handshake/recovery policy.
NIFM therefore remains local-path authority only, never proof of remote-peer reachability.

The sysmodule intentionally does not register its UDP socket descriptor with NIFM.
Reverse-engineering and device probes did not establish a conclusive descriptor-registration procedure or a requirement for connection-state observation.
Until that contract is understood and needed for a separate feature, the activation-owned NIFM request remains observation-only and BSD retains complete ownership of the transport socket.

### Goal

Make peer protocol state survive ordinary UDP path and endpoint changes.

### Scope

- learn endpoint changes only from authenticated peer traffic
- preserve protocol state across generation-safe UDP rebinding
- recover from surfaced BSD send/receive failures without making them terminal
- validate Wi-Fi loss, uplink-only loss, and Wi-Fi/Ethernet transitions
- retain NIFM as path information, not as proof of peer reachability
- gate socket ownership on event-backed NIFM local-path availability without polling Internet status or IP configuration

### Definition Of Done

- authenticated roaming updates the endpoint and subsequent sends use it
- stale socket-generation results cannot mutate current transport state
- temporary transport failure does not discard peer configuration or valid protocol state
- the transition test matrix recovers without OS stalls or peer restart
- NIFM `Unavailable` suspends local socket ownership, while `Available` only permits normal WireGuard recovery and cannot establish a peer by itself

## Milestone 7: Interoperability And Lifecycle Hardening

**Status:** Partially complete and externally constrained.
The deterministic conformance floor, bounded repeated-lifecycle coverage, host sanitizer runs, and target resource/stack gates pass.
The suite includes serialized datagram-fault and key-rotation cases covering loss/delay reordering, malformed input, authentication failure, replay-state isolation, and delayed old-session traffic through the previous-keypair slot.
Existing real-peer device regressions are stable, but the independent `wireguard-go`/BoringTun peer matrix and a reproducible prolonged fault-injection device matrix cannot currently be run in the available environment.
This milestone must therefore not yet be described as full interoperability validation.

### Goal

Establish a defensible userspace WireGuard conformance floor before system integration increases concurrency and traffic volume.

### Scope

- compare observable behavior against `wireguard-go` and BoringTun peers
- exercise packet loss, delayed responses, duplicate packets, replay attempts, malformed messages, key rotation, and prolonged silence
- validate bounded memory use and teardown under repeated peer lifecycles
- remove temporary diagnostics or workarounds that alter protocol behavior

### Definition Of Done

- repeated long-running tests do not require peer or sysmodule restart
- malformed and replayed traffic is rejected without corrupting peer state
- packet queues, keypairs, and timers remain bounded across repeated outages
- documented behavior matches upstream or records a justified Horizon-specific deviation
- the on-device outage and network-transition matrix passes consistently

### Current Completion And Remaining Gap

Completed locally:

- deterministic host coverage exercises malformed, unauthenticated, delayed, duplicate, and replayed serialized datagrams without advancing invalid receive state
- a delayed packet from the previous session is accepted exactly once across initiator key rotation, while replacement-session replay state remains isolated
- sixteen production activation, initial-handshake-send, and teardown cycles prove that socket, protocol, timer, resolver, transmit, and stale receive work are retired within their fixed bounds
- host tests, ASan/UBSan, target build, stack gate, and resource gate pass
- real-peer requester regressions and the available Wi-Fi/flight-mode recovery scenarios have remained stable on device

Still required for the milestone goal:

- run the same observable handshake, transport, rekey, and recovery matrix against independently deployed `wireguard-go` and BoringTun peers
- run prolonged device sessions with controlled loss, delay, duplication, malformed input, and outage/recovery injection, retaining logs for each transition
- complete the feasible physical-interface matrix, including Ethernet and roaming cases

The remaining items require independent peer deployments and controlled network/fault-injection facilities.
They are deferred validation, not an implementation workaround or a known protocol divergence.
Milestone 8 may proceed on the established local conformance floor.
Milestone 7 remains open until this external matrix is attested.

## Milestone 8: Cryptographic And Parsing Hardening

### Goal

Modernize and audit the remaining legacy cryptographic, packet-parsing, serialization, and sensitive-memory code after lifecycle behavior has a stable test baseline.

### Current Progress

- BLAKE2s now uses the pinned portable reference C implementation from the upstream BLAKE2 project behind a typed, lifecycle-enforcing C++ wrapper.
  Provenance, license selection, integrity digests, and the vendor refresh process are recorded in `wg-sysmodule/src/wireguard/crypto/third_party/blake2/UPSTREAM.md`.
- The wrapper accepts only byte spans, rejects invalid state transitions and unsupported output/key sizes, and clears retained reference state after use.
- The project-facing crypto façade now exposes fixed-size keys, tags, nonces, and digest arrays plus spans.
  Raw pointer calls are confined to the backend bridge in `primitives.cpp`
  Obsolete block/XOR/Poly1305 production wrappers are internal self-test adapters only.
- WireGuard HMAC/KDF now operates on typed 32-byte Noise values, has no caller-provided copy length, and propagates failures through handshake creation and consumption.
  Scoped sensitive buffers scrub ephemeral DH, transcript, timestamp, cookie, and KDF material on every exit path.
  The handshake initialization cache is a thread-safe function-local static.
- Horizon resolver results now use an endian-aware wire reader/writer in `platform/resolver_serialization.*`, with documented 20.5.0 ABI assumptions, checked record arithmetic, declared-sockaddr-length and family minimums, whole-reply validation before endpoint acceptance, deterministic malformed record coverage, and a libFuzzer target.
  The request serializer has a fixed output type and the parser writes its endpoint by reference, so neither API exposes nullable output pointers or caller-managed wire lengths.
- The primitive suite now includes authoritative keyed/unkeyed BLAKE2s, truncated and block-boundary digest cases, BLAKE2s-HMAC and Noise KDF output vectors, AEAD authentication rejection, and low-order X25519 rejection.
  Authenticated decryption clears its plaintext output on failure, preventing unauthenticated bytes from escaping the primitive boundary.
  Resolver coverage includes IPv4 and IPv6 records plus malformed boundaries.
  libFuzzer writes discoveries to `out/fuzz/`, never the checked-in seed corpus.
  The full host suite, ASan/UBSan, target build, and short fuzz matrix pass locally.
- Monocypher remains the intentional low-level C backend.
  Its provenance, retention rationale, and refresh procedure are recorded in `wg-sysmodule/src/wireguard/crypto/UPSTREAM.md`.
- The full primitive façade, production call-site, and intentional low-level boundary audit is recorded in `docs/crypto-boundaries.md`.
  Vector fixtures and direct backend conformance calls are host-test-only.
  Target `primitives.cpp` now contains only the runtime façade.
- The two source-audit Definition of Done conditions are complete.
  Remaining Milestone 8 work is limited to its focused real-peer device regression, rather than crypto provenance, wrapper ownership, or low-level boundary classification.
- Local validation is complete for the hardening changes.
  A focused real-peer device regression remains required before Milestone 8 can claim its final interoperability definition of done.

### Scope

- replace remaining ambiguous raw buffers and C-style ownership
- use fixed-size types and `std::span` consistently at cryptographic and packet boundaries
- centralize checked message parsing and serialization
- review secret zeroization, copying, comparison, and lifetime
- remove obsolete compatibility code and duplicated helpers
- validate behavior against protocol test vectors and interoperability tests
- prefer typed wrappers around proven cryptographic primitives rather than rewriting the primitives themselves
- audit the entirety of `wg-sysmodule/src/wireguard/crypto/primitives.cpp`, not only the routines changed by the lifecycle refactor, including primitive implementations, state transitions, parameter validation, return-value handling, and sensitive-memory behavior
- establish and document the provenance, version, license compatibility, and expected algorithm variant for every primitive implementation.
  In particular, reconcile the local BLAKE2s implementation with a traceable, established upstream implementation rather than treating project-local code as implicitly trusted
- independently verify primitive behavior with authoritative vectors and differential tests covering keyed and unkeyed operation, supported digest sizes, incremental updates, block boundaries, malformed parameters, and WireGuard-specific hash, MAC, and KDF constructions

### Definition Of Done

- all externally supplied packets are validated before field access
- cryptographic material has explicit ownership and cleanup semantics
- every implementation in `wireguard/crypto/primitives.cpp` has recorded provenance or an explicit justification for retention, and the complete file has been reviewed against its public API and all production call sites
- the primitive test suite covers normal operation, boundary conditions, and rejected API misuse using results independent of the implementation under test
- the established protocol lifecycle suite detects no behavioral regressions
- handshake and transport outputs still match known vectors and interoperate with upstream peers
- remaining low-level C-style code is removed or documented as intentional

## Milestone 9: Resume Horizon Integration

### Goal

Use the stabilized tunnel as the data plane for transparent system traffic.

### Scope

- return to the system-owned packet ingress/egress research in `nx-reversing.git`
- select the narrowest viable transparent traffic class
- keep the development packet API as a diagnostic boundary
- distinguish integration failures from protocol and transport failures using the tests and state visibility established above

### Definition Of Done

- a defined class of ordinary application traffic traverses the tunnel without app-specific WireGuard IPC calls
- protocol lifecycle tests remain passing under the additional traffic and IPC load
- integration limitations and the next expansion target are documented

## Immediate Order

Proceed through the milestones consecutively.
Milestones 1 and 2 establish the refactoring foundation.
Milestones 3 through 6 deliver the missing upstream peer lifecycle.
Milestone 7 establishes the conformance baseline.
And Milestone 8 hardens the remaining cryptographic and parsing code before transparent Horizon integration resumes in Milestone 9.
