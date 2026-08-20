# Protocol Testing

WireGuard-NX separates deterministic protocol validation from final Horizon interoperability testing.
State-machine work should fail on the development host before an on-device run is needed.

## Running The Host Suite

From the repository root:

```sh
make -C sysmodule test
```

This host-only goal does not require `DEVKITPRO`, devkitA64, libnx, or the Atmosphere submodule.
Run the same sources with AddressSanitizer and UndefinedBehaviorSanitizer using:

```sh
make -C sysmodule test-sanitize
```

The runner reports every case by name and emits the failed expression, source location, and protocol-state detail where available.
A nonzero exit status means at least one case failed.

## Unified Local Verification

Run the complete pre-device gate with:

```sh
make -C sysmodule verify
```

This command checks the repository-owned formatting profile, cppcheck's warning/performance/portability analysis over first-party sysmodule, host-test, and fuzz-harness sources, the stricter host warning profile, deterministic tests, ASan/UBSan, the target build, stack-chain budget, footprint report, and both staged and unstaged `git diff --check` output.
It intentionally excludes the vendored Atmosphere libraries, Monocypher implementation, and pinned BLAKE2 reference implementation.

`verify` requires `DEVKITPRO`, Python 3, `clang-format`, and `cppcheck` in addition to the normal target build prerequisites.
Tool paths can be overridden with `CLANG_FORMAT=/path/to/clang-format` and `CPPCHECK=/path/to/cppcheck`.

ThreadSanitizer remains an optional gate:

```sh
make -C sysmodule test-tsan
```

Run it only on a host/compiler combination with a supported TSan runtime; it is deliberately not part of `verify`.

## Fuzzing Parsers

Parser fuzzing is host-only and requires Clang with libFuzzer and AddressSanitizer/UndefinedBehaviorSanitizer support.
Build the three targets with:

```sh
make -C sysmodule fuzz
```

Run each target against its versioned seed corpus for a bounded local pass:

```sh
make -C sysmodule fuzz-run FUZZ_SECONDS=60
```

`fuzz-run` applies the supplied duration independently to configuration and endpoint parsing, WireGuard message admission, and inner IPv4/IPv6 validation.
The default is 30 seconds per target.
The configuration seeds are readable versioned text files under `wg-sysmodule/test/fuzz/corpus/config_endpoint/`.
Message and inner-IP seeds are escaped byte strings in `wg-sysmodule/test/fuzz/fuzz_seed_data.hpp`; `fuzz-run` materializes them beneath `wg-sysmodule/out/fuzz/corpus/` for libFuzzer.
This keeps opaque binary inputs out of the source tree.
The input roots used at runtime are:

- `wg-sysmodule/test/fuzz/corpus/config_endpoint/`
- `wg-sysmodule/out/fuzz/corpus/message_admission/`
- `wg-sysmodule/out/fuzz/corpus/inner_ip/`

Use `FUZZ_CXX=/path/to/clang++` when the required Clang is not the default compiler.
Fuzzing is intentionally outside `make verify`: execution time is nondeterministic, while CI can invoke `fuzz-run` with an explicit budget.
Represent minimized non-text crashing inputs as escaped seed strings in `fuzz_seed_data.hpp`; plain-text configuration examples belong in the versioned configuration corpus.
Add a deterministic regression before accepting a parser correction.

## Scripted Platform Failures

The host suite includes a scripted platform adapter that consumes production runtime effects and drives the corresponding completion events.
`RuntimeCoordinator` remains the production state owner while tests defer and fail endpoint resolution, UDP open/send/receive work, protocol timer delivery, and autostart persistence deterministically.
This supplies cancellation and stale-completion coverage without this composed test assembling completion events directly.

## Deterministic Boundary

The host target links the production protocol sources against controlled test adapters:

- monotonic time changes only when a test changes it
- wall-clock time is controlled independently for TAI64N timestamps
- random bytes come from a resettable, project-defined deterministic stream
- serialized datagrams cross an in-memory bounded link instead of UDP
- timer tests inspect typed absolute deadlines and generation-safe ownership without an asynchronous worker thread
- peer-controller tests apply closed construction and transport outcomes to the production queue mutations and drive the complete retry-exhaustion and later-recovery workflow
- packet-channel tests cover PID ownership transfer, receive-queue clearing, and monotonic packet IDs

The deterministic runtime records random-byte consumption so a change in the handshake's external inputs is observable even when the resulting packet still passes cryptographic validation.

The in-memory link is intentionally a datagram boundary.
Handshake initiation, handshake response, and transport-data messages are serialized into bytes and parsed again by the receiving peer.
Tests must not transfer message structs or key material directly between peers.

## Protocol Model

The protocol core uses explicit ownership boundaries rather than passing the platform UDP descriptor through handshake and transport code:

- parsers borrow immutable wire bytes through `std::span<const std::uint8_t>`
- serializers borrow mutable output storage through `std::span<std::uint8_t>`
- fixed-size wire fields and cryptographic material use `std::array`
- checked readers and writers reject insufficient input or output before a field is accessed
- a keypair owns its establishment state, indices, birth time, session keys, send counter, and receive replay window as one coherent object
- successful transport serialization consumes its send counter before socket I/O, preventing nonce reuse when the later UDP send fails
- keypair send and receive capability is evaluated against the upstream `RejectAfterTime` and `RejectAfterMessages` hard limits
- replay state uses wireguard-go's 128-block, 8,128-packet backtrack window
- outbound inner packets are staged in a bounded peer-owned queue while no send-capable keypair exists; session derivation makes that queue sendable
- protocol monotonic time points, elapsed durations, and timer deadlines are distinct types; conversion to Horizon jiffies remains at the platform edge
- inner-packet queues have compile-time capacity, reject-new overflow behavior, and disposition counters whose totals preserve depth accounting
- sensitive protocol owners are move-only and clear themselves on destruction

The legacy self-tests use adapters local to the host test translation unit.
Production protocol headers do not retain overloads for the removed nullable packet-buffer API.

## Deterministic Coverage

The protocol suite currently verifies:

- identical clock and random inputs produce an identical initiation packet
- the initiator and responder traverse the expected handshake states
- both peers derive reciprocal sending and receiving keys at the controlled key-creation time
- encrypted transport data succeeds in both directions
- send and receive counters advance as expected
- replayed transport packets are rejected
- loss, delayed reordering, malformed transport data, authentication failure, and replay preserve independent receiver state: only authenticated, non-replayed packets commit replay-window advancement
- an old authenticated datagram delayed across an initiator key rotation is accepted once through the retained previous keypair, while its replay remains isolated from the replacement session
- timer intent can be scheduled, replaced, canceled individually, and canceled as a group
- every truncated handshake-initiation size is rejected before parsing
- fixed-size handshake packets reject trailing bytes and undersized output storage
- transport headers accept checked variable-size packets but reject undersized headers
- keypair establishment, age evaluation, reset, and secret clearing are observable without UI or runtime state
- bounded queue overflow policy and statistics are deterministic
- clear and removal dispositions preserve `pushed - popped == depth`
- the upstream replay-window boundary accepts 8,128 counters of reordering and rejects the next older counter
- timer rearming, cancellation, activation replacement, and retry-sequence replacement invalidate stale action tokens
- fake construction and UDP outcomes exercise production queue-retirement policy through the platform-independent peer controller
- the exact hard time and counter rejection boundaries prevent transport serialization without consuming or reusing a nonce
- traffic submitted without a keypair remains staged across a deterministic handshake and is sent after session derivation
- traffic submitted after key expiry remains staged until replacement key derivation through a second serialized handshake, including initiator current/previous rotation and responder next-key confirmation
- the peer staging queue rejects new traffic at capacity and records overflow
- every timed handshake retry replaces both ephemeral material and sender index
- retry exhaustion occurs at the upstream send-attempt boundary, drops staged work, and permits later traffic to begin a new sequence
- stale key-material cleanup clears sessions and handshake secrets while preserving configured identity and reusable peer state

The previous message, primitive, and core self-tests remain in the host suite as legacy regression cases.
They live under `wg-sysmodule/test/host` and are no longer linked into or executed by the production sysmodule.

## What Host Tests Do Not Prove

The protocol suite does not emulate Horizon service behavior, BSD socket lifetime, NIFM, Atmosphere work queues, or real timer-thread scheduling.
Those belong to platform-adapter and on-device integration tests.
The host-tested production controller defines retry transitions, timer identity, and queue mutation; the Horizon dispatcher still needs on-device validation that its synchronous cancellation and token capture behave correctly under real thread scheduling.

## On-Device Gate

After a protocol change passes on the host:

1. Build and install matching sysmodule and requester binaries.
2. Establish a tunnel with the known-good peer.
3. Run the requester at least three times while one sysmodule instance remains active.
4. Confirm a bidirectional inner IPv4/UDP echo round trip and retained peer responsiveness.
5. Retain sysmodule and requester logs for comparison with the host transition expectations.

This real-peer round trip is the final validation layer for protocol-refactor milestones.
Host tests are the fast protocol gate, not a replacement for interoperability testing.

## Milestone 7 Interoperability Gate

The host suite establishes protocol invariants but does not make two independent WireGuard implementations interoperate.
Milestone 7 uses it as the mandatory first gate, then compares behavior with checked-out public `wireguard-go` and BoringTun references.

The deterministic `protocol.faulted-datagram-lifecycle` case uses serialized datagrams and verifies a loss/delay/reordering sequence, an authenticated-data tag failure, a truncated packet, and a replay.
This specifically protects the upstream replay invariant that a rejected packet never advances receive state. `protocol.key-rotation-delayed-datagram` then retains an authenticated packet from the old session, completes an initiator rekey, promotes the responder replacement keypair through new traffic, and accepts the retained packet once through the initiator's previous-keypair slot.
Its replay must remain rejected without mutating replacement-session state.
Finally, `runtime.repeated-lifecycle-bounds` executes sixteen complete activation, initial-handshake-send, and teardown cycles through the production runtime event/effect boundary.
Every cycle must retire its socket, protocol instance, timer ownership, resolver work, transmit work, and stale receive work.

For each target build, validate a real peer in this order:

1. Establish a tunnel and complete repeated requester round trips without restarting the peer or sysmodule.
2. Induce a bounded interruption, restore the path, and verify a fresh authenticated round trip without configuration replacement.
3. Exercise a peer rekey or reconnect while retaining traffic flow.
   Record endpoint, handshake, key-generation, and packet-queue transitions.
4. Repeat with `wireguard-go` and BoringTun peer implementations where the test environment permits.
   Compare only observable protocol outcomes, not scheduler timing or platform-specific socket behavior.

The deterministic responder-cookie test covers the local cookie wire contract, MAC2 admission, the bounded per-source rate limit, and the documented arrival-trigger adaptation.
Multi-peer routing and full transparent Horizon traffic integration remain outside this milestone.
Any behavior that differs from upstream must be recorded as a deliberate Horizon-specific deviation before it is relied upon by later integration work.

### Current Validation Boundary

The local part of this gate is complete: serialized datagram-fault handling, previous-keypair delayed traffic, and bounded repeated lifecycle retirement are deterministic host tests.
The host test suite, ASan/UBSan run, target build, stack gate, and resource gate pass.
Available real-peer requester and Wi-Fi/flight-mode recovery tests are also stable on device.

This is not equivalent to the full Milestone 7 goal.
The environment does not currently provide independently deployed `wireguard-go` and BoringTun peers, nor controlled prolonged loss/delay/duplicate/malformed fault injection or the complete physical-interface matrix.
Those tests remain deferred external validation.
Their absence must not be interpreted as an accepted protocol deviation or as evidence of full independent-implementation interoperability.
