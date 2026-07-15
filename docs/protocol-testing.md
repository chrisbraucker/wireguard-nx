# Protocol Testing

WireGuard-NX separates deterministic protocol validation from final Horizon
interoperability testing. State-machine work should fail on the development
host before an on-device run is needed.

## Running The Host Suite

From the repository root:

```sh
make -C sysmodule test
```

This host-only goal does not require `DEVKITPRO`, devkitA64, libnx, or the
Atmosphere submodule. Run the same sources with AddressSanitizer and
UndefinedBehaviorSanitizer using:

```sh
make -C sysmodule test-sanitize
```

The runner reports every case by name and emits the failed expression, source
location, and protocol-state detail where available. A nonzero exit status
means at least one case failed.

## Deterministic Boundary

The host target links the production protocol sources against controlled test
adapters:

- monotonic time changes only when a test changes it
- wall-clock time is controlled independently for TAI64N timestamps
- random bytes come from a resettable, project-defined deterministic stream
- serialized datagrams cross an in-memory bounded link instead of UDP
- timer tests inspect typed absolute deadlines and generation-safe ownership
  without an asynchronous worker thread
- peer-controller tests apply closed construction and transport outcomes to
  the production queue mutations and drive the complete retry-exhaustion and
  later-recovery workflow
- packet-channel tests cover PID ownership transfer, receive-queue clearing,
  and monotonic packet IDs

The deterministic runtime records random-byte consumption so a change in the
handshake's external inputs is observable even when the resulting packet still
passes cryptographic validation.

The in-memory link is intentionally a datagram boundary. Handshake initiation,
handshake response, and transport-data messages are serialized into bytes and
parsed again by the receiving peer. Tests must not transfer message structs or
key material directly between peers.

## Protocol Model

The protocol core uses explicit ownership boundaries rather than passing the
platform UDP descriptor through handshake and transport code:

- parsers borrow immutable wire bytes through `std::span<const std::uint8_t>`
- serializers borrow mutable output storage through `std::span<std::uint8_t>`
- fixed-size wire fields and cryptographic material use `std::array`
- checked readers and writers reject insufficient input or output before a
  field is accessed
- a keypair owns its establishment state, indices, birth time, session keys,
  send counter, and receive replay window as one coherent object
- successful transport serialization consumes its send counter before socket
  I/O, preventing nonce reuse when the later UDP send fails
- keypair send and receive capability is evaluated against the upstream
  `RejectAfterTime` and `RejectAfterMessages` hard limits
- replay state uses wireguard-go's 128-block, 8,128-packet backtrack window
- outbound inner packets are staged in a bounded peer-owned queue while no
  send-capable keypair exists; session derivation makes that queue sendable
- protocol monotonic time points, elapsed durations, and timer deadlines are
  distinct types; conversion to Horizon jiffies remains at the platform edge
- inner-packet queues have compile-time capacity, reject-new overflow behavior,
  and disposition counters whose totals preserve depth accounting
- sensitive protocol owners are move-only and clear themselves on destruction

The legacy self-tests use adapters local to the host test translation unit.
Production protocol headers do not retain overloads for the removed nullable
packet-buffer API.

## Deterministic Coverage

The protocol suite currently verifies:

- identical clock and random inputs produce an identical initiation packet
- the initiator and responder traverse the expected handshake states
- both peers derive reciprocal sending and receiving keys at the controlled
  key-creation time
- encrypted transport data succeeds in both directions
- send and receive counters advance as expected
- replayed transport packets are rejected
- timer intent can be scheduled, replaced, canceled individually, and canceled
  as a group
- every truncated handshake-initiation size is rejected before parsing
- fixed-size handshake packets reject trailing bytes and undersized output
  storage
- transport headers accept checked variable-size packets but reject undersized
  headers
- keypair establishment, age evaluation, reset, and secret clearing are
  observable without UI or runtime state
- bounded queue overflow policy and statistics are deterministic
- clear and removal dispositions preserve `pushed - popped == depth`
- the upstream replay-window boundary accepts 8,128 counters of reordering and
  rejects the next older counter
- timer rearming, cancellation, activation replacement, and retry-sequence
  replacement invalidate stale action tokens
- fake construction and UDP outcomes exercise production queue-retirement
  policy through the platform-independent peer controller
- the exact hard time and counter rejection boundaries prevent transport
  serialization without consuming or reusing a nonce
- traffic submitted without a keypair remains staged across a deterministic
  handshake and is sent after session derivation
- traffic submitted after key expiry remains staged until replacement key
  derivation through a second serialized handshake, including initiator
  current/previous rotation and responder next-key confirmation
- the peer staging queue rejects new traffic at capacity and records overflow
- every timed handshake retry replaces both ephemeral material and sender index
- retry exhaustion occurs at the upstream send-attempt boundary, drops staged
  work, and permits later traffic to begin a new sequence
- stale key-material cleanup clears sessions and handshake secrets while
  preserving configured identity and reusable peer state

The previous message, primitive, and core self-tests remain in the host suite
as legacy regression cases. They live under `sysmodule/test/host` and are no
longer linked into or executed by the production sysmodule.

## What Host Tests Do Not Prove

The protocol suite does not emulate Horizon service behavior, BSD socket
lifetime, NIFM, Atmosphere work queues, or real timer-thread scheduling. Those
belong to platform-adapter and on-device integration tests. The host-tested
production controller defines retry transitions, timer identity, and queue
mutation; the Horizon dispatcher still needs on-device validation that its
synchronous cancellation and token capture behave correctly under real thread
scheduling.

## On-Device Gate

After a protocol change passes on the host:

1. Build and install matching sysmodule and requester binaries.
2. Establish a tunnel with the known-good peer.
3. Run the requester at least three times while one sysmodule instance remains
   active.
4. Confirm a bidirectional inner IPv4/UDP echo round trip and retained peer
   responsiveness.
5. Retain sysmodule and requester logs for comparison with the host transition
   expectations.

This real-peer round trip is the final validation layer for protocol-refactor
milestones. Host tests are the fast protocol gate, not a replacement for
interoperability testing.
