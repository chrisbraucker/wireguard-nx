# Protocol Testing

WireGuard-NX separates deterministic protocol validation from final Horizon
interoperability testing. State-machine work should fail on the development
host before an on-device run is needed.

## Running The Host Suite

From the repository root:

```sh
make -C sysmodule test
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
- timer tests inspect scheduling intent and absolute deadlines without an
  asynchronous worker thread

The deterministic runtime records random-byte consumption so a change in the
handshake's external inputs is observable even when the resulting packet still
passes cryptographic validation.

The in-memory link is intentionally a datagram boundary. Handshake initiation,
handshake response, and transport-data messages are serialized into bytes and
parsed again by the receiving peer. Tests must not transfer message structs or
key material directly between peers.

## Milestone 1 Coverage

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

The previous message, primitive, and core self-tests remain in the host suite
as legacy regression cases. They live under `sysmodule/test/host` and are no
longer linked into or executed by the production sysmodule.

## What Host Tests Do Not Prove

The protocol suite does not emulate Horizon service behavior, BSD socket
lifetime, NIFM, Atmosphere work queues, or real timer-thread ordering. Those
belong to platform-adapter and on-device integration tests. The protocol core
currently records timer intent while `ipc_service.cpp` owns the Horizon timer
and work dispatchers; later lifecycle milestones should move behavior across
that boundary only with corresponding deterministic tests.

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

This real-peer round trip is the final Milestone 1 validation layer. Host tests
are the fast protocol gate, not a replacement for interoperability testing.
