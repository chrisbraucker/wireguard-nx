# Key Validity And Outbound Staging

Milestone 3 makes key validity a protocol decision rather than an inference from the daemon's broad `Active` runtime state.
Its constants and boundary semantics follow `wireguard-go/device/constants.go` and `wireguard-go/device/send.go`.

## Hard Key Limits

A keypair is send-capable only while both conditions hold:

- its age is less than `RejectAfterTime` (180 seconds)
- its next send counter is less than `RejectAfterMessages` (`2^64 - 2^13 - 1`)

Receive use also stops at `RejectAfterTime`, and transport counters at or above `RejectAfterMessages` are rejected before replay or authentication state is changed.
The boundary is exclusive: a key is usable immediately before either limit and rejected at the limit.

Replay filtering follows `wireguard-go/replay`: 128 64-bit ring blocks retain an 8,128-packet backtrack window.
Duplicate packets, packets beyond that window, and counters at or above `RejectAfterMessages` are rejected without committing replay state.

Transport serialization reserves and advances the nonce before encryption.
The nonce therefore remains consumed if encryption or the later UDP send fails, avoiding reuse with another plaintext.

Session derivation follows upstream keypair rotation.
An initiator installs the new keypair as current and retains the old current keypair as previous.
A responder installs a derived keypair as next while retaining current; the first transport packet authenticated through next promotes it to current and moves the old current keypair to previous.
The device index registry is refreshed at each transition so in-flight packets may still resolve through the retained previous keypair while an unconfirmed responder key cannot be used for sends.

`RekeyAfterTime` and `RekeyAfterMessages` remain distinct soft thresholds.
Milestone 5 evaluates them through authenticated outbound activity: initiator key age and either-role send-counter pressure start a replacement handshake without permitting use after a hard rejection limit.
The detailed timer mapping is in [`authenticated-activity-timers.md`](authenticated-activity-timers.md).

## Staged Outbound Traffic

Each configured protocol peer owns a fixed eight-packet outbound staging queue.
New packets are rejected when the queue is full; existing packets are not displaced.
Queue depth, high-watermark, and rejected-packet counts remain observable through the queue model.
Every removal records a disposition: sent, delivered, stale, unavailable, send-failed, retry-exhausted, or cleared.
Consequently, `pushed - popped` remains equal to current depth after teardown and exhaustion as well as ordinary sends.

The packet worker evaluates the front packet without removing it:

1. A send-capable current keypair releases packets in FIFO order.
2. A missing, expired, or counter-exhausted keypair retains the packets and requests a handshake.
3. An already pending handshake is coalesced instead of creating duplicate initiation work.
4. Successful session derivation schedules the worker and releases the staged packets through the replacement keypair.

The production worker does not remove the queue front before transport packet construction.
If the current key crosses a hard limit between the readiness check and nonce reservation, the plaintext remains staged and starts a fresh handshake.
A successfully serialized datagram consumes its nonce; a later UDP send failure follows the explicit transport-drop policy and does not retry the same plaintext with that nonce.

That policy is implemented by the platform-independent `PeerController` and covered with deterministic build and transport outcomes.
The Horizon worker does not infer construction failure from a later clock read.

Peer deactivation, peer error, packet-API ownership transfer, and protocol reset clear staged records and overwrite their packet storage.
Staged traffic cannot cross an activation generation or survive peer shutdown.

The daemon currently supports one remote peer per configured tunnel entry, so `wg_device` owns that peer directly.
This avoids reserving an unused nested eight-peer array and keeps the bounded staging storage proportional to the eight configured tunnel slots.

## Sensitive Ownership

Private keys, symmetric keys, cookie material, handshake secrets, and keypairs are move-only owners.
Their `Clear()` operations and destructors use the project's non-optimizable secure clear primitive.
Key rotation transfers ownership; it cannot accidentally retain a freely copyable secret snapshot.

Configuration loading parses private and preshared keys into binary owners and then scrubs their base64 buffers from both the loader result and retained configuration.
The persistent binary owner is copied explicitly only when an active protocol peer is instantiated. `wg_device` and `wg_peer` no longer keep additional encoded copies.

## Recovery Behavior

Milestone 4 replaces the proof-of-concept retry state machine.
Retry windows, attempt exhaustion, later traffic restarting a new sequence, and stale handshake-material cleanup are documented in [`handshake-recovery.md`](handshake-recovery.md).
Authenticated-activity-driven rekey and keepalive scheduling are documented in [`authenticated-activity-timers.md`](authenticated-activity-timers.md).
