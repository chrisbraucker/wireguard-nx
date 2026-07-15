# Key Validity And Outbound Staging

Milestone 3 makes key validity a protocol decision rather than an inference
from the daemon's broad `Active` runtime state. Its constants and boundary
semantics follow `wireguard-go/device/constants.go` and
`wireguard-go/device/send.go`.

## Hard Key Limits

A keypair is send-capable only while both conditions hold:

- its age is less than `RejectAfterTime` (180 seconds)
- its next send counter is less than `RejectAfterMessages`
  (`2^64 - 2^13 - 1`)

Receive use also stops at `RejectAfterTime`, and transport counters at or above
`RejectAfterMessages` are rejected before replay or authentication state is
changed. The boundary is exclusive: a key is usable immediately before either
limit and rejected at the limit.

Transport serialization reserves and advances the nonce before encryption.
The nonce therefore remains consumed if encryption or the later UDP send
fails, avoiding reuse with another plaintext.

`RekeyAfterTime` and `RekeyAfterMessages` remain distinct soft thresholds. The
existing time-based rekey timer is still provisional, and message-count-driven
rekey scheduling belongs to Milestone 5. Neither soft threshold permits use
after a hard rejection limit.

## Staged Outbound Traffic

Each configured protocol peer owns a fixed eight-packet outbound staging
queue. New packets are rejected when the queue is full; existing packets are
not displaced. Queue depth, high-watermark, and rejected-packet counts remain
observable through the queue model.

The packet worker evaluates the front packet without removing it:

1. A send-capable current keypair releases packets in FIFO order.
2. A missing, expired, or counter-exhausted keypair retains the packets and
   requests a handshake.
3. An already pending handshake is coalesced instead of creating duplicate
   initiation work.
4. Successful session derivation schedules the worker and releases the staged
   packets through the replacement keypair.

Peer deactivation, peer error, packet-API ownership transfer, and protocol
reset clear staged records and overwrite their packet storage. Staged traffic
cannot cross an activation generation or survive peer shutdown.

The daemon currently supports one remote peer per configured tunnel entry, so
`wg_device` owns that peer directly. This avoids reserving an unused nested
eight-peer array and keeps the bounded staging storage proportional to the
eight configured tunnel slots.

## Deferred Recovery Behavior

Milestone 3 starts a handshake when staged traffic has no usable session, but
does not replace the proof-of-concept retry state machine. Retry windows,
attempt exhaustion, later traffic restarting a new sequence, and stale
handshake-material cleanup are Milestone 4. Authenticated-activity-driven
rekey and keepalive scheduling remain Milestone 5.
