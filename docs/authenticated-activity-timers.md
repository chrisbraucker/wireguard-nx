# Authenticated-Activity Timers

Milestone 5 replaces the proof-of-concept `Rekey` deadline with the five timer
roles used by `wireguard-go/device/timers.go`. Peer protocol events produce
timer effects; the Horizon scheduler only executes generation-checked tokens.

## Timer Roles

| Hook                  | Upstream role                                                          | WireGuard-NX trigger                                                                                          |
|-----------------------|------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| `RetransmitHandshake` | retry an unanswered initiation                                         | arm only after a handshake initiation has successfully reached UDP submission                                 |
| `SendKeepalive`       | answer authenticated data receive activity with a delayed empty packet | first authenticated non-empty transport packet arms `KeepaliveTimeout` (10 seconds)                           |
| `NewHandshake`        | rekey when sent data is not answered                                   | authenticated non-empty transport send arms `KeepaliveTimeout + RekeyTimeout + jitter` when not already armed |
| `ZeroKeyMaterial`     | erase stale transient session state                                    | session derivation and retry exhaustion arm `3 * RejectAfterTime`                                             |
| `PersistentKeepalive` | retain NAT state for configured peers                                  | every authenticated packet traversal resets the configured interval                                           |

An authenticated send cancels `SendKeepalive`. An authenticated receive cancels
`NewHandshake`. Repeated data receives while `SendKeepalive` is already armed
set one peer-owned `need_another_keepalive` bit. Its expiry sends one empty
packet and schedules at most one follow-up delayed keepalive, so receive bursts
cannot create unbounded or duplicate timer work.

## Handshake And Session Transitions

Authenticated handshake messages reset persistent-keepalive timing. A response
processed by an initiator, or the first authenticated transport packet that
confirms a responder session, completes handshake retry bookkeeping and cancels
`RetransmitHandshake`. Every derived session refreshes `ZeroKeyMaterial`.

Timer expiry first invalidates its peer-owned intent and scheduler token. A
replacement effect receives a new arm generation, so an already queued callback
cannot mutate a later arm, handshake sequence, activation, or peer selection.

## Soft Rekey Thresholds

`noise_keypair::NeedsRekeyAt` follows wireguard-go's soft thresholds:

- an initiator requests rekey after its current keypair is older than
  `RekeyAfterTime` (120 seconds)
- either role requests rekey once the outgoing counter is greater than
  `RekeyAfterMessages` (`2^60`)

The hard `RejectAfterTime` and `RejectAfterMessages` limits remain independent
and continue to prevent packet construction before nonce or key reuse can
occur.

WireGuard-NX serializes one pending encrypted datagram per peer. It therefore
starts the replacement handshake after the threshold-crossing authenticated data
send completes, rather than concurrently before that send as wireguard-go's
multi-queue pipeline can. The triggering packet still uses a valid keypair and
the follow-up handshake is generation-checked; this is a bounded scheduling
adaptation, not a change to the protocol thresholds.

## Validation

The deterministic host suite covers all five timer intent slots, replacement,
cancellation, captured stale delivery, initiator-only age rekey, message-count
rekey, session derivation, authenticated data send, delayed keepalive, and
persistent-keepalive rescheduling. The remaining Milestone 5 gate is a
real-peer on-device test covering idle persistent keepalive, delayed keepalive,
and a rekey transition.
