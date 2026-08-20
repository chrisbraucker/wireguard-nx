# Handshake Retry And Recovery Lifecycle

Milestone 4 replaces the proof-of-concept cached-initiation retry loop with the retry lifecycle used by `wireguard-go`.
A failed retry sequence is a protocol event, not a terminal tunnel or UDP transport failure.

## Retry Sequence

Every initial send and timed retry constructs a fresh handshake initiation.
That operation allocates a new sender index, replaces the handshake index registry entry, and generates new ephemeral key material before serialization.
An old response can therefore no longer be routed through the current handshake slot after a retry has replaced it.

The retry timer uses the upstream constants:

- `RekeyTimeout`: 5 seconds
- `RekeyTimeoutJitterMaxMs`: 334 milliseconds, producing 0-333 ms jitter
- `RekeyAttemptTime`: 90 seconds
- `MaxTimerHandshakes`: 18

The attempt boundary follows the current `wireguard-go` implementation rather than deriving a different policy from the constant names.
It permits the initial send plus retries numbered 2 through 20, then gives up on the next timer expiry.
Consequently, an entirely unanswered sequence exhausts slightly after 100 seconds once retry jitter is included.

A valid cookie reply updates peer cookie state.
It does not immediately resend the cached initiation.
The next timed retry constructs a fresh initiation and applies the cookie to that message, matching the upstream receive/send split.

## Responder Cookie Admission

Responder admission validates MAC1 before it accounts for an initiation or response.
A global valid-MAC1 arrival token bucket allows `20/s` with a burst of `5` and enters the upstream one-second sticky under-load period when that threshold is exceeded.
This is the target-specific overload signal for the current serialized receive runtime, rather than a speculative handshake-worker queue-depth proxy.

While under load, admission requires a valid MAC2 derived from a rotating 120-second responder secret and the received UDP endpoint.
A missing or invalid MAC2 produces a stateless cookie reply sent to that received endpoint without changing the authenticated peer binding or endpoint-roaming state.
Valid cookie-authenticated handshakes then pass a fixed, bounded per-source-IP `20/s` burst-`5` limiter.
The implementation follows wireguard-go's cookie wire format and cryptographic construction, while its arrival-trigger source is deliberately documented as a Horizon runtime adaptation.

## Exhaustion And Restart

When the sequence is exhausted, the sysmodule:

- cancels handshake retransmission
- drops packets staged behind the failed sequence
- leaves the configured peer, resolved endpoint, UDP socket, and existing keypairs intact
- retains `Handshaking` or `Active` runtime state instead of entering `Error`
- schedules stale key-material destruction if no such timer is pending

Later newly submitted traffic can start a new sequence.
In particular, an initially unreachable peer may remain in `Handshaking`; a new packet submitted after exhaustion queues work, creates a fresh initiation, and restarts retry bookkeeping without peer deactivation or UDP rebinding.

This preserves upstream's bounded staging policy: packets associated with an exhausted attempt are not retained indefinitely.
Only new work triggers the next attempt window.

## Stale Key Material

Session derivation and retry exhaustion schedule `ZeroKeyMaterial` for `3 * RejectAfterTime`, currently 540 seconds.
Expiry clears current, next, and previous keypairs; transient handshake secrets; the handshake index; and any staged packets.
It preserves configured static identity, static-static precomputation, cookie state, endpoint configuration, and the UDP binding.

This timer remains active when the development transport-suspension experiment cancels retransmit, delayed-keepalive, new-handshake, and persistent-keepalive activity.
The authenticated-activity timer semantics are documented in [`authenticated-activity-timers.md`](authenticated-activity-timers.md).

## Stale Timer Rejection

Each armed protocol timer carries its hook, peer index, activation generation, handshake sequence where applicable, and a monotonically changing arm generation.
Horizon cancellation waits for an in-flight timer callback to finish capturing its token.
Queued work validates that exact token through the platform-independent `PeerController` before touching current peer state.

Rearming, cancellation, peer replacement, and a later handshake sequence all invalidate previously queued work.
In particular, an expired zero-key callback from an old activation cannot erase a newly established session or a different active peer.

## On-Device Validation

The milestone's real-peer gate is:

1. Confirm three requester round trips during one uninterrupted peer session.
2. Make the peer unreachable while leaving the existing UDP socket open.
3. Wait at least 110 seconds and confirm the log records 20 sends followed by nonterminal sequence exhaustion, without peer `Error` or socket teardown.
4. Restore reachability and submit a new requester packet.
5. Confirm a new sequence number starts at attempt 1 and the staged packet is released after handshake completion without peer restart or manual bind replacement.

If Horizon UDP send itself returns an error while NIFM reports an available local path, the peer retains its binding and follows normal WireGuard retry policy.
NIFM unavailability remains the authority for local socket suspension; a BSD error does not by itself establish that the local path disappeared.
