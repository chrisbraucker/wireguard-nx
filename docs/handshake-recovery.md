# Handshake Retry And Recovery Lifecycle

Milestone 4 replaces the proof-of-concept cached-initiation retry loop with the
retry lifecycle used by `wireguard-go`. A failed retry sequence is a protocol
event, not a terminal tunnel or UDP transport failure.

## Retry Sequence

Every initial send and timed retry constructs a fresh handshake initiation.
That operation allocates a new sender index, replaces the handshake index
registry entry, and generates new ephemeral key material before serialization.
An old response can therefore no longer be routed through the current
handshake slot after a retry has replaced it.

The retry timer uses the upstream constants:

- `RekeyTimeout`: 5 seconds
- `RekeyTimeoutJitterMaxMs`: 334 milliseconds, producing 0-333 ms jitter
- `RekeyAttemptTime`: 90 seconds
- `MaxTimerHandshakes`: 18

The attempt boundary follows the current `wireguard-go` implementation rather
than deriving a different policy from the constant names. It permits the
initial send plus retries numbered 2 through 20, then gives up on the next
timer expiry. Consequently, an entirely unanswered sequence exhausts slightly
after 100 seconds once retry jitter is included.

A valid cookie reply updates peer cookie state. It does not immediately resend
the cached initiation. The next timed retry constructs a fresh initiation and
applies the cookie to that message, matching the upstream receive/send split.

## Exhaustion And Restart

When the sequence is exhausted, the sysmodule:

- cancels handshake retransmission
- drops packets staged behind the failed sequence
- leaves the configured peer, resolved endpoint, UDP socket, and existing
  keypairs intact
- retains `Handshaking` or `Active` runtime state instead of entering `Error`
- schedules stale key-material destruction if no such timer is pending

Later newly submitted traffic can start a new sequence. In particular, an
initially unreachable peer may remain in `Handshaking`; a new packet submitted
after exhaustion queues work, creates a fresh initiation, and restarts retry
bookkeeping without peer deactivation or UDP rebinding.

This preserves upstream's bounded staging policy: packets associated with an
exhausted attempt are not retained indefinitely. Only new work triggers the
next attempt window.

## Stale Key Material

Session derivation and retry exhaustion schedule `ZeroKeyMaterial` for
`3 * RejectAfterTime`, currently 540 seconds. Expiry clears current, next, and
previous keypairs; transient handshake secrets; the handshake index; and any
staged packets. It preserves configured static identity, static-static
precomputation, cookie state, endpoint configuration, and the UDP binding.

This timer remains active when the development transport-suspension experiment
cancels retransmit, keepalive, and rekey activity. Full authenticated-activity
timer semantics, including new-handshake and persistent-keepalive interactions,
remain Milestone 5 work.

## On-Device Validation

The milestone's real-peer gate is:

1. Confirm three requester round trips during one uninterrupted peer session.
2. Make the peer unreachable while leaving the existing UDP socket open.
3. Wait at least 110 seconds and confirm the log records 20 sends followed by
   nonterminal sequence exhaustion, without peer `Error` or socket teardown.
4. Restore reachability and submit a new requester packet.
5. Confirm a new sequence number starts at attempt 1 and the staged packet is
   released after handshake completion without peer restart or manual bind
   replacement.

If the Horizon UDP send itself returns an error, the current development flag
`SuspendUdpTransportOnFirstSendFailure` deliberately closes that socket. That
diagnostic path is outside this milestone's existing-socket recovery claim and
still requires the separate bind-recovery experiment.
