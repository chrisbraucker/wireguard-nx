# WireGuard-NX Runtime State Model

This document defines how WireGuard-NX should represent connection state
internally and externally as the transport and protocol implementation evolves.

## Principles

- Keep the user-facing state conservative.
- Do not claim more certainty than WireGuard over UDP can provide.
- Treat transport silence differently from local operational failure.
- Keep static config separate from live runtime state.

## Upstream Alignment

The Linux WireGuard implementation does not expose a primary peer state such as
`connected`, `connecting`, or `error`.

Instead, the upstream reporting surface exposes peer facts such as:

- endpoint
- allowed IPs
- latest handshake time
- received bytes
- transmitted bytes
- persistent keepalive interval

This is visible both in the kernel netlink API and in `wg show`, which presents
those values directly rather than inventing an additional connection-state
label.

For WireGuard-NX, this means:

- a simple top-level `inactive` / `active` status is acceptable
- any `established` interpretation should be derived from observed handshake
  and traffic data
- any `error` interpretation should be tied to local failures, not mere lack of
  UDP response

## Linux Runtime Model

The Linux implementation tracks peer runtime through a combination of:

- peer runtime fields
- handshake state
- keypair lifecycle
- timers
- observed traffic

It does not rely on a single high-level peer-state enum.

### Peer Runtime Fields

The upstream peer object carries facts such as:

- endpoint
- transmit and receive counters
- keepalive interval
- last handshake wall-clock time
- staged packet queues
- timer bookkeeping

These are peer facts, not user-facing labels.

### Handshake State

Linux does keep an explicit internal handshake state machine. The handshake
object moves through phases such as:

- zeroed
- initiation created
- initiation consumed
- response created
- response consumed

This state is useful for protocol implementation, but it is not surfaced
directly as the main user-facing connection state.

### Keypair Lifecycle

Session liveness is represented primarily through keypairs rather than through
a `connected` flag.

Linux tracks:

- current keypair
- previous keypair
- next keypair
- validity bits
- birth time
- sending counter
- replay protection state

This is one of the main reasons not to invent an overly simple boolean state
model too early.

### Timer-Driven Operation

Linux peer management is heavily timer-driven. The main behaviors are:

- retransmit handshake when no response arrives after the rekey timeout
- send keepalive after receive-without-send
- initiate a new handshake after send-without-receive
- zero ephemeral key material after extended inactivity
- send periodic persistent keepalives when configured

These timers are a core part of the runtime model and should be treated as part
of the reference behavior.

### Traffic-Derived Confirmation

Linux treats successful authenticated packet flow as the strongest confirmation
of session usability.

In particular:

- a handshake is treated as complete only after the relevant authenticated
  traffic/key confirmation path is observed
- endpoint updates are learned from real packet traffic
- liveness is inferred from packet activity and timer behavior

## Implementation Guidance

To stay close to the reference implementation, WireGuard-NX should prefer:

- explicit internal handshake states
- explicit keypair lifecycle tracking
- timer-driven retry and keepalive behavior
- peer facts exposed over IPC
- conservative derived user-facing state

WireGuard-NX should avoid:

- inventing a primary connection-state enum that claims more certainty than the
  protocol provides
- treating lack of UDP response as a hard peer error by itself
- collapsing keypair state, handshake state, and packet activity into a single
  boolean beyond what the overlay needs to display

## User-Facing State

The primary state shown in the overlay should remain simple:

- `inactive`
- `active`

This matches what most WireGuard users expect and avoids overpromising on top
of a connectionless transport.

### Meaning

- `inactive`
  - no peer is selected
  - the engine is stopped
  - no connection attempt is currently being made

- `active`
  - a peer is selected
  - the engine is configured and attempting to operate
  - the tunnel may still be handshaking or waiting for return traffic

## Derived State

Some richer state can be shown as secondary detail rather than the primary
label.

- `established`
  - should only be inferred after receiving valid authenticated traffic for the
    current session
  - in practice this means a completed handshake plus recent confirmed receive
    activity

- `error`
  - should represent a local operational failure
  - examples:
    - invalid config
    - key parse failure
    - endpoint resolution failure
    - socket setup failure
    - crypto initialization failure
    - malformed or rejected packets
  - lack of UDP response alone is not enough to call the peer "error"

## Internal Runtime State

Internally, the sysmodule should track a richer state machine than the overlay
necessarily exposes.

Recommended internal states:

- `stopped`
- `starting`
- `resolving_endpoint`
- `handshake_pending`
- `handshake_sent`
- `session_active`
- `rekeying`
- `timed_out`
- `fatal_error`

These states are intended for logging, control flow, and IPC-visible detail
fields.

## Recommended IPC Detail Fields

The top-level state can stay simple if the IPC surface also carries detail
fields such as:

- `endpoint`
- `persistent_keepalive_interval`
- `last_handshake_age`
- `last_rx_age`
- `last_tx_age`
- `rx_bytes`
- `tx_bytes`
- `last_error_code`
- `last_error_stage`
- `is_established`

This allows the overlay to present better diagnostics without making the main
status model misleading.

## Practical Interpretation

For this project, the intended interpretation is:

- primary status:
  - `inactive` or `active`
- secondary detail:
  - whether the peer appears established
  - when traffic was last seen
  - whether the sysmodule is locally failing

This keeps the UI honest while still leaving enough detail for debugging and
future runtime operations.
