# Transport Recovery

WireGuard peer state and the Horizon UDP socket have separate lifecycles. A
temporary uplink failure must not discard peer configuration, keypairs,
handshake state, timers, or queued inner packets merely because the current BSD
socket can no longer send or receive.

The protocol peer no longer stores a resolved Horizon endpoint or includes the
platform UDP abstraction. Resolved address text, socket handles, and socket
generations are owned only by the runtime transport state. Protocol timer and
staged-send decisions are handled by a platform-independent peer controller.

## Manual UDP Bind Bump

IPC API version 4 adds `BumpUdpBinding` as command 23. The command records a
request for the active peer's current activation generation and schedules the
existing receive worker. It does not perform socket operations on an IPC
thread.

The receive worker serializes the operation with receive polling:

1. Reject a request whose peer or activation generation is stale.
2. Close the current Horizon UDP socket.
3. Open a replacement socket for the already resolved endpoint family.
4. Assign a new socket generation.
5. Send an immediate WireGuard keepalive for an active session, or resend the
   current initiation while handshaking.
6. Continue receive polling on the replacement socket.

Receive snapshots and completion paths validate both activation generation and
socket generation. This prevents a result from an older socket lifetime from
being committed after a replacement, including when Horizon reuses the same
integer descriptor.

Repeated requests for the same pending activation are coalesced. Socket-open or
resume-send failures are logged but leave the WireGuard peer state intact so a
later recovery attempt can retry. The manager maps this development command to
the `X` button.

## NIFM Path Observer

The shadow observer is controlled by
`development_config::NifmPathObserver`. Its staged modes isolate an
active-tunnel flight-mode hang that occurs during application launch:

- `Disabled`: do not initialize or call NIFM
- `InitializeOnly`: retain a `nifm:s` general-service session without queries
- `InternetStatusOnly`: additionally query Internet connection status
- `IpConfigOnly`: additionally query the current IP configuration
- `Full`: run both queries

The current test build uses `InitializeOnly`. This preserves the system-service
endpoint and session lifetime while compiling out both observer queries.

When a mode other than `Disabled` is selected and a peer is active, the
sysmodule samples NIFM every two seconds. Enabled queries contribute to this
path fingerprint when it changes:

- Internet connection query result, connection type, status, and Wi-Fi strength
- IP configuration query result
- local IPv4 address, subnet mask, gateway, and DNS servers

This observer is deliberately passive. NIFM's Internet status is not endpoint
reachability: a LAN WireGuard peer may remain usable when Horizon reports no
Internet connection. Recovery must therefore not be gated on a `Connected`
status. Later automation may treat a fingerprint change as one input to the
same bind-bump operation, with transport failures as a fallback.

Each enabled sample logs a monotonic sequence number around NIFM initialization,
the Internet-connection-status query, and the current-IP-configuration query.
The begin/end pairs identify a blocking call, while the final sample record is
a periodic liveness heartbeat even when the fingerprint does not change.

Endpoint hostname re-resolution is not part of the manual bind bump yet. It
belongs in automated path recovery after the socket lifecycle is validated.

## Packet Client Session Lifetime

The requester originally used the one-shot client wrapper for every
`ReceiveInnerIpv4Packet` poll. A five-second timeout at the current polling
interval performed roughly 198 `smGetService` and `serviceClose` cycles. During
flight-mode tests, repeated timeout runs correlated with delayed application
launch and teardown even though requester `main()` completed and the WireGuard
sysmodule remained live.

The controlled packet scenario now holds one `wgnx:ctl` CMIF session for API
version negotiation, packet submission, and all receive polls. This separates
transport recovery behavior from service-manager session churn and matches the
expected ownership model for a request/response exchange. The IPC wire
contract is unchanged, so this client-lifecycle correction does not increment
API version 4.

## Transition Test

Use matching API-v4 sysmodule and manager builds.

1. Connect Ethernet, select the peer, and confirm one requester round trip.
2. Enable Wi-Fi while Ethernet remains connected and retain the resulting NIFM
   path-change log.
3. Disconnect Ethernet, wait at least three seconds, and retain the next NIFM
   path-change log.
4. Run requester once before recovery to establish whether the old binding is
   usable.
5. Open manager, press `X`, and wait for `Completed UDP bind bump` in the log.
6. Run requester again without reselecting or reconnecting the peer.
7. Repeat in the Wi-Fi-to-Ethernet direction.

For a LAN-only test, repeat while the network has no Internet uplink. A failed
NIFM Internet-status query must be logged but must not block the manual bind
bump or tunnel traffic to the local peer.

## BSD socket suspension experiment

The current development build enables
`SuspendUdpTransportOnFirstSendFailure`. On the first recoverable UDP send
failure, the sysmodule cancels transport timers and closes only the active UDP
socket. It deliberately preserves the selected peer, WireGuard keys and
protocol state, and the retained NIFM session.

This is an isolation experiment rather than automatic recovery. It tests
whether an uplink-loss socket or an outstanding BSD receive call blocks later
application startup. The transport remains suspended until an explicit bind
bump or peer reactivation opens a new socket. Logs bracket every `RecvFrom`,
`Shutdown`, and `Close`; an unmatched `begin` record identifies the IPC call
that did not return.

## Uplink-only outage findings

An uplink-only outage was tested while the Switch remained associated with the
same Wi-Fi network. Horizon continued to report the network as Internet-capable
after upstream connectivity was removed, including when the network lacked a
working uplink during an earlier association test. This confirms that NIFM
Internet status is not a usable WireGuard peer-reachability signal and may be
spoofed or cached by the runtime environment.

The requester completed two tunnel round trips before the outage. During the
outage, two submitted inner packets timed out. After the uplink was restored,
two more submissions also timed out even though application launch, `wgnx:ctl`
session creation, packet validation, and queueing remained responsive.

The Horizon UDP sends continued to return success while the uplink was absent.
That return value proves only that BSD accepted a datagram locally; it does not
prove that the encrypted packet reached the peer or that an authenticated
WireGuard packet was received. Consequently,
`SuspendUdpTransportOnFirstSendFailure` is useful for failures surfaced by BSD,
but cannot detect this class of silent path outage.

The current simulated protocol timers make stale cryptographic state a leading
hypothesis. A rekey can be locally accepted during the outage, exhaust its
bounded retransmissions without a response, and leave the old session marked
established. After the peer's reject-after-time window, restored uplink alone
would then be insufficient to recover traffic. The next discriminating test is:

1. Establish the tunnel and confirm a requester round trip.
2. Remove only the uplink for longer than three minutes.
3. Restore the uplink and confirm that requester traffic still times out.
4. Invoke `BumpUdpBinding` and retry without reactivating the peer.
5. If that fails, reactivate the peer and retry.

If a bind bump fails but peer reactivation succeeds, the stale state is the
WireGuard handshake/key lifecycle rather than only the Horizon UDP binding.
Recovery should then follow upstream WireGuard timer semantics: outbound data
after prolonged absence of authenticated receive activity must be able to
start a fresh handshake, with bounded retransmission for each attempt and a
later outbound packet able to initiate another attempt.

### Uplink-outage recovery experiment result

The discriminating test above confirmed the stale handshake/key hypothesis.
The initial session completed requester round trips before the uplink was
removed. While the uplink was unavailable, the 120-second rekey timer created a
new initiation and sent it five times at five-second intervals. No response was
received. The retransmit timer was then canceled, but the peer remained active
with the unsuccessful handshake in `initiation_created` and its old transport
keypair still usable locally.

After the uplink was restored, requester traffic still timed out. Two manual
bind bumps exercised both relevant transport paths:

- the first resumed a transport that had been suspended after a surfaced BSD
  send failure, opening socket generation 2;
- the second closed generation 2 and opened generation 3 normally.

Both bumps sent an immediate keepalive with the retained keypair. A subsequent
requester packet was encrypted and accepted by BSD on socket generation 3, but
no authenticated response arrived. Neither bump generated a handshake
initiation. Deactivating and reactivating the peer then created activation 2,
socket generation 4, and a fresh handshake. The next requester round trip
succeeded immediately.

This rules out a stale Horizon UDP binding as the sufficient cause. Socket
replacement is necessary for some path transitions, but cannot recover an
expired cryptographic session by itself. The current timer model differs from
upstream WireGuard in several material ways:

- upstream retries a handshake throughout `RekeyAttemptTime` rather than using
  the current fixed five-attempt limit;
- upstream schedules key-material destruction after an exhausted handshake;
- upstream rejects outbound use of a keypair at `RejectAfterTime` and starts a
  fresh handshake instead of continuing to emit transport packets;
- upstream timer hooks use authenticated send and receive activity to schedule
  a new handshake when a peer stops responding.

Milestones 3 and 4 now implement that coherent subset: hard key rejection,
bounded staging, upstream-style retry exhaustion, delayed stale-key cleanup,
and later traffic-triggered retry restart. The next validation pass is the same
prolonged-outage shape above, now expecting recovery after restored reachability
without peer reactivation or UDP rebinding.

## Logger reliability

Transport, timer, and NIFM work run on multiple threads. The file logger must
therefore serialize backend initialization and the complete
open/get-size/write/flush append transaction. Without that serialization, two
writers can observe the same file size, overwrite records, or cause one
filesystem failure to disable all later file output.

File-backend failures now emit an operation name and result code directly via
`svcOutputDebugString`, without recursively entering the logger. The backend is
reset to an uninitialized state after an append failure so a later record can
remount/reopen and resume file logging. This is important for outage tests that
run beyond the 120-second rekey point; a truncated file otherwise hides the
timer transition that the test is intended to measure.
