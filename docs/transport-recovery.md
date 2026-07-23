# Transport Recovery

WireGuard peer state and the Horizon UDP socket have separate lifecycles. A
temporary uplink failure must not discard peer configuration, keypairs,
handshake state, timers, or queued inner packets merely because the current BSD
socket can no longer send or receive.

The protocol peer no longer stores a resolved Horizon endpoint or includes the
platform UDP abstraction. A move-only runtime `UdpBinding` owns resolved
address text, socket lifetime, socket generation, and transport suspension.
Protocol timer and staged-send transitions are handled by the
platform-independent production `PeerController`; concrete Horizon timers and
work queues are owned by `HorizonDispatcher`.

## Manual UDP Bind Bump

IPC API version 4 adds `BumpUdpBinding` as command 23. The command records a
request for the active peer's current activation generation and schedules the
existing receive worker. It does not perform socket operations on an IPC
thread.

The receive worker serializes the operation with receive polling:

1. Reject a request whose peer or activation generation is stale.
2. Open a candidate replacement socket for the already resolved endpoint family.
3. Assign a new socket generation and close the replaced descriptor only after
   the candidate is adopted.
4. Send an immediate WireGuard keepalive for an active session, or resend the
   current initiation while handshaking.
5. Continue receive polling on the replacement socket.

Receive snapshots and completion paths validate both activation generation and
socket generation. This prevents a result from an older socket lifetime from
being committed after a replacement, including when Horizon reuses the same
integer descriptor.

Repeated requests for the same pending activation are coalesced. Socket-open or
resume-send failures are logged but leave the WireGuard peer state intact so a
later recovery attempt can retry. The manager maps this development command to
the `X` button.

## NIFM Local-Path Gate

Each active peer owns one asynchronous `nifm:s` request. Its Horizon adapter
waits on `event_request_state` on a dedicated bounded worker; it does not sample
Internet status or IP configuration and does not use a two-second polling timer.
After consuming the autoclear event, the adapter reads `IRequest` state and
result directly rather than using libnx's event-gated cache getters. Request
creation, submission, cancellation, and closure all occur outside the daemon
state mutex. NIFM does not own or register the transport socket.

The runtime has three semantic local-path facts: `Available`, `Unavailable`,
and `Unknown`. The Horizon 20.5.0 `IRequest` state-machine reconstruction
establishes raw state `1` (`Pending`/reset) and raw state `2` (`OnHold`/submitted
but not admitted) as not eligible for new local network transmission. A
successful read of either maps to `Unavailable`; raw state `3` maps to
`Available`. The runtime's `Unavailable` branch suspends the current binding
while preserving peer configuration, authenticated endpoint, key material, and
bounded staged packets. Raw states `0`, `4`, and `5`, and failed state reads,
remain `Unknown` rather than manufacturing a path decision from incomplete
evidence.

`Available` permits endpoint resolution, UDP opening, and normal WireGuard
recovery; it never establishes peer reachability by itself. `Unavailable` is
authoritative only for local socket ownership, so it closes the current
descriptor once and a later `Available` performs one generation-safe rebind.
While the binding is unavailable, new inner packets remain in the bounded
peer-owned staging queue; they are not encrypted into a pending datagram until
a replacement binding can actually accept a send. Once a rebind adopts a valid
socket, recovery drains staged traffic first when the current WireGuard key can
send, falling back to a keepalive only when there is no queued traffic.
Failed request observations and stale request generations preserve the prior
authoritative decision. If an already-open binding was `Available` and NIFM
then becomes `Unknown`, the runtime records one potential local-path change
without closing the binding. The next confirmed `Available` consumes that
marker by requesting one generation-safe rebind; repeated `Unknown` or
`Available` observations are coalesced.

NIFM never proves remote reachability. In particular, local-only networking can
be `Available`, and a reachable LAN peer may remain usable without Internet
uplink. Authenticated WireGuard traffic remains the only positive reachability
proof; handshake timers and surfaced BSD results remain transport facts. A
nonterminal BSD send or receive failure does not replace the active binding or
rewrite NIFM state. A failed handshake initiation arms the normal bounded
retransmit timer, while the serialized receive worker retries its current
binding with a short backoff. Replacement is reserved for an explicit manual
bind bump, an authoritative NIFM `Unavailable` to `Available` transition, or a
single confirmed `Available` following a recorded indeterminate local-path
transition.

A send effect can still race a path suspension after it has been emitted. The
effect executor therefore admits a current peer-owned datagram independently
of binding snapshot availability. If the worker later cannot snapshot the
released binding, it emits the ordinary failed-send completion, which retires
the pending slot and lets a later rebind recover. It must never silently drop
that effect, because doing so leaves recovery permanently deferred behind a
datagram that no worker owns.

The raw `NifmRequestState` mapping is logged with activation and path-request
generations whenever its raw state, classified availability, or result changes;
steady-state observations remain silent. On Horizon 20.5.0, `OnHold` is a
request-wait state: an observed `nim` request configured with requirement
preset `0x0B` transitions from `OnHold` to `Available` while its `GetResult`
remains `0x0000DE6E`. Classification deliberately relies on the successfully
read state, not `GetResult`; the latter may remain non-zero during a normal
`OnHold -> Available` transition. Separate `nim` traffic uses `IRequest`
command 12; the sysmodule tests `SetPersistent(true)` before submit. This is
an evidence-backed compatibility experiment, not yet a confirmed mandatory
step in the short `nim` request trace. Device validation must still observe
the state sequence across Wi-Fi, flight mode, no-DHCP, local-only, and Ethernet
transitions.

### NIFM reachability discrepancy

NIFM reports Horizon's local-path admission state, not whether the configured
WireGuard endpoint is reachable. In particular, testing on modified consoles
shows that removing Internet uplink from an otherwise associated Wi-Fi network
can leave NIFM `Available`; conversely, `Pending` and `OnHold` do not identify
which physical interface changed. The sysmodule therefore uses `Unavailable`
only to relinquish its local UDP descriptor. It continues to use authenticated
WireGuard traffic, retry timers, and BSD outcomes to determine remote-peer
progress. This discrepancy is intentional and remains a constraint on future
automatic recovery and Wi-Fi/Ethernet source-selection work.

Endpoint changes are accepted only from authenticated WireGuard traffic.
Hostname resolution occurs during peer activation; neither manual nor automatic
UDP rebinding re-resolves the configured hostname. This matches the WireGuard
endpoint model: an unannounced remote address change must either roam through
authenticated traffic or be applied through an explicit peer configuration
update, rather than being inferred from an unauthenticated DNS refresh.

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
2. Enable Wi-Fi while Ethernet remains connected, then disconnect Ethernet.
   Retain every NIFM observation and the next requester result.
3. Wait for the request to return to `Available`; do not invoke a manual bind
   bump. Confirm exactly one controlled automatic rebind and a requester round
   trip without reselecting or reconnecting the peer.
4. Repeat in the Wi-Fi-to-Ethernet direction.
5. Repeat with flight mode, and separately with a local-only network and an
   attachment that cannot acquire DHCP. Record each raw NIFM request state.

The manual bind bump remains a diagnostic fallback only after an automatic
recovery failure. Local-only networking must not block tunnel traffic to a LAN
peer merely because it lacks Internet uplink; this implementation does not make
an Internet-status query.

## BSD Failure Recovery

The former compile-time first-failure suspension experiment has been removed.
NIFM transitions alone suspend a locally unavailable path. When NIFM remains
available, nonterminal BSD send and receive failures preserve and continue to
use the live binding. A failed handshake initiation uses the normal bounded
retransmit timer; receive failures retry the same serialized receive path after
a short backoff. This keeps remote-peer recovery separate from local-path
availability and prevents repeated close/open churn while Horizon still reports
a usable local attachment.

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
WireGuard packet was received. Consequently, a BSD send or receive failure
cannot establish that a local binding is stale. It cannot detect this class of
silent path outage; only authenticated WireGuard traffic and the protocol's
bounded recovery policy establish remote-peer reachability.

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
