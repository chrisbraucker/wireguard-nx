# Transport Recovery

WireGuard peer state and the Horizon UDP socket have separate lifecycles. A
temporary uplink failure must not discard peer configuration, keypairs,
handshake state, timers, or queued inner packets merely because the current BSD
socket can no longer send or receive.

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
