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

While a peer is selected, the sysmodule samples NIFM every two seconds and logs
only changes to this path fingerprint:

- Internet connection query result, connection type, status, and Wi-Fi strength
- IP configuration query result
- local IPv4 address, subnet mask, gateway, and DNS servers

This observer is deliberately passive. NIFM's Internet status is not endpoint
reachability: a LAN WireGuard peer may remain usable when Horizon reports no
Internet connection. Recovery must therefore not be gated on a `Connected`
status. Later automation may treat a fingerprint change as one input to the
same bind-bump operation, with transport failures as a fallback.

Endpoint hostname re-resolution is not part of the manual bind bump yet. It
belongs in automated path recovery after the socket lifecycle is validated.

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
