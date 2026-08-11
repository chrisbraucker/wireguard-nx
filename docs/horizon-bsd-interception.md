# Horizon BSD:S Interception and Tunnel Flow

## Status and Evidence

This document records the Horizon BSD:S behavior relevant to the project and the narrow TCP translation derived from it.
The service-acquisition, session, descriptor, and BSD operation observations are implementation facts from the current MITM path and the companion Horizon probing work.
The Toolbox-only TCP path passes host checks and a target build, but remains subject to the focused real-peer acceptance routine in `docs/task-7-tcp-flow-foundation.md`.
It is not evidence of general BSD TCP compatibility or system-wide routing.

## Relevant Horizon Boundary

Horizon applications use the BSD:S service rather than calling the WireGuard sysmodule directly.
Atmosphere asks the MITM policy whether to intercept when a process acquires `bsd:s`, before the first BSD CMIF command is available.
The decision therefore cannot depend on `RegisterClient`, socket arguments, or another later request.

The current policy admits only the build-configured Toolbox forwarder `ams::ncm::ProgramId`.
The WireGuard and MITM sysmodule IDs are unconditional exclusions.
Every other program ID receives the original BSD:S service without entering the project MITM.

After admission, the server acknowledges the MITM session and receives both the original BSD:S forward service and the client process identity.
The session implementation owns a small descriptor table and forwards unknown requests unchanged.
`RegisterClient` remains on Atmosphere's generic forwarding path because it carries the original PID descriptor and a duplicated transfer-memory handle that must retain Horizon's normal tagging and cleanup behavior.
The observed short-lived monitoring sessions also remain generic forwarded sessions.

## One-Time Route Selection

The MITM forwards `socket()` to BSD:S first and records only IPv4 UDP or IPv4 TCP descriptors in a fixed four-entry table.
Each recorded descriptor starts in `Created` state.
The first valid `connect()` performs the one-time route decision.

```text
Toolbox BSD socket call
        |
        v
bsd:s MITM session
        |
        +-- unsupported socket or non-Toolbox process --> original BSD:S
        |
        v
tracked IPv4 UDP or TCP descriptor in Created state
        |
        v
wgnx:tun discovery and OpenConnected*Flow
        |
        +-- RouteNotCovered or temporary tunnel unavailable --> original BSD:S connect
        |
        +-- tunnel policy block --> defined BSD error without direct fallback
        |
        +-- protocol error --> terminal BSD error
        |
        `-- tunnel flow opened --> virtual BSD socket operations
```

After the direct or tunneled path is selected, the descriptor does not migrate because service availability or routing policy changes.
An established tunneled descriptor reports later tunnel failure as a BSD error rather than falling back to direct BSD traffic.
This preserves the application's one-socket route expectation and prevents a later silent route change.

## Ownership Flow

```text
Toolbox
  -> libnx BSD:S client
  -> Atmosphere bsd:s MITM
  -> bounded TunnelFlowWorker
  -> private wgnx:tun client IPC
  -> WireGuard flow plane
  -> serialized lwIP adapter owner
  -> complete inner IPv4 packets
  -> WireGuard peer and outer Horizon UDP transport
```

The MITM translates BSD socket semantics and owns no IP, UDP, TCP, retransmission, congestion-control, fragmentation, or reassembly implementation.
The WireGuard sysmodule owns virtual tuple allocation, lwIP PCB state, Layer 3 packets, transport progress, and tunnel recovery.
The private API returns only flow handles, bounded payload records, completion records, flow state, and closed status outcomes.

The MITM worker is the sole owner of `wgnx:tun` service-manager requests, root and child CMIF sessions, and completion-event handles.
BSD dispatch only submits fixed-capacity operations to that worker and waits according to each BSD operation contract.
This keeps Horizon BSD dispatch from sharing raw WireGuard IPC handles or lwIP state.

## Confirmed Narrow TCP Translation

The TCP translation begins only for `socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)` or its protocol-zero equivalent.
Socket options applied before route selection still use the retained BSD descriptor.
Once the MITM selects the tunnel, it opens `OpenConnectedFlow` with TCP kind and waits on that flow's completion event for the flow-state transition.

The worker accepts `FlowState::Open` only after a successful `GetFlowState` response identifies the flow as TCP and supplies a nonzero advertised virtual local tuple.
The wait has a six-second MITM guard in addition to the WireGuard-owned connection lifecycle timeout.
On success, the MITM records the original remote tuple and the WireGuard-advertised local tuple, then transitions the descriptor to `Tunneled`.

The successful TCP `connect()` is not forwarded to BSD:S.
The retained BSD descriptor remains unconnected and exists solely to preserve the application-visible descriptor lifecycle until `close()`.
This prevents a second native TCP handshake and a direct connection outside the tunnel.

| BSD:S operation | Narrow tunneled TCP behavior |
| --- | --- |
| `connect` | Opens and waits for TCP `OpenConnectedFlow`, then records virtual endpoints without native BSD:S connect. |
| `getsockname` | Returns the WireGuard flow's advertised virtual local tuple. |
| `getpeername` | Returns the original requested remote tuple. |
| `send` | Submits one bounded `WriteTcpStream` request and reports all-or-`EAGAIN` admission. |
| `recv` | Copies ordered `InboundTcpStream` records and retains an unread suffix after a short application buffer. |
| `poll` | Reports readable buffered bytes, write capacity, or `POLLHUP` after remote EOF and buffer drain. |
| `shutdown(SHUT_WR)` | Calls `ShutdownTcpWrite`. |
| `close` | Retires the private flow, clears MITM state, then closes the retained BSD descriptor. |

The initial path rejects mixed direct and virtual polls, `recvfrom` on TCP, `sendto` on any tunneled connected flow, unsupported message flags, virtual `bind`, post-connect socket options, and shutdown directions other than `SHUT_WR`.
`POLLERR` remains intentionally unused because the private flow API has no per-flow asynchronous-error contract.

## Virtual Endpoint Ownership

UDP follows the same route-selection, endpoint, and payload-delegation structure as TCP.
After UDP `OpenConnectedFlow`, the MITM worker takes the WireGuard-allocated virtual UDP tuple from the successful open result and returns it from `getsockname`.
The retained BSD descriptor remains unconnected for every successfully tunneled flow and exists only for Horizon descriptor lifecycle and close.
This removes unrelated native BSD routing state and makes UDP and TCP resource ownership symmetric.

## Scope Limits

The confirmed path applies only to the configured Toolbox forwarder and only to the operation subset documented above.
It does not establish interception behavior for arbitrary application programs, DNS, SSL, IPv6, listening sockets, accept, nonblocking connect, generalized socket options, or multiple virtual descriptors in one poll.
Native Horizon interface and routing integration remain separate reversing work.
The BSD MITM is a practical first transparent path, not evidence that it is the final system-wide VPN integration point.
