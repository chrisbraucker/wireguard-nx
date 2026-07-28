# Experimental Inner IPv4 Packet API

The debug packet API is the first application-independent boundary into the WireGuard data path.
It allows one test process to submit complete inner IPv4 packets and poll decrypted IPv4 packets without using BSD sockets or the network MITM.

This API is experimental and is compiled into every development build.
`IpcApiVersion` 5 adds command 24, `Shutdown`, for an orderly sysmodule teardown initiated by `ovl-sysmodules`.
Version 4 added the manual UDP bind-bump command used by transport recovery testing.
Version 3 removed the fixed Program ID authorization used by version 2 while retaining PID-based stream ownership.
The API version must be incremented whenever the public command set, command semantics, or request/response wire layout changes so clients can reject incompatible sysmodule binaries.

## Development Access

The experimental packet commands have no Program ID allowlist.
Any process that can open `wgnx:ctl` can submit inner packets and take ownership of the packet stream.
This development policy avoids coupling the test API to one NRO forwarder while the tunnel integration architecture is still changing.

This is not a release security model.
The security model remains a major open design problem that requires careful consideration before `wgnx:ctl` is advertised as a service for other applications.
A production data plane must define deliberate service access, authorization, ownership, and isolation semantics before a stable release.

Both packet commands still request the caller PID from CMIF.
PID identity is used for stream ownership and lifecycle isolation, not as an authorization decision.

## Commands

`SubmitInnerIpv4Packet` is command 21.
It accepts one map-alias input buffer and returns `PacketSubmissionResult`.

`ReceiveInnerIpv4Packet` is command 22.
It accepts one map-alias output buffer and returns `PacketReceiveResult`.
It is nonblocking: an empty queue returns `PacketApiStatus::QueueEmpty` immediately.

Clients should use the wrappers in `common/include/wgnx/client.hpp`; both packet commands send the caller PID required by the service interface.
A client that submits a packet and waits for a response should open one `ScopedService` and pass it to `GetApiVersion`, `SubmitInnerIpv4Packet`, and every `ReceiveInnerIpv4Packet` call.
The one-shot overloads remain suitable for isolated control operations, but opening a new SM/CMIF session for every nonblocking receive poll creates unnecessary system-session churn.

`Shutdown` is command 24.
The CMIF handler only records the request and returns its reply before any server teardown begins.
The main thread then stops and joins the dedicated IPC server thread.
Before it destroys the server manager, it signals the existing completion event of every active `wgnx:tun` client context without enqueuing a completion record.
The server manager then closes `wgnx:ctl` and `wgnx:tun` sessions, and the runtime finally deactivates the selected peer through the normal lifecycle and closes transport and NIFM state.
A `wgnx:tun` client awakened during this sequence must treat a failed `ReceiveCompletions` call or any later CMIF call as terminal service loss and release its local flow state and event handle.
The shutdown wake is not a drainable `CompletionRecord` and does not add a new protocol status or completion type.
It is intended for process managers and is not a recoverable tunnel-state transition.

The submission and receive result structures report:

- a daemon-assigned packet ID
- a `PacketApiStatus` value
- packet size
- peer activation generation
- peer index

## Validation

Submissions must contain exactly one complete IPv4 packet:

- 20 bytes minimum and 1500 bytes maximum
- IPv4 version 4
- valid IHL within the supplied buffer
- IPv4 total length equal to the supplied buffer size
- valid IPv4 header checksum

Transport checksums and protocol-specific payloads are intentionally not changed by this boundary.
Keepalives remain internal WireGuard transport messages and are not valid packet API submissions.

Decrypted non-debug payloads pass through the same IPv4 validation before they enter the receive queue.
Invalid payloads are logged and dropped.

## Queue And Lifecycle Semantics

Transmit and receive queues each hold at most eight 1500-byte packets.
Submit returns `Queued`; an ordered worker performs encryption and outer UDP sending.
Packets may be queued while the selected peer is resolving or handshaking and are dispatched when that activation becomes active.

Each record carries the peer index and activation generation.
Peer deactivation, peer error, and peer replacement clear both queues.
The worker also rejects stale records defensively.

The first successful submission establishes one packet API owner PID.
A submission from a new process transfers ownership and clears queued transmit and receive data, preventing replies from a previous requester launch from leaking into the next launch.
Receive calls from a process that does not own the current packet stream return `AccessDenied`.

Queue full, queue empty, unavailable tunnel, malformed packet, stale activation, access denied, and undersized output buffer are protocol statuses, not CMIF transport failures.
For `OutputBufferTooSmall`, the packet remains at the front of the receive queue and `packet_size` reports the required size.

## Current Limits

- IPv4 only; IPv6 is rejected.
- One owner process at a time.
- Polling receive only; there is no event or blocking wait command.
- A submission ID confirms queue admission, not eventual peer delivery.
- Receive packets are not correlated to submission IDs.
  The test client must validate protocol endpoints and an unpredictable payload token.
- Queue depths and packet drops are logged but do not yet have a status/counter query command.

These constraints are deliberate for the direct requester connectivity test.
The fixed-flow UDP bridge should reuse the validated packet boundary and bounded queue semantics rather than introduce a second encryption/decryption path.
