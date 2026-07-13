# Experimental Inner IPv4 Packet API

The debug packet API is the first application-independent boundary into the
WireGuard data path. It allows one authorized test process to submit complete
inner IPv4 packets and poll decrypted IPv4 packets without using BSD sockets or
the network MITM.

This API is experimental. It is only compiled when
`WGNX_ENABLE_DEBUG_PROBE=1`, and its addition increments `IpcApiVersion` to 2.
The API version must be incremented whenever the public command set, command
semantics, or request/response wire layout changes so clients can reject
incompatible sysmodule binaries.

## Build And Authorization

Build the sysmodule with the packet API enabled:

```sh
make WGNX_ENABLE_DEBUG_PROBE=1 \
  WGNX_DEBUG_PACKET_CLIENT_PROGRAM_ID=0x05720820ABC97000
```

`WGNX_DEBUG_PACKET_CLIENT_PROGRAM_ID` defaults to the requester forwarder
Program ID shown above. Both packet commands request the caller PID from CMIF,
resolve it through `pm:info`, and return `PacketApiStatus::AccessDenied` unless
the resolved Program ID exactly matches the build-time value. Failure to start
the authorization dependency also leaves the packet API closed.

## Commands

`SubmitInnerIpv4Packet` is command 21. It accepts one map-alias input buffer and
returns `PacketSubmissionResult`.

`ReceiveInnerIpv4Packet` is command 22. It accepts one map-alias output buffer
and returns `PacketReceiveResult`. It is nonblocking: an empty queue returns
`PacketApiStatus::QueueEmpty` immediately.

Clients should use the wrappers in `common/include/wgnx/client.hpp`; both
wrappers send the caller PID required by the service interface.

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

Transport checksums and protocol-specific payloads are intentionally not
changed by this boundary. Keepalives remain internal WireGuard transport
messages and are not valid packet API submissions.

Decrypted non-debug payloads pass through the same IPv4 validation before they
enter the receive queue. Invalid payloads are logged and dropped.

## Queue And Lifecycle Semantics

Transmit and receive queues each hold at most eight 1500-byte packets. Submit
returns `Queued`; an ordered worker performs encryption and outer UDP sending.
Packets may be queued while the selected peer is resolving or handshaking and
are dispatched when that activation becomes active.

Each record carries the peer index and activation generation. Peer
deactivation, peer error, and peer replacement clear both queues. The worker
also rejects stale records defensively.

The first successful submission establishes one packet API owner PID. A
submission from a new authorized process transfers ownership and clears queued
transmit and receive data, preventing replies from a previous requester launch
from leaking into the next launch. Receive calls from a process that does not
own the current packet stream return `AccessDenied`.

Queue full, queue empty, unavailable tunnel, malformed packet, stale
activation, access denied, and undersized output buffer are protocol statuses,
not CMIF transport failures. For `OutputBufferTooSmall`, the packet remains at
the front of the receive queue and `packet_size` reports the required size.

## Current Limits

- IPv4 only; IPv6 is rejected.
- One authorized consumer process at a time.
- Polling receive only; there is no event or blocking wait command.
- A submission ID confirms queue admission, not eventual peer delivery.
- Receive packets are not correlated to submission IDs. The test client must
  validate protocol endpoints and an unpredictable payload token.
- Queue depths and packet drops are logged but do not yet have a status/counter
  query command.

These constraints are deliberate for the direct requester connectivity test.
The fixed-flow UDP bridge should reuse the validated packet boundary and
bounded queue semantics rather than introduce a second encryption/decryption
path.
