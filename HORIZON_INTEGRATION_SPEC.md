# Horizon Integration Specification

## Purpose

This document specifies the first private flow IPC contract in [Horizon Integration Plan](HORIZON_INTEGRATION_PLAN.md).
The contract is the boundary between Horizon-facing consumers, initially the separate BSD MITM sysmodule, and the WireGuard tunnel data plane.
It is intentionally narrow enough to implement and test without pretending to support generic IP or TCP socket behavior.

This is an active-development private API rather than a stable public interface.
The service does not authenticate, whitelist, or pin callers during the current research phase.
It still validates all inputs, maintains fixed resource limits, and returns defined errors because caller permissiveness is not a reason to weaken memory safety or lifecycle correctness.

## Scope And Non-Goals

The first contract version supports connected IPv4 UDP flows only.
A client opens a logical flow for one remote IPv4 endpoint, submits UDP payloads, and receives matching UDP payloads with their remote source endpoint.
The WireGuard sysmodule selects the active peer, owns the tunnel source IPv4 address and virtual UDP source port, constructs and parses inner IPv4 and UDP packets, and retains all tunnel-facing flow mappings.
The current implementation performs that work in its bounded UDP flow plane, while the planned fragmentation milestone replaces the manual transport and IP adapter with a WireGuard-owned userspace IP stack behind the same client-facing ownership boundary.

The contract does not expose arbitrary raw inner IPv4 packets, unconnected UDP `sendto` behavior, TCP, listeners, DNS, socket options, or general native L3 routing.
The existing `wgnx:ctl` raw packet API remains a diagnostic and protocol-validation boundary with its existing API version and semantics.
It is not the ordinary client transport API.

The UDP flow API is one BSD-facing protocol adapter over a WireGuard-owned userspace IP adapter and shared inner-packet plane.
Route selection, source tuple allocation, transport state, packet construction, effective-MTU handling, fragmentation, reassembly, reverse-flow delivery, bounded packet storage, and WireGuard submission belong inside the WireGuard sysmodule.
UDP payload IPC and a future TCP or lower-layer source must use explicit adapters over that shared implementation rather than duplicate those responsibilities in the MITM.
This separation is critical before TCP work because a BSD MITM observes socket operations and payloads rather than kernel-produced IP packets.

The MITM owns Horizon BSD interception, descriptor and process bookkeeping, BSD-visible endpoints, operation translation, readiness, error mapping, and the one-time direct-versus-tunnel socket decision.
An uncovered socket remains on its retained Horizon BSD descriptor.
A tunneled socket delegates payload work to the WireGuard sysmodule and never falls back silently to BSD after selection.
The MITM does not construct, parse, fragment, reassemble, or demultiplex IP packets.

The userspace IP adapter is not part of the WireGuard cryptographic protocol core.
It converts BSD-level flow operations to and from complete inner IP packets, while `PeerRuntime` and the shared packet plane continue to transport authenticated opaque inner packets.
Userspace IP stack calls, callbacks, pbuf operations, and timeout processing must run through one serialized post-lock owner and never while the daemon state mutex is held.
WireGuard handshake cookie replies are stateless encrypted-transport control traffic and bypass the flow IPC only to return to their received UDP endpoint.
They never update the authenticated peer endpoint or enter BSD routing policy.

An unconnected UDP extension requires a bounded per-destination association table and an explicit policy for destinations that stop matching a tunnel route.
That extension is deferred rather than being hidden behind ambiguous direct-flow behavior.
TCP must introduce stream-specific operations and lifecycle semantics rather than being modeled as UDP payloads with a different protocol number.

## Service And Versioning

The service name is `wgnx:tun`.
Its current contract version is `TunApiVersion = 3` and is independent from the existing `wgnx:ctl` development API version.
An incompatible change to command shapes, result semantics, handle lifetime, or delivery behavior increments `TunApiVersion`.
Additive optional behavior may be introduced only when its absence is observable through an explicit capability or version query.

The first command set is conceptually:

| Operation                  | Purpose                                                                                                      |
|----------------------------|--------------------------------------------------------------------------------------------------------------|
| `GetTunApiVersion`         | Returns the private flow API version and supported capability bits.                                          |
| `OpenTunnelClient`         | Creates a logical client context and returns its private object interface.                                   |
| `GetRoutingPolicySnapshot` | Returns a read-only, generation-tagged view of effective active `AllowedIPs` routes for a client context.    |
| `GetCompletionEvent`       | Returns the one manual-clear readiness event owned by a client context.                                      |
| `OpenConnectedUdpFlow`     | Atomically selects a peer for a remote IPv4 UDP endpoint and allocates an opaque flow in the client context. |
| `SendUdpDatagram`          | Queues one validated UDP payload for a live flow as a convenience operation.                                 |
| `SendUdpDatagramBatch`     | Submits a bounded descriptor array and payload buffer with a disposition for every entry.                    |
| `ReceiveCompletions`       | Drains bounded datagram, flow-state, policy, and writable-transition records for the client context.         |
| `GetFlowState`             | Returns lifecycle, peer-activation, route, and bounded diagnostic state.                                     |
| `CloseFlow`                | Idempotently closes a client flow and releases its resources.                                                |

Command IDs, exact CMIF buffer attributes, result codes, and fixed capacity values are implementation details that must be recorded beside the IPC definitions before the first buildable implementation.
They must not be inferred by clients from struct layout or service implementation details.
The version response must advertise effective inner MTU, maximum payload size, flow and queue limits, batch limits, supported completion types, and optional capabilities so clients do not infer resource limits.

### Version 3 ABI Record

The version 3 declarations live in `common/include/wgnx/tunnel_protocol.hpp`.
They are intentionally separate from `wgnx/protocol.hpp` so the raw diagnostic API remains unchanged.
`wgnx:tun` is registered with the bounded flow data plane supplied by implementation step 3.
Clients must validate `Capabilities.api_version` and the advertised limits before opening flows.
Version 3 preserves every prior command ID and wire record layout.
It adds the `LeakProtection` capability and `TunnelBlockedByPolicy` result so a client can distinguish an optional direct pass-through decision from a selected route that policy requires it to block.
Version 2 changed completion-event delivery during orderly sysmodule shutdown, so a version 1 client cannot assume every event wake has a drainable completion record.

All scalar IPC fields use the Switch little-endian ABI.
IPv4 addresses are four network-order octets.
UDP ports are host-order `u16` values because the private ABI is not a raw `sockaddr` representation.
Every request and response structure is trivially copyable and has compile-time layout checks in the shared header.

| Root command ID | Operation          | Input | Output                                 |
|----------------:|--------------------|-------|----------------------------------------|
|               0 | `GetTunApiVersion` | None  | `Capabilities` with `api_version = 3`. |
|               1 | `OpenTunnelClient` | None  | A shared `ITunnelClient` CMIF object.  |

| Client command ID | Operation                  | Input                                                                              | Output                                                                 |
|------------------:|----------------------------|------------------------------------------------------------------------------------|------------------------------------------------------------------------|
|                 0 | `GetCapabilities`          | None                                                                               | `Capabilities`.                                                        |
|                 1 | `GetRoutingPolicySnapshot` | An output `RouteRecord` map-alias array.                                           | `RoutingPolicySnapshot` and copied route count.                        |
|                 2 | `GetCompletionEvent`       | None.                                                                              | One copy handle for the context-owned manual-clear event.              |
|                 3 | `OpenConnectedUdpFlow`     | `OpenConnectedUdpFlowRequest`.                                                     | `OpenConnectedUdpFlowResult`.                                          |
|                 4 | `SendUdpDatagram`          | `DatagramDescriptor` and one input map-alias payload buffer.                       | One `DatagramDisposition`.                                             |
|                 5 | `SendUdpDatagramBatch`     | Input `DatagramDescriptor` map-alias array and one input map-alias payload buffer. | One output `DatagramDisposition` map-alias array entry per descriptor. |
|                 6 | `ReceiveCompletions`       | Output `CompletionRecord` map-alias array and one output map-alias payload buffer. | Copied completion count and `ProtocolStatus`.                          |
|                 7 | `GetFlowState`             | `FlowHandle`.                                                                      | `FlowStateResult`.                                                     |
|                 8 | `CloseFlow`                | `FlowHandle`.                                                                      | `ProtocolStatus`.                                                      |

`DatagramDescriptor.payload_offset` and `DatagramDescriptor.payload_size` identify a complete payload inside the command's payload buffer.
The command rejects descriptors whose range is outside that buffer and returns an individual `MalformedInput` disposition rather than consuming adjacent bytes.
`CompletionRecord.payload_offset` and `CompletionRecord.payload_size` use the caller-provided output payload buffer in the same way.
`ReceiveCompletions` returns only complete datagrams and leaves a datagram queued when the supplied output payload buffer cannot hold it.
It returns `OutputBufferTooSmall` with no partial record in that case.

| Resource limit or default        |                 Value | Meaning                                                                                               |
|----------------------------------|----------------------:|-------------------------------------------------------------------------------------------------------|
| Logical client contexts          |                     4 | Each context has one readiness event and its own flow namespace.                                      |
| Flows per client                 |                     4 | A context may not consume all global flow capacity.                                                   |
| Global flows                     |                    16 | The product of the client and per-client limits.                                                      |
| Default effective inner MTU      |            1420 bytes | Conventional WireGuard interface MTU for a 1500-byte Ethernet path when `[Interface] MTU` is omitted. |
| Maximum UDP payload              | 1392 bytes by default | Active effective inner MTU minus 20 IPv4 header bytes and 8 UDP header bytes.                         |
| Outbound packet slabs            |                    16 | Global payload ownership for client-to-tunnel packets.                                                |
| Inbound packet slabs             |                    16 | Global payload ownership for tunnel-to-client packets.                                                |
| Inbound datagrams per flow       |                     4 | A per-flow quota in addition to global slab capacity.                                                 |
| Completion queue entries         |                    16 | Per-client records with reserved or coalesced lifecycle capacity.                                     |
| Batch entries                    |                     8 | Maximum descriptors and dispositions in one command.                                                  |
| Policy route records             |                    16 | Maximum normalized routes returned by one snapshot.                                                   |
| Kernel handles per client        |                     1 | The readiness event copy handle only.                                                                 |
| Reverse tuple quarantine records |                    16 | One retained tuple slot per maximum live flow.                                                        |

The fixed limits are deliberately modest for the first measurement path.
They reserve 32 maximum-payload slab slots across both directions plus 16 reverse-tuple quarantine records before the existing runtime, CMIF object state, and packet headers are counted.
The current target build gates the flow plane at 80 KiB and the composed daemon at 272 KiB.
Any fixed resource-capacity change that changes a client-visible `Capabilities` value requires a documented compatibility review and a new API version when a client cannot safely adapt at runtime.
The active profile MTU is intentionally dynamic and is reported through `Capabilities` after every policy transition.

`FlowHandle` is one opaque 64-bit value.
Its allocation and generation encoding is private to the WireGuard sysmodule and clients must not decode, compare by numeric ordering, or construct a handle.
The implementation validates the encoded client context, allocation generation, and active peer-activation generation before every flow operation.

## Routing Authority And Policy Visibility

The WireGuard sysmodule is the authoritative owner of cryptokey route selection.
`OpenConnectedUdpFlow(remote)` atomically evaluates the active effective `AllowedIPs` policy and either selects a live peer or returns a defined result.
The MITM must not reproduce CIDR precedence or peer selection as a second routing implementation.
The first implementation must parse configured `AllowedIPs` into normalized CIDR entries and perform deterministic longest-prefix selection.
The currently active single-peer runtime may be the only selectable peer in v1, but the route result must still be produced by the normalized route engine rather than a string or nonempty-policy check.

`GetRoutingPolicySnapshot` exists for traceability, diagnostics, and policy-aware MITM decisions.
Each snapshot contains a monotonically changing policy generation and a read-only normalized route list with address family, network address, prefix length, and an optional non-secret opaque route identifier.
The snapshot is advisory because it can become stale before a flow is opened.
Policy transitions enqueue a `PolicyChanged` completion so a client can refresh the snapshot without polling.

`OpenConnectedUdpFlow` returns `RouteNotCovered` when no active tunnel route covers the remote endpoint.
It returns `PeerUnavailable` when no selected peer exposes an effective policy and `TransportUnavailable` when a matching selected route has no local tunnel transport yet.
With the optional profile-owned `[Interface] LeakProtection = true` setting, the latter case returns `TunnelBlockedByPolicy` instead.
The setting defaults to `false` when absent.
The MITM must pass the original BSD operation through for `RouteNotCovered`, `PeerUnavailable`, and `TransportUnavailable`.
It must fail the BSD connect with `ENETUNREACH` for `TunnelBlockedByPolicy` and must not create a direct fallback for that socket.
Only the WireGuard sysmodule parses the profile setting and makes this decision.
The MITM remains configuration-stateless and consumes the typed result from `wgnx:tun`.
If `wgnx:tun` itself is absent or its CMIF session fails, the MITM remains fail-open because no authoritative selected-profile policy is available.
An opened flow remains pinned to its selected peer activation and is never silently rerouted or converted to direct traffic by a later policy change.
If a policy or peer transition makes that selection invalid, the flow reaches an explicit terminal state and the client decides how the BSD socket reports it.

## Client Context, Flow Identity, And Ownership

`OpenConnectedUdpFlow` returns an opaque generation-tagged `FlowHandle`.
The handle identifies no tunnel table address, virtual source port, or peer configuration.
The sysmodule rejects malformed, closed, unknown, stale-generation, and cross-client handles.

`OpenTunnelClient` creates one logical client context that owns its flows, completion queue, diagnostics, and one manual-clear readiness event.
Cloned IPC sessions may issue concurrent commands against the same object context without creating new flow ownership domains or new readiness events.
Closing one physical CMIF session only releases that reference.
Closing the final reference closes all flows owned by the logical client context through the same idempotent lifecycle path as `CloseFlow`.
The MITM maps one virtual BSD UDP socket to one live `FlowHandle` in v1.
Before the ABI is frozen, a target-side service test must prove that the selected CMIF object and session-cloning mechanism preserves this shared object lifetime and final-reference cleanup.

Each live flow retains at least:

- owner client-context identity
- opaque handle and allocation generation
- selected peer and peer-activation generation
- routing-policy generation used at open
- protocol and connected remote IPv4 endpoint
- tunnel IPv4 source address and allocated virtual UDP source port
- creation and last-activity timestamps
- bounded inbound occupancy and disposition counters
- lifecycle state and terminal reason
- optional caller-provided opaque diagnostic tag

Peer deactivation, peer-activation transition, client-context teardown, and sysmodule restart invalidate affected flows.
No flow mapping survives those transitions.
WireGuard key-session rotation and an outer UDP binding replacement do not by themselves invalidate a logical inner flow.
Flow identity is guarded by client-context, flow-allocation, and peer-activation generations.
Outer binding generations guard only transport effects, socket completions, and datagrams associated with a replaced outer socket.
This distinction is critical because a binding generation is not present in a decrypted inner UDP tuple and must not be used as an inbound flow-delivery requirement.

The virtual UDP source-port allocator must quarantine or tombstone a released reverse tuple before reuse.
The quarantine interval and exhaustion behavior are fixed and documented.
This prevents a delayed valid inner packet from being delivered to a newly allocated flow whose generation is not encoded on the wire.

## Datagram Submission And Delivery

`SendUdpDatagram` accepts a `FlowHandle` and one caller-owned payload buffer.
The payload is copied or synchronously consumed before the IPC command returns, and the caller retains no borrowed buffer lifetime obligation afterwards.
The caller cannot supply an IPv4 source address, UDP source port, peer identity, or preconstructed IP header.

The sysmodule validates the payload size against the active profile-derived maximum datagram size and validates the flow before admitting work to bounded queues.
It constructs the IPv4 and UDP headers from flow state, calculates required checksums, and inserts the resulting packet through the existing bounded peer-owned tunnel path.
Resource exhaustion, inactive transport, stale flow state, and closed flow state are returned as distinct result categories and counted.
When peer-owned outbound staging is full, the direct-flow API rejects the new datagram with `QueueFull`, retains no submitted payload, and emits a coalesced `Writable` completion for each waiting flow whenever a staged packet retires and frees admission capacity.
This includes both a successful outer UDP submission and a nonterminal outer transport drop.
This differs intentionally from WireGuard's netdevice boundary, where upstream implementations may evict queued packets, because the separate MITM must own any packet-drop policy and preserve an explicit backpressure signal to its IPC client.
For v1, the maximum UDP payload is the effective inner MTU minus the IPv4 and UDP header sizes.
An omitted `[Interface] MTU` resolves to 1420 bytes.
An explicit value must be in the IPv4-safe 576 to 1500-byte range.
The 1500-byte packet slabs are storage capacity only and must not be interpreted as a client-visible transmission guarantee.
The transport writer follows wireguard-go's 16-byte padding calculation and never pads the final active-MTU unit beyond the effective inner MTU.
Larger payloads return `DatagramTooLarge` until an explicit fragmentation contract is designed and implemented.
That later contract is owned by the WireGuard userspace IP adapter rather than the MITM.
It must preserve BSD UDP send atomicity for every advertised size, apply the effective inner MTU, and expose a measured bounded maximum through capabilities.
The maximum may remain below 65,507 bytes until IPC transfer and target memory measurements justify the full theoretical IPv4 UDP size.

The receive path parses and validates decrypted inner packets before reverse-flow matching.
The shared packet plane first verifies that the decrypted source address belongs to the authenticating peer's AllowedIPs before the IP adapter or any other plaintext consumer can observe the packet.
The userspace IP adapter then validates IPv4 structure, reassembles fragments within fixed limits, validates the resulting transport packet, and demultiplexes it to a live flow.
The reverse key is `(protocol, tunnel destination address, tunnel destination port, remote source address, remote source port)`.
Only a packet matching a live flow of the same peer activation may be delivered.
Malformed packets, packets for an unknown flow, stale-generation packets, queue-overflow packets, and packets with a mismatched remote endpoint are dropped and counted without reaching the MITM.

Inbound and outbound payload storage comes from fixed-capacity global packet slabs rather than a maximum-size packet array embedded in every flow.
The client completion queue retains inbound slab indices and metadata, while each flow tracks only its occupancy against a fixed per-flow quota.
Admission fails with an explicit disposition when the global slab or a per-flow limit is exhausted.
This global bound is critical because memory consumption must scale with the configured system-wide packet budget rather than `flow count * queue depth * maximum datagram size`.

`SendUdpDatagramBatch` consumes a fixed-capacity descriptor array plus one map-alias payload buffer and returns one disposition for every submitted descriptor.
It may accept only a prefix or subset when bounded capacity is exhausted, and the response must identify every accepted and rejected entry without requiring payload replay inference.
For a batch whose descriptors all belong to one connected flow, admission is evaluated in descriptor order under the flow-plane lock.
Successful dispositions therefore form a prefix, and a `QueueFull` disposition retains that descriptor and its suffix for the adapter to retry without reordering the socket's UDP submissions.
`ReceiveCompletions` fills a fixed-capacity completion array plus one caller-provided payload buffer and returns as many complete records as fit.
It never emits a partial datagram.
The single-datagram send operation remains a convenience wrapper over the same admission path and does not define separate behavior.

## Readiness And Push Delivery

Each logical client context has one sysmodule-owned manual-clear completion event.
`GetCompletionEvent` returns a copy handle for that event, and the client waits on it without clearing it.
The event represents a nonempty bounded completion queue rather than one flow or one packet.

Completion records are tagged with `FlowHandle` where applicable and distinguish at least inbound datagram, terminal flow state, routing-policy change, and writable transition.
The writable transition exists so a BSD adapter can implement nonblocking send and readiness semantics without polling every flow.
Datagram completions may be dropped with an explicit disposition when their bounded queue is full.
Terminal, policy, and writable-state information must use reserved capacity or coalesced state so datagram pressure cannot erase the latest lifecycle truth.
The sysmodule signals the event after enqueueing a completion while holding the client queue synchronization.
The sysmodule clears the event only while holding the same synchronization and only after observing that the completion queue is empty.
This ownership prevents a client-side clear race from losing an inbound readiness transition.

Orderly sysmodule shutdown is the sole exception to the nonempty-queue meaning of the readiness event.
After the control shutdown handler has replied and the CMIF server loop has stopped, the sysmodule signals every active client event without enqueueing a completion record.
It retains the terminal static server manager and returns from `ams::Main`, allowing Horizon process teardown to close all root and child `wgnx:tun` sessions and their handles.
A client woken by this signal must attempt its normal completion drain and treat CMIF failure from that call, or from any subsequent tunnel command, as terminal service loss.
It must release its local flow mappings and completion-event handle instead of retrying the closed session.
This wake does not use `FlowStateChanged`, `FlowTerminalReason::SysmoduleShutdown`, or a new protocol status because the service cannot guarantee delivery of a drainable record while it is closing the session that carries it.

After a wake, the client drains `ReceiveCompletions` until it returns `QueueEmpty`.
The event is a context readiness notification rather than a packet count.
The contract does not provide an unbounded blocking receive CMIF command because that would consume an IPC worker through arbitrary client lifetimes and complicate client exit, shutdown, and ownership cleanup.

Transport suspension does not permanently signal every flow.
It is observable through send dispositions, `GetFlowState`, and edge-triggered state completions where a client must update BSD readiness.
Terminal close, peer invalidation, or another flow-local terminal transition enqueues a completion so a waiting client can retire its BSD-facing socket state promptly.

## Endpoint Semantics

The tunnel source tuple is internal to the WireGuard sysmodule.
It is not the local endpoint visible to Horizon applications.
The MITM owns the logical BSD socket's bind state and the `getsockname` semantics it exposes to a client.

For a successfully tunneled connected IPv4 UDP socket, `GetSockName` returns the ordinary device-facing IPv4 address and native ephemeral port selected for the retained upstream BSD descriptor.
The MITM forwards exactly the socket's initial UDP `Connect` to that descriptor after WGNX flow creation only to establish this Horizon-visible endpoint and retain normal descriptor lifecycle behavior.
The adapter captures that endpoint immediately through upstream `GetSockName`, stores it in the BSD socket state, and never exposes the WireGuard interface address or tunnel source port to the application.
The adapter does not forward payload or later routed endpoint operations through that descriptor.
`GetFlowState.advertised_local` remains tunnel-layer diagnostic data and is not a BSD-visible endpoint source.
If the retained descriptor cannot establish or report a valid local endpoint, the MITM closes the newly created WGNX flow and makes the socket terminal with `EIO` rather than exposing an incomplete or leaking tunnel state.
Before a successful `Connect`, `GetSockName` retains ordinary upstream BSD behavior.
The visible endpoint is a per-socket snapshot, so later interface changes affect newly connected sockets rather than rewriting the identity of an existing tunneled flow.

## BSD Adapter Requirements

### Requester-Only V1 Surface

The first active `bsd:s` adapter is restricted to requester forwarder title ID `0x0515C00B3A04A000`.
It admits every BSD service session for each requester process because SM requests the MITM decision before the adapter can inspect `RegisterClient` or `StartMonitoring`.
Observed `StartMonitoring` sessions are short-lived and use the generic forward path after admission.
The `RegisterClient` session owns the descriptor table used by later socket commands.
`RegisterClient` is not reimplemented by the adapter.
It uses Atmosphere's generic forwarder so the original process ID uses Mesosphere's tagged MITM restoration protocol and the MITM-owned duplicate request copy handle is closed after forwarding.
This is a diagnostic scope boundary rather than a general process-admission policy.

The implemented tunneled surface is connected IPv4 UDP through `Socket`, `Connect`, `Fcntl`, `Send`, `Recv`, `RecvFrom`, one-descriptor `Poll` with `POLLIN` and `POLLOUT`, `GetPeerName`, `GetSockName`, and `Close`.
`Socket` always forwards to the original `bsd:s` service and the returned descriptor remains the Horizon lifecycle anchor.
An uncovered destination, an inactive selected peer, or a selected route with transport unavailable and leak protection disabled forwards its `Connect` and all later operations to upstream BSD.
`TunnelBlockedByPolicy` fails the `Connect` with `ENETUNREACH` and leaves the descriptor without a route decision so a later application-issued `Connect` can be evaluated again.
Once `OpenConnectedUdpFlow` and retained-descriptor endpoint capture succeed, `Send`, `Recv`, `RecvFrom`, and `POLLIN` are served from the matching private flow and a later tunnel failure never changes that socket back to upstream BSD.

The V1 tunneled socket is always nonblocking.
The requester reads its existing flags with `F_GETFL` and then enables the Horizon BSD:S nonblocking wire flag with `F_SETFL` after `Connect`.
A tunneled descriptor virtualizes `F_GETFL` as the BSD:S `O_NONBLOCK` wire value `0x800` and accepts only `F_SETFL(0x800)`.
This is a service ABI value, not the sysmodule toolchain's `O_NONBLOCK` macro, whose value differs.
The v1 errno mapping is `QueueFull` to `EAGAIN`, empty receive to `EAGAIN`, closed flow to `ECONNABORTED`, oversized payload to `EMSGSIZE`, policy-blocked connect to `ENETUNREACH`, unsupported operation to `EOPNOTSUPP`, and other worker or CMIF failures to `EIO`.
Tunneled `Send`, `Recv`, and `RecvFrom` accept only zero message flags.
Tunneled `Poll` accepts exactly one descriptor and only `POLLIN` and `POLLOUT` request bits.
`SendTo`, `Bind`, `SetSockOpt`, and `Shutdown` on a tunneled connected socket return `EOPNOTSUPP`.
Mixed direct and tunneled descriptor arrays in `Poll` return `EOPNOTSUPP` rather than presenting ambiguous readiness.
The requester workload uses `POLLIN` for echo delivery and uses `POLLOUT` only after a tunneled `Send` reports `EAGAIN` from bounded adapter or WGNX staging pressure.
`POLLOUT` indicates that the worker has observed a coalesced WGNX `Writable` completion after an earlier `QueueFull` result and that the bounded adapter FIFO can admit another payload.
It is not a general guarantee that every later send will succeed.
BSD operations outside this requester-only surface are not compatibility guarantees.
Each needs typed rejection or a documented adapter and test coverage before the admission policy expands beyond requester.

The private flow API does not itself define Horizon descriptor numbers or BSD call behavior.
The MITM retains a real descriptor from the original `bsd:s` service for every intercepted socket so Horizon descriptor allocation, local endpoint selection, close, and descriptor reuse remain anchored in the upstream namespace.
An uncovered connected socket remains on that original path.
A tunnel-covered socket forwards only its initial UDP `Connect` to establish the retained descriptor's visible endpoint, then maps that descriptor to one `FlowHandle` and suppresses upstream payload and later routed endpoint operations.
The MITM never changes an established tunneled socket to direct BSD transport after a tunnel failure.

The first supported BSD subset is nonblocking and readiness-driven.
`Send` copies an accepted payload into the bounded MITM adapter FIFO without waiting for WGNX queue capacity or outer UDP transmission and returns `EAGAIN` on local adapter pressure.
The worker submits up to four FIFO entries at a time only for the WGNX child client that owns that BSD socket.
The adapter owns eight fixed 1472-byte payload slots globally and limits each BSD socket to four slots, so batch storage remains bounded independently from the WireGuard sysmodule's packet slabs.
If WGNX reports `QueueFull`, the worker retains the unsubmitted FIFO suffix and makes the socket non-writable until it consumes a coalesced `Writable` completion.
`Recv` and `RecvFrom` return `EAGAIN` until inbound data is available.
`Poll` is the only V1 wait operation and reports `POLLIN`, coalesced `POLLOUT` recovery after queue pressure, timeout, or `POLLHUP` on terminal flow closure.
Timeout and ordinary readiness return a nonnegative count with errno zero, while worker ingress or pending-poll capacity rejection returns `-1` with `EAGAIN` and worker or CMIF failure returns `-1` with `EIO`.
V1 does not use `POLLERR` because it has no per-flow asynchronous error state.
Blocking-mode behavior, socket-option virtualization, multi-descriptor polling, and arbitrary BSD operation support are deferred extensions.
Typed WGNX flow statuses and dispositions map to documented BSD return values and errno values.
Unsupported operations fail explicitly before they can create a split state between the retained BSD descriptor and the WGNX flow.

The MITM and WireGuard sysmodule program identities are unconditional `bsd:s` interception exclusions.
This exclusion remains active for a default route such as `0.0.0.0/0` and prevents recursive interception of the WireGuard outer UDP socket.

### BSD Socket Route States

The MITM tracks every retained descriptor as `Created`, `OpeningTunnel`, `Direct`, `Tunneled`, `Failed`, or `Closed`.
`Created` may select either a direct path or one tunnel flow during its first supported `Connect`.
`Direct` remains direct for the descriptor lifetime and later tunnel availability cannot migrate it.
`OpeningTunnel` is internal to synchronous flow opening and rejects reentrant connect attempts.
`Tunneled` serves the defined adapter surface only through WGNX and rejects unsupported calls explicitly.
`Failed` rejects data and endpoint operations with a terminal BSD error or `POLLHUP` and never falls through to the retained upstream descriptor.
`Closed` is recorded before the descriptor is forgotten and its upstream close is issued.
The policy-blocked connect outcome returns the descriptor to `Created` so a later application-issued `Connect` may be evaluated against updated policy.

## States, Results, And Limits

The minimum flow lifecycle states are `Open`, `Suspended`, `Closing`, and `Closed`.
State results include the flow allocation generation, selected peer-activation generation where applicable, and a terminal reason for closed flows.
The public state shape must not expose mutable peer internals or cryptographic material.

The implementation defines and centrally records fixed limits for total flows, flows per client context, maximum datagram size, queued inbound datagrams per flow, total queued inbound datagrams, and all allocation or queue admission timeouts.
Every full queue, rejected datagram, stale completion, unmatched inbound packet, and terminal discard has a bounded counter suitable for diagnostics.
The sysmodule drops excess traffic predictably instead of allocating beyond its defined resource budget.
The implementation also centrally records client-context count, kernel-handle use, packet-slab capacity by direction, completion-queue capacity, batch limits, and reverse-tuple quarantine capacity.

At minimum, result categories distinguish malformed input, unsupported operation, incompatible API version, route not covered, peer unavailable, transport unavailable, flow quota exhausted, datagram too large, queue full, stale handle or generation, flow closed, and queue empty.
The concrete Horizon result values are assigned with the IPC implementation and are tested as part of the service contract.
Expected route, flow, queue, and transport outcomes are returned as typed protocol statuses or per-entry dispositions.
CMIF command failure is reserved for malformed ABI use, invalid IPC buffers, or a service-level failure that prevented a valid protocol response.
Production diagnostics aggregate counters and state transitions, while per-datagram logging remains disabled outside an explicit debug gate.
The MITM reports a bounded final summary for each closed flow and worker lifetime, and WireGuard reports its corresponding flow totals at closure, so requester and harness measurements can be reconciled without synchronous filesystem activity on the packet path.

## Version 1 Implementation Notes

The `wgnx:tun` root service creates child clients through a dedicated 4 KiB static SF allocator, which is initialized with the sysmodule and bounded independently of the optional global SF allocator.
This makes child-client exhaustion a normal `ResultOutOfMemory` service outcome instead of a dependency on implicit process-wide allocator initialization.

The initial implementation owns its fixed client contexts, flow slots, packet slabs, completion queues, route records, and reverse-tuple tombstones in `runtime::TunnelFlowPlane`.
It creates IPv4 and UDP headers only from validated flow metadata and synchronously releases an outbound slab after the existing bounded WireGuard packet path has accepted or rejected the resulting packet.
The current active peer configuration is normalized into IPv4 `AllowedIPs` routes sorted by longest prefix and routes are re-evaluated on peer activation or policy transition.

Virtual source tuples are quarantined for 60 seconds after a flow closes.
The allocator reserves one free tombstone per live flow before admitting a new flow, so every close can retain its released tuple instead of silently weakening stale-reply isolation under pressure.

The implementation consumes matched decrypted IPv4/UDP packets before the legacy raw packet queue receives them.
Unmatched valid packets continue to the raw diagnostic API.
Malformed, stale, and resource-exhausted direct-flow packets are consumed and recorded as direct-flow dispositions so they cannot be misinterpreted as raw diagnostic traffic.

The initial requester workload uses `wgnx:tun` and never supplies an inner source address or port.
Its `NXRVWG1` payload records workload ID, logical flow index, sequence, seed, and deterministic payload bytes.
The remote requester harness recognizes this record, logs the configured endpoint and source tuple, and produces per-workload and per-flow packet and byte totals at shutdown.
The raw `wgnx:ctl` packet scenario remains separately configurable for protocol diagnostics.

## Required Validation

Host and target coverage for the first implementation must demonstrate malformed endpoint and payload rejection, flow and queue exhaustion, longest-prefix route selection, context-reference cleanup, explicit close idempotence, stale peer-activation rejection, stale outer-binding completion rejection without flow invalidation, inbound reverse-key isolation, reverse-tuple quarantine, batch partial acceptance, ordinary event signal and drain behavior, writable transitions, policy transitions, terminal flow wake-up behavior, and shutdown wake-up without a fabricated completion record.
The requester migrates one UDP echo scenario to this contract while preserving the existing raw inner-IPv4 diagnostic regression.

On-device validation must include repeated requester launch, peer activation and teardown, rebind without logical-flow loss, Wi-Fi interruption and recovery, queue pressure, concurrent cloned client sessions, and operation with the BSD MITM inactive.
The separate `bsd:s` MITM implementation begins only after this direct client path has stable lifecycle and resource evidence.

## Future Extensions

A future unconnected UDP mode may reuse `FlowHandle`, client-context readiness, generations, route snapshots, bounded queues, and terminal lifecycle semantics.
It must add explicit bounded remote-association ownership and a policy for both tunnel-covered and non-covered destinations.

A future TCP path may reuse routing classification, client-context ownership, quotas, completion delivery, global packet storage, and peer-activation invalidation.
It must define stream connection, ordered receive, send backpressure, shutdown, error, and BSD readiness behavior separately from UDP.
It must not treat TCP as a raw packet submission extension.
TCP state and the userspace IP stack belong in the WireGuard sysmodule behind a separate IP-adapter boundary from the WireGuard protocol core.
The MITM translates BSD stream operations and lifecycle outcomes through a versioned private stream-flow contract without owning retransmission, congestion control, packet construction, or tunnel-facing buffering.
TCP implementation starts only after the UDP-backed IP adapter passes its fragmentation, reassembly, resource, lifecycle, and device-validation gates.

Shared-memory payload transfer remains an optional later optimization.
It must preserve the same flow ownership, generation tagging, bounded resource model, backpressure, and teardown guarantees as this IPC contract.
Control-plane operations, lifecycle queries, and readiness notifications remain ordinary IPC and kernel handles.
Before ring implementation, a target-side lifecycle test must prove shared-memory handle transfer, mapping, access, unmapping, and teardown between the two sysmodules.
The first experiment must use fixed rings and payload pools with one explicit producer and one explicit consumer per direction.
If concurrent MITM workers would make a ring multi-producer, they must serialize through an owned producer before the experiment rather than relying on an unspecified concurrent ring.
