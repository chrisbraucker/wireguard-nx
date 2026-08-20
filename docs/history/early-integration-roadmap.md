# WireGuard System Integration Roadmap

This is a retained early integration record and does not define the current architecture.
The current separate BSD MITM and WireGuard-owned IP-adapter design is documented in [`../architecture/bsd-mitm-traffic.md`](../architecture/bsd-mitm-traffic.md) and [`../work/horizon-integration-plan.md`](../work/horizon-integration-plan.md).

## Objective

Make ordinary Horizon applications use the existing `wireguard-nx` tunnel
without application changes. The first practical integration path is a bounded
`bsd:*` MITM adapter that redirects selected application sockets into the
WireGuard sysmodule.

The target data path is:

```text
Horizon application socket
  -> bsd:* MITM destination rewrite
  -> local native socket bridge
  -> UDP/TCP adapter
  -> inner IPv4 packet
  -> existing wireguard-nx transport
  -> WireGuard peer
```

Replies follow the reverse path. The long-term implementation must preserve
the socket behavior applications observe, including source endpoints, errors,
blocking behavior, and lifecycle semantics.

## Confirmed Foundation

- The `wireguard-nx` sysmodule establishes real WireGuard tunnels.
- Synthetic ICMP and HTTP traffic generated in the sysmodule traverses real
  peers successfully.
- The WireGuard core already accepts plaintext inner packets through the path
  used by `SendProtocolPeerPayload`.
- Decrypted inner packets already reach `CommitReceivedPacket`; they are not
  yet delivered to applications.
- The `bsd:s` MITM survives repeated requester launches with the current
  lifecycle and `RegisterClient` handling.
- The MITM can safely replace a `SendTo` sockaddr input descriptor without
  changing requester memory.
- Exact UDP destination port rewrites and IPv4-plus-port rewrites have been
  validated on device across repeated requester launches.
- A requester can receive a successful UDP echo after its destination is
  rewritten by the MITM.
- Binary MITM tracing confirmed that `RecvFrom` returned the effective echo
  source `192.168.0.2:29001` after a request originally addressed to
  `192.168.0.24:29000` was rewritten. Horizon does not restore the original
  destination as the response source automatically.

These results establish a usable application ingress point. They do not yet
establish a general VPN data plane.

## Design Constraints

1. Keep the WireGuard outer UDP socket outside interception to prevent loops.
2. Keep MITM request threads bounded and non-blocking. Handshake, encryption,
   peer I/O, and flow expiry belong on dedicated workers.
3. Never mutate application memory directly. Continue replacing IPC buffer
   descriptors with owned shadow buffers.
4. Add each behavior behind narrow configuration gates until it passes the
   repeated-launch and long-lived-probe matrix.
5. Preserve the known-stable spoof and observation modes as recovery and
   comparison paths.
6. Fail closed for malformed internal state, but fail open to the original BSD
   service when a request is outside the explicitly supported interception
   shape.
7. Bound all queues, flow tables, packet sizes, and timeouts. A stalled peer
   must not stall Horizon socket service handling.
8. Support `bsd:s` and `bsd:u` eventually. Applications choose the service, so
   either service alone is insufficient for system-wide coverage.

## Milestone 1: Expand The WireGuard Packet IPC API

Make arbitrary plaintext inner IPv4 packets a supported, testable sysmodule
boundary before involving the BSD MITM or a local socket bridge.

Implementation status (2026-07-13): the initial API v2 implementation is in
place on the clean `wireguard-nx.git` branch. It includes debug-gated CMIF
commands 21/22, shared client wrappers, strict IPv4 validation, bounded
eight-packet transmit and receive queues, activation-generation invalidation,
single-client PID ownership, and a build-time Program ID allowlist. Host tests
and both debug and non-debug Horizon builds pass. Device acceptance remains
pending and will be exercised by Milestone 2; until then this milestone is not
considered operationally complete.

Refactor the existing WireGuard send and receive paths into explicit internal
interfaces:

```text
SubmitInnerIpv4Packet(packet, metadata)
RegisterInnerIpv4Receiver(callback or bounded queue)
```

Expose that boundary initially through debug-gated `wgnx:ctl` commands with a
contract along these lines:

```text
SubmitInnerIpv4Packet(input packet) -> submission ID/status
ReceiveInnerIpv4Packet(output packet) -> packet metadata/status
```

The exact CMIF buffer types and result structures should be fixed as part of
the implementation. The receive operation should initially be nonblocking;
clients can poll under their own bounded timeout without occupying a sysmodule
IPC worker indefinitely.

Requirements:

- Add project-owned request, response, and status structures to the shared IPC
  protocol and increment the API version.
- Add matching client wrappers so test applications do not issue raw service
  dispatches themselves.
- Accept only complete, structurally valid inner IPv4 packets within the
  configured MTU and transport payload limits.
- Reuse the established peer, keypair, handshake, encryption, and outer UDP
  paths rather than creating a second WireGuard implementation.
- Make ownership and lifetime of packet buffers explicit.
- Queue work when the peer is temporarily unable to send, with strict limits
  and observable drop reasons.
- Deliver decrypted IPv4 packets to a consumer instead of only logging or
  discarding them.
- Keep existing synthetic ICMP and HTTP tests working through the refactored
  interface.
- Keep submission and receive queues strictly bounded and return explicit
  empty, full, unavailable, malformed, and stale-activation outcomes.
- Restrict the experimental packet commands to intended clients while they are
  debug-gated; arbitrary local processes must not gain an unbounded packet
  injection interface.

Acceptance gate:

- Existing WireGuard synthetic tests still pass.
- IPC version negotiation and command availability behave correctly in debug
  and non-debug builds.
- Valid test packets reach the existing WireGuard encryption/send path and
  decrypted non-debug packets reach the bounded receive queue.
- Queue overflow, no-peer, no-keypair, malformed-packet, and shutdown paths
  return stable results, are logged, and do not block the caller.

## Milestone 2: Requester Direct Packet-API Test

Implementation status (2026-07-13): the requester now has an independently
feature-gated `wgnx_packet_udp_echo` scenario using the shared API v2 client
wrappers. It builds a checksummed IPv4/UDP packet with a random token, performs
bounded nonblocking receive polling, validates the complete reply tuple and
checksums, logs unrelated packets, and supports an explicit malformed IPv4
checksum rejection test. The default next-test profile disables BSD and all
socket scenarios. On-device acceptance is pending.

Add a feature-gated requester scenario that proves general connectivity
through the new sysmodule IPC API without using BSD sockets or the MITM path.

Initial UDP test shape:

- Open `wgnx:ctl` and verify the expected IPC API version.
- Read the configured tunnel source, remote echo destination, and test ports
  from requester configuration.
- Construct a complete inner IPv4 and UDP packet with correct lengths and
  checksums.
- Submit it through `SubmitInnerIpv4Packet`.
- Poll `ReceiveInnerIpv4Packet` under a requester-owned bounded timeout.
- Match the reply by protocol, source and destination addresses, ports, and
  an unpredictable payload token.
- Validate IPv4 and UDP lengths/checksums before reporting success.

This scenario should be independently selectable from all existing requester
socket scenarios. In particular, it must be possible to run it without
initializing BSD so that a failure cannot be confused with socket lifecycle or
MITM behavior.

Acceptance gate:

- The requester sends a UDP echo packet through the WireGuard sysmodule and
  receives and validates the decrypted reply through IPC.
- The peer and destination-host capture confirm that the packet traversed the
  WireGuard tunnel.
- Three requester launches against one continuously active WireGuard
  sysmodule complete successfully.
- Wrong destination, unavailable peer, malformed packet, empty receive queue,
  and timeout cases produce bounded, distinguishable requester results.
- Requester exit does not leave client-specific packets or state that can be
  consumed by a later invocation.

This proves the reusable packet boundary and WireGuard routing independently.
The later bridge should call the same internal submit/receive implementation,
not create a parallel path.

## Parallel Track: Inner IP Protocol Coverage

The first two milestones use IPv4/UDP because the existing echo harness gives
an unambiguous bidirectional result. Broader inner-packet coverage is necessary
but does not block creation of the packet API or its initial requester client.

Once the UDP baseline is stable, use the same IPC path to test independently:

- IPv4 ICMP echo, including matching identifiers and sequence numbers
- additional IPv4 protocols required by observed application traffic
- IPv4 options, fragmentation, and reassembly policy
- packets at, below, and above the effective WireGuard tunnel MTU
- malformed version, header length, total length, checksum, and protocol fields
- IPv6, after the IPv4 integration path is operationally stable

Each protocol test should state whether validation belongs at the IPC ingress,
the WireGuard packet boundary, the peer/router, or the eventual userspace IP
stack. The raw packet API should avoid silently changing packet semantics merely
to make a test pass.

## Milestone 3: Fixed-Flow UDP Bridge

Build the smallest end-to-end application integration proof before adding a
general flow table.

Initial shape:

- The probe rewrites the requester's exact UDP echo destination to a dedicated
  loopback endpoint, such as `127.0.0.1:29001`.
- The WireGuard sysmodule owns a local UDP listener at that endpoint.
- The bridge records the requester's local source address and ephemeral port.
- The original remote destination is fixed in build configuration for this
  one test flow.
- The bridge synthesizes a complete inner IPv4 and UDP packet using:
  - source IP: configured WireGuard tunnel address
  - source port: requester's ephemeral UDP port
  - destination IP and port: configured original echo endpoint
  - payload: datagram received by the loopback listener
- The resulting inner packet is submitted through the Milestone 1 internal
  interface already exercised by the requester IPC test.
- A decrypted reply is parsed and its UDP payload is sent from the bridge to
  the recorded requester endpoint.

Acceptance gate:

- The unmodified requester reports UDP echo success.
- The remote host observes the packet arriving through the WireGuard peer,
  not directly from the Switch network interface.
- Three requester runs without the probe and three runs under one continuous
  probe instance complete successfully.
- Probe/sysmodule shutdown and restart do not leave stale listeners or flows.
- A missing peer or unreachable destination causes a bounded requester timeout
  and does not hang the OS.

This milestone proves application -> MITM -> bridge -> WireGuard -> peer and
the complete return path. Hard-coding one original destination is intentional;
it avoids introducing a control protocol before the packet path itself works.

## Milestone 4: UDP Source Transparency

Add a response-side sockaddr substitution mechanism to the Atmosphere-libs
MITM layer, analogous to the validated request input-buffer replacement hook.
This is now a confirmed requirement rather than a conditional step: binary
trace records show that `RecvFrom` exposed the rewritten endpoint
`192.168.0.2:29001` instead of the original endpoint
`192.168.0.24:29000`.

The fixed-flow bridge may initially return its local listener as the source to
prove packet delivery, but it is not application-transparent until this
milestone restores the original remote endpoint.

Requirements:

- Replace owned response buffers safely; do not write into application memory
  outside the IPC framework.
- Rewrite only matching `RecvFrom` results for an active intercepted flow.
- Source the replacement address from flow state that records the original
  destination; do not infer it from the rewritten bridge endpoint.
- Preserve payload length, truncation behavior, return values, and BSD errno.
- Leave the response sockaddr untouched for errors, unmatched flows, and
  responses that do not have the expected descriptor and sockaddr shape.
- Document any generally useful Atmosphere-libs change as a candidate upstream
  patch, separately from project-specific policy.

Acceptance gate:

- Requester receives the echoed payload and reports the original remote IP and
  port as the source.
- Control runs outside interception retain their native source endpoint.
- Repeated launch and long-lived probe tests remain stable.

## Milestone 5: General UDP Flow Tracking

Replace fixed build-time endpoint knowledge with a bounded flow table and a
control path between the MITM adapter and WireGuard bridge.

Track enough identity to avoid collisions across processes and socket reuse:

```text
service kind + process/program identity + BSD session + socket descriptor
+ local endpoint + original remote endpoint + generation
```

Cover:

- `SendTo` / `RecvFrom`
- UDP `Connect` followed by `Send` / `Recv`
- socket close
- process and BSD-session teardown
- inactivity expiry
- descriptor and ephemeral-port reuse
- concurrent flows to multiple destinations
- both `bsd:s` and `bsd:u`

The control path must communicate original destinations to the bridge without
putting metadata into application payloads. It must authenticate or otherwise
constrain senders so unrelated local software cannot inject tunnel traffic.

Acceptance gate:

- Multiple concurrent UDP destinations work through one continuous probe and
  WireGuard session.
- Repeated process launches do not reuse stale flow state.
- Flow limits and expiry are visible in logs and remain stable under stress.
- DNS, UDP echo, and at least one real application UDP workload pass.

## Milestone 6: Policy, Bypass, and Operations

Turn the experimental interception rules into explicit runtime policy:

- included and excluded Program IDs
- included destination networks and ports
- `bsd:s` / `bsd:u` service selection
- WireGuard outer transport bypass
- local bridge and management socket bypass
- fail-open versus fail-closed behavior
- tunnel unavailable behavior
- per-flow counters and bounded diagnostic tracing

Move proven build-time toggles toward manager-controlled runtime settings only
after the data path is stable. Keep a safe mode that disables interception
without destroying the WireGuard control plane.

Acceptance gate:

- Autoboot and long-lived operation survive repeated application churn.
- Starting, stopping, and reconfiguring the tunnel has defined behavior for
  existing flows.
- The outer WireGuard transport cannot recursively enter the MITM path.
- Resource use remains bounded during peer outage and network transitions.

## Milestone 7: TCP Integration

Do not emulate Horizon's BSD TCP semantics directly in the MITM handler. Use a
proven userspace TCP/IP stack, expected to be lwIP unless evaluation identifies
a better fit.

Proposed path:

- Rewrite selected application `Connect` destinations to a local TCP listener.
- Let Horizon's native loopback TCP socket preserve application-facing stream,
  blocking, poll, shutdown, and error behavior.
- Map the accepted local connection to the original remote destination.
- Let the userspace TCP/IP stack create and consume inner IP packets through
  the Milestone 1 WireGuard interface.
- Relay stream bytes between the local native socket and userspace TCP flow.

Acceptance gate:

- Requester TCP echo succeeds through WireGuard across repeated launches.
- HTTP succeeds without application modification.
- Half-close, reset, timeout, DNS result reuse, and peer loss have bounded and
  documented behavior.
- Multiple simultaneous TCP connections do not block MITM service threads.

## Milestone 8: Coverage Expansion

After UDP and TCP are stable:

- Validate applications using `ssl:*`; their underlying TCP sockets should be
  captured below TLS without MITMing TLS content.
- Add IPv6 only after the IPv4 path is operationally stable.
- Test NIFM transitions, sleep/resume, Wi-Fi reconnect, Ethernet changes, and
  WireGuard peer roaming.
- Measure MTU and fragmentation behavior; establish a tunnel MTU policy and
  TCP MSS handling if required.
- Audit system services individually before broadening the allowlist.

Success means ordinary selected applications use WireGuard without code
changes while excluded services and the WireGuard transport retain native
connectivity.

## Immediate Iteration Sequence

1. Expand `wgnx:ctl` with debug-gated, bounded plaintext IPv4 submit and
   receive commands backed by reusable internal interfaces.
2. Add a feature-gated requester scenario that constructs, submits, receives,
   and validates an IPv4/UDP echo exchange through that API.
3. Run the direct packet-API matrix without the probe and verify both sides of
   the exchange at the WireGuard peer.
4. Add a fixed-destination loopback UDP bridge in the WireGuard sysmodule using
   the same internal packet interfaces.
5. Configure the current requester-only MITM rewrite to target that bridge.
6. Run the fixed-flow MITM end-to-end matrix and verify traffic at the
   WireGuard peer.
7. Implement matching `RecvFrom` sockaddr restoration and verify that the
   requester observes the original remote endpoint, not the bridge endpoint.
8. Generalize the fixed-flow state only after both payload delivery and source
   transparency pass repeated-launch testing.

Each iteration should change one boundary at a time and retain a configuration
that reproduces the last known-good behavior.

## Standard Device Test Matrix

For every lifecycle-sensitive milestone:

1. Three requester runs with probe disabled.
2. Start probe once; run requester three times with short idle periods.
3. Leave probe active through a longer idle period; run requester again.
4. Exercise expected success, remote timeout, and tunnel-unavailable paths.
5. Stop and restart probe; repeat one requester run.
6. Check probe, requester, fatal, and ERPT logs for silent errors even when the
   GUI reports success.

For Milestones 1 and 2, omit probe-specific steps and instead run repeated
requester clients against one continuously active WireGuard sysmodule, followed
by sysmodule restart, peer-unavailable, queue-empty, and queue-pressure cases.

For bridge milestones, also capture the WireGuard peer and destination host so
the observed route, source address, destination address, and port can be
verified independently of requester output.

## Deferred Alternatives

- Native Horizon interface or route injection remains architecturally cleaner,
  but no viable integration point has yet been demonstrated.
- Full BSD response emulation inside the MITM is deferred because reproducing
  blocking, polling, cancellation, errno, and lifecycle behavior has a much
  larger risk surface than redirecting to native local sockets.
- TCP implementation is deferred until the UDP bridge validates the shared
  packet boundary and return delivery.

These alternatives should be revisited only when new evidence changes their
cost or feasibility relative to the working BSD redirect path.
