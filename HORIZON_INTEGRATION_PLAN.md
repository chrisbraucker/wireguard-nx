# Horizon Integration Plan

## Purpose

This document turns Milestone 9 into an incremental implementation plan for transparent Horizon traffic.
The existing WireGuard sysmodule is a validated tunnel data plane, but ordinary Horizon applications do not yet route traffic through it.
The immediate objective is a bounded UDP path that can serve both direct homebrew clients and a separate BSD MITM sysmodule.

This plan intentionally does not define a stable public API or a security model.
The project is in active research and development, and Atmosphere homebrew normally does not use service ACLs to restrict private inter-sysmodule APIs.
Correctness, bounded resource use, and diagnosable lifecycle behavior are the requirements at this stage.

## Architectural Direction

Keep WireGuard protocol and tunnel ownership in the WireGuard sysmodule.
The WireGuard sysmodule owns peer configuration, tunnel identity, packet encryption and decryption, peer lifecycle, the userspace IP stack, and the bounded flow mappings required to carry traffic through the tunnel.
It must not own Horizon BSD service emulation, application process lifetime, or MITM handle bookkeeping.

Run Horizon-facing interception in a separate MITM sysmodule.
The MITM sysmodule owns the Atmosphere service contract, client PID and domain bookkeeping, virtual BSD socket lifecycle, and translation between BSD operations and the private WireGuard flow IPC.
For each intercepted socket, it selects either the retained Horizon BSD path or the WireGuard flow path once and never silently migrates or falls back after that selection.
It forwards BSD-level payloads and operations to the selected owner rather than constructing, fragmenting, parsing, or reassembling IP packets itself.
This preserves the reviewed WireGuard runtime as a separate failure domain while the BSD MITM remains under active discovery.

The current raw inner-IPv4 packet API remains a diagnostic and protocol-validation boundary.
It continues to require a valid tunnel-source packet and must not become the general client API.
The normal client path supplies flow metadata and payload, allowing the WireGuard sysmodule to choose the tunnel source address and virtual source port itself.

The reusable data-plane boundary is a WireGuard-owned userspace IP adapter over the shared inner-packet plane.
BSD flow adapters supply validated socket metadata and payloads to that adapter, while the existing diagnostic API may continue to supply complete inner packets directly to the shared packet plane.
The IP adapter owns transport endpoint state, address and port translation, checksums, effective-MTU handling, IPv4 fragmentation and reassembly, IP protocol demultiplexing, and conversion between BSD-level data and complete inner packets.
The first UDP flow adapter, a future TCP implementation, and any later IP protocol must share this adapter rather than duplicate those responsibilities in the MITM.
This distinction is critical because a BSD MITM observes socket operations and payloads, not arbitrary IP packets emitted by the Horizon kernel.

Address and port translation therefore belongs in the WireGuard flow layer, immediately before inner IPv4 packet construction and immediately after decrypted packet parsing.
It does not belong in the cryptographic protocol core or in arbitrary callers that happen to submit packets.
The userspace IP adapter remains separate from `PeerRuntime`, handshake state, key lifecycle, replay protection, and encrypted transport so the WireGuard protocol core continues to carry opaque authenticated inner IP packets.
All userspace IP stack calls, callbacks, pbuf operations, and timeout processing must execute through one serialized post-lock owner and must not run while the daemon state mutex is held.

The selected path is symmetric at the interception boundary:

```text
intercepted BSD operation
        |
        +-- route not selected --> retained Horizon BSD descriptor
        |
        +-- route selected -----> private WireGuard flow IPC
                                      |
                                      v
                              userspace IP adapter
                                      |
                                      v
                              WireGuard packet plane
```

Outbound delegated flow data passes through route and leak-protection policy, the userspace IP adapter, and then the shared packet plane.
Inbound decrypted packets pass through peer AllowedIPs source authorization before the userspace IP adapter validates, reassembles, and demultiplexes them to a live flow.
No diagnostic, flow, or raw-packet consumer may observe authenticated plaintext before the peer source-policy check succeeds.

Native Horizon interface or routing integration is currently deprioritized.
Current evidence suggests Horizon treats networking as one active interface rather than a routeable set of coexisting interfaces.
Installing a virtual primary interface without an official fallback route could disrupt the entire network stack.
This remains a parallel reversing question, not a dependency for the MITM path.

## Resource And Mapping Model

Flow state is ephemeral and remains entirely in memory.
No flow mapping survives peer deactivation, sysmodule restart, or a peer-activation transition.
All flow and packet resources have fixed global limits and explicit drop behavior.

The initial UDP flow table must record at least:

- client identity and client-owned logical flow handle
- IP protocol
- requested remote address and port
- selected tunnel source address and virtual source port
- peer-activation, policy, and flow-allocation generation
- creation and last-activity time
- bounded inbound occupancy and disposition counters
- optional opaque caller diagnostic tag

Inbound packets are matched through a reverse key containing protocol, the tunnel destination address and port, and the remote source address and port.
The exact matching policy must be documented with the implementation because connected and unconnected UDP socket behavior differs.
Packets that do not match a live flow, exceed a resource limit, belong to a stale generation, or cannot be parsed safely are dropped and counted.
An outer UDP binding generation guards only transport effects and stale outer-socket completions.
It must not invalidate a logical inner flow or participate in reverse-flow matching because it is not encoded in decrypted inner traffic.

Payload memory comes from fixed-capacity global slabs shared across flows, with separate accounting for each direction.
The client completion queue contains inbound slab references and metadata, while each flow retains only quota occupancy rather than maximum-size packet arrays.
Released virtual source tuples are quarantined before reuse so delayed inner traffic cannot be delivered to a new flow that happens to receive the same tuple.

The initial transparent path supports IPv4 and UDP only.
TCP requires stream-specific BSD translation in the MITM and a bounded TCP implementation in the WireGuard-owned userspace IP adapter because rewriting individual TCP packets does not implement connection state, retransmission, congestion control, or stream semantics.
It must not be implied by the UDP work.


## Implementation Plan

### 1. Split Sysmodule Responsibilities And Repository Layout

Urgency: required before transparent interception code is introduced.

Move the current `sysmodule/` directory to `wg-sysmodule/` without changing its current tunnel behavior.
Create `mitm-sysmodule/` as a separate Atmosphere sysmodule project with its own build, deployment, logging, and test entry points.
Update manager, overlay, requester, documentation, tooling, and workspace orchestration paths to use the renamed WireGuard sysmodule location.

The split must not introduce a shared mutable implementation library between the two sysmodules.
The IPC contract is the initial boundary and is deliberately exercised as such.
Code may later be shared only where it is platform-neutral and has a clearly owned API.

Definition of done:

- the renamed WireGuard sysmodule builds and passes its current host, sanitizer, target, stack, and resource gates unchanged
- manager and overlay still communicate with the WireGuard control service
- the new MITM sysmodule can be built, deployed, started, stopped, and logged independently without intercepting traffic yet
- repository and tooling documentation no longer refer to the old `sysmodule/` path
- the MITM policy explicitly excludes its own program and the WireGuard sysmodule from `bsd:s` interception so the outer WireGuard UDP socket cannot recurse through the tunnel
- Each system process currently identified as interfering with network connectivity needs to continue to maintain individual feature flags to toggle whether they are intercepted by MITM or not
  The module shall support on demand toggling at runtime and autobooted loading during OS boot, and as such needs to make sure that system stability is not affected negatively


### 2. Specify The Private Flow IPC Contract

Urgency: critical prerequisite for all implementation work.

Define a versioned private `wgnx:tun` IPC contract alongside the existing development packet API.
The contract is permissive during development and does not authenticate, whitelist, or pin callers.
It still validates all inputs and rejects malformed requests because caller trust is not a substitute for memory safety or bounded resource use.

The first iteration supports only UDP flows and should provide a root service that creates logical tunnel-client object contexts.
One logical client context owns all of its flows, a bounded completion queue, and one manual-clear readiness event.
Cloned IPC sessions share the same context so the MITM can issue concurrent commands without allocating one event or ownership domain per physical CMIF session.

The contract should provide operations equivalent to:

- create a logical tunnel-client context
- query capabilities, effective inner MTU, and fixed limits
- create a connected logical UDP flow with one destination endpoint
- submit one UDP payload on a live flow as a convenience operation
- submit a bounded descriptor and payload batch with a disposition for every entry
- dequeue a bounded completion batch containing inbound datagrams, flow transitions, routing-policy changes, and writable transitions
- obtain the client-context readiness event
- query flow state and tunnel-layer diagnostic endpoint data without treating it as a BSD-visible local endpoint
- close a flow and release its bounded resources
- query transport and peer-activation state needed to distinguish unavailable transport from a closed flow

The contract must define fixed maximum datagram size from effective inner MTU, maximum clients and flows, global packet-slab capacities, maximum queued references per flow, completion and batch capacities, kernel-handle cost, error/result categories, ownership of IPC buffers, and behavior across peer activation, rebind, suspension, and teardown.
It must use opaque client flow handles rather than exposing tunnel-table storage or requiring callers to invent the tunnel source address.
It must distinguish peer activation, flow allocation, routing policy, and outer binding generations so stale work cannot be mistaken for live traffic without destroying flows during a socket rebind.
Expected route, queue, and lifecycle outcomes use typed protocol statuses, while CMIF failures are reserved for malformed IPC or service-level inability to return a valid response.
The completion design must reserve or coalesce terminal, policy, and writable-state notifications so inbound datagram pressure cannot discard lifecycle truth.

Definition of done:

- the contract and its lifecycle/error rules are documented before implementation
- API version is incremented when an incompatible shape is introduced
- host tests cover malformed requests, resource exhaustion, close races, cloned-session ownership, batch partial acceptance, completion saturation, event drain races, and each stale-generation category
- the existing raw packet API remains available for protocol diagnostics


### 3. Implement Direct UDP Flows And Migrate The Requester

Urgency: critical proof of the private contract before BSD interception.

Implementation status: the first bounded direct-flow plane, `wgnx:tun` service, direct requester echo workload, and controlled remote-harness accounting are implemented.
Host coverage currently validates route selection, malformed endpoint rejection, peer-activation invalidation, data-completion saturation with terminal notification reservation, and reverse-tuple exhaustion and expiry.
The remaining Step 3 evidence is on-device lifecycle and workload validation across the stated matrix.

Implement the private UDP flow IPC in `wg-sysmodule/` using a fixed-capacity, peer-activation-tagged flow table.
Construct inner IPv4 and UDP packets from validated flow metadata and payload rather than mutating application-provided packets.
Compute and validate the required IPv4 and UDP checksums at this boundary.
Implement a normalized `AllowedIPs` route table with deterministic longest-prefix selection before exposing `GetRoutingPolicySnapshot` or accepting flows.
The current single active peer may be the only selectable result in v1, but route coverage must not rely on a nonempty configuration string.

Back payloads with fixed global slabs, keep inbound slab references in the client completion queue, and retain only quota occupancy in each flow.
Derive the maximum UDP payload from effective inner MTU and return `DatagramTooLarge` rather than fragmenting in v1.
Quarantine released virtual source tuples for a fixed documented interval and expose exhaustion as a typed disposition.

Deliver decrypted matching UDP payloads back through the flow handle while preserving the source endpoint metadata the client needs.
The requester must migrate one scenario to this API and stop supplying the WireGuard interface address as a hand-crafted inner-packet source for that scenario.
The raw inner-IPv4 requester path remains as a separate diagnostic regression.
Use one client-context completion event and bounded completion batches rather than one event and one receive IPC call per flow or datagram.
Keep single-datagram operations as convenience wrappers over the same batch admission and completion paths.

Extend the requester with a controlled UDP workload scenario before introducing BSD interception.
The scenario targets a defined remote harness endpoint and generates reproducible, self-identifying payloads so that the local requester and remote harness can independently account for accepted, received, echoed, timed-out, malformed, reordered, duplicated, and unexpected datagrams.
Its configuration must cover destination IPv4 address and port, payload size or a defined size sweep, datagram count, pacing or burst shape, concurrent logical sockets, receive deadline, and deterministic payload seed.
It must support both one-way receive accounting and request-response echo accounting so that throughput, reverse delivery, and queue pressure can be measured separately.
The default workload must remain conservative enough for routine device regressions, while the bounds must make sustained and burst traffic experiments possible without editing source code.
The remote harness must log its configured endpoint, workload identity, per-flow counters, byte totals, and observed source tuples so a result can be correlated with sysmodule and MITM diagnostics.

Definition of done:

- direct requester UDP echo completes through a real peer without caller-supplied tunnel source addressing
- all client contexts, handles, flow allocations, slabs, queues, batches, and packet sizes are bounded and observable
- repeated requester launches, peer teardown, reactivation, rebind, and stale-reply cases are covered by host and device tests
- a received packet cannot be delivered to a flow from a different peer activation, and an outer socket rebind does not destroy an otherwise live flow
- delayed packets cannot cross a released and reused reverse tuple during its quarantine window
- completion delivery covers inbound data, policy changes, terminal state, and send-writability transitions without empty-queue polling
- controlled requester and remote-harness workload accounting agrees for at least a baseline echo run, a sustained paced run, and a bounded burst run

Additional considerations: The requester should become the deliberate multi-client and flow-plane exerciser before we enable active MITM routing. I would add feature-gated scenarios for:

- Open two or more cloned wgnx:tun clients and verify shared-context behavior.
- Close clones in different orders, then confirm final-close cleanup and successful client-slot reuse.
- Open several connected UDP flows per client and across clients.
- Run paced and bounded-burst workloads with configurable payload, count, pacing, flow count, and deadline.
- Trigger peer teardown/reactivation and manual bind bump while flows remain open.
- Intentionally leave completions unread to validate bounded queue pressure and recovery.

The harness already has most workload observability needed.
The requester needs configuration-driven client/flow topology and lifecycle controls, plus counters that distinguish expected pressure or unavailable outcomes from unexpected failures.

The requester now contains an opt-in contract-validation scenario for the remaining client-context and batch-disposition evidence.

Its clone-lifetime pass keeps a clone alive after closing its original CMIF session, proves the clone can complete an echo, exhausts remaining logical-client slots while that clone is the final reference, and proves a slot is reusable only after final close.

Its mixed-batch pass executes the real `SendUdpDatagramBatch` CMIF path with accepted, malformed-range, oversized, and stale-handle entries and verifies the ordered dispositions plus the echo for the accepted entry.

The shared batch-dispatch helper has deterministic host coverage for accepted, malformed, oversized, stale-handle, and queue-full dispositions, including the rule that malformed entries never reach runtime admission.

Task 3 device acceptance requires one successful execution of each enabled contract-validation pass through an active real peer and controlled echo harness.


### 4. Implement A Separate Narrow `bsd:s` UDP MITM

Urgency: critical transparent-integration proof and the first measurement subject.

Implementation status: the requester-only proof has completed its initial lifecycle and real-peer validation.
`mitm-sysmodule` registers `bsd:s` and admits every service acquisition from requester forwarder title ID `0x0515C00B3A04A000`.
SM makes the MITM admission decision before a session's first CMIF command is available, so `RegisterClient` and `StartMonitoring` cannot safely select a session in `ShouldMitm`.
Observed `StartMonitoring` side sessions are short-lived and stay on Atmosphere's generic forward path after admission.
The expected `RegisterClient` session remains the descriptor-table owner used by later socket operations and session clones.
`RegisterClient` remains on Atmosphere's generic MITM forward path, which tags the original PID for Mesosphere restoration and closes the MITM-owned duplicate of its transfer-memory copy handle after forwarding.
The generic forward service uses a bounded explicit allocator because Stratosphere system modules intentionally do not provide a newlib heap for `std::shared_ptr` or `new`.
The first routed surface is connected IPv4 UDP using `Socket`, `Connect`, `Send`, `Recv`, `RecvFrom`, `Poll`, `GetPeerName`, `GetSockName`, and `Close`.
The original `bsd:s` descriptor remains the lifecycle and visible-local-endpoint anchor.
The worker owns all raw `wgnx:tun` root and child-client CMIF calls outside the BSD dispatch stack.
The current BSD handlers synchronously wait for a bounded worker operation to complete, but they never issue raw service-manager or WGNX CMIF themselves.
Unavailable, inactive, incompatible, or route-uncovered tunnel state leaves the socket on upstream BSD.
After a flow opens, tunnel failure returns a BSD error and never falls back to upstream BSD.
The current implementation is a bounded per-socket FIFO adapter that batches up to four FIFO-ordered datagrams per WGNX client submission rather than a performance characterization.
The requester workload and adapter include writable readiness and bounded queue-pressure retry coverage, but still require on-device lifecycle and saturation validation before the performance gate can attribute saturation correctly.
The requester-only V1 tunnel surface is explicitly nonblocking and readiness-driven.
After a socket becomes tunneled, `F_GETFL` reports the Horizon BSD:S `O_NONBLOCK` wire value `0x800`, `F_SETFL` accepts only `0x800`, and zero-flag `Send`, `Recv`, and `RecvFrom` are supported.
The value is defined by the BSD:S service ABI and must not be replaced by the sysmodule toolchain's distinct `O_NONBLOCK` macro.
Tunneled `Poll` supports exactly one descriptor requesting `POLLIN`, `POLLOUT`, or both.
`SendTo`, `Bind`, `SetSockOpt`, and `Shutdown` return `EOPNOTSUPP` after a descriptor becomes tunnel-owned.
Blocking-mode behavior, socket-option virtualization, multi-descriptor polling, and other BSD descriptor operations remain deferred.
Because generic MITM forwarding remains necessary for lifecycle commands, no other descriptor operation is a V1 compatibility guarantee and each needs typed rejection or a defined mapping before the admission policy extends beyond requester.

Graceful MITM shutdown is terminal for the process.
After both dispatch loops have stopped and their threads have joined, the module retains its static control and BSD:S `ServerManager` instances plus the BSD service object heap until `ams::Main` returns.
This matches the WireGuard sysmodule's proven Horizon workaround because destroying a post-dispatch `ServerManager` aborts inside Horizon's opaque teardown path.
The BSD server unregisters its own `bsd:s` MITM registration directly after its dispatch loop has stopped and before the retained process exit.
This direct unregister is ownership-scoped to a registration successfully installed by the current process and is followed by a logged `HasMitm` verification.
It is required because retaining the manager suppresses its normal destructor cleanup and SM does not reliably remove the retained MITM registration during process teardown.
The retained state is never reused, and the process must exit immediately after the worker and discovery shutdown sequence completes.

Implement passive service registration and lifecycle tracing in `mitm-sysmodule/` before changing any BSD behavior.
The first device pass for all-requester-session admission must keep WireGuard unavailable or route-uncovered and prove repeated requester initialization, socket activity, and teardown remain transparent through generic lifecycle forwarding.
Only after that pass succeeds may the requester socket-owning session be tested with a route-covered destination and an active tunnel flow.
Start with the narrowest viable `bsd:s` operation subset: UDP socket creation, destination setup, send, receive, close, nonblocking-mode control, readiness polling, and the minimum endpoint and socket-option queries required by the tested client.
`bsd:s` is the intended transparent interception point because it is the system-process service and has the less restrictive service role and client capacity required for a durable system integration.
`bsd:u` observations remain useful for BSD semantic research, but `bsd:u` is not the production target for this plan.
Do not begin with TCP emulation.

The MITM forwards each `Socket` creation to the original `bsd:s` service and retains the returned real descriptor as the Horizon descriptor-namespace, lifecycle, and local-endpoint anchor.
For a connected destination covered by WireGuard policy, it opens one private WGNX flow, forwards the initial UDP `Connect` only to let Horizon select the ordinary device-facing local address and ephemeral port, then services subsequent payload and virtual endpoint operations through `wgnx:tun`.
The MITM captures that local endpoint and returns it from `GetSockName`, while the WireGuard source tuple remains private to the tunnel sysmodule.
If endpoint capture fails, the MITM closes the new flow and returns a terminal socket error rather than risking direct payload fallback.
For an explicitly uncovered destination, it retains the original BSD path.
For a matching route whose tunnel transport is unavailable, the WireGuard-owned leak-protection result determines whether a new socket retains the direct BSD path or fails with `ENETUNREACH`.
Once a socket enters tunneled state, transport or peer failure must surface as a socket error and must never silently switch that socket to the original BSD path.
Once a socket enters direct state, later tunnel availability must not silently migrate that socket to the tunnel.
This state machine is required before mixed pass-through and tunneled traffic can be considered safe.
The explicit per-descriptor states are `Created`, `OpeningTunnel`, `Direct`, `Tunneled`, `Failed`, and `Closed`.
Only `Created` can select a path, `Direct` never migrates to tunnel, `Tunneled` never falls back to direct, and `Failed` cannot dispatch payload work to the retained upstream descriptor.

The MITM maps each tunneled UDP socket to one private WGNX flow handle and forwards operations through `wgnx:tun`.
It preserves Horizon-visible socket semantics where they are understood and fails unsupported operations explicitly rather than forwarding some calls to the original service in an ambiguous state.
PID and domain bookkeeping remain in the MITM for traceability and cleanup, but are not an authorization mechanism for the private WGNX service.
The MITM program and WireGuard sysmodule program are unconditional interception exclusions, including when policy contains `0.0.0.0/0`.
Map every typed WGNX route, queue, flow, and transport disposition to a documented BSD return value and errno outcome.
Synthetic BSD:S errno values use the Linux-numbered CMIF wire ABI rather than the sysmodule toolchain's newlib errno macros.

Use the controlled requester UDP workload to verify this path before starting TCP work.
Run the same workload first without interception as a direct BSD baseline and then with the MITM configured to route its defined remote endpoint through the WireGuard tunnel.
Compare requester, remote-harness, MITM, and WireGuard counters to locate loss, duplication, queue pressure, unexpected bypass, or teardown leakage at the boundary that owns it.
Increase offered load only within explicitly configured fixed resource bounds, and record the first observed saturation point and its reported disposition rather than treating drops as an opaque performance result.

The initial MITM submits UDP flow metadata and whole payloads rather than inner IPv4 packets.
The current WireGuard flow layer constructs one unfragmented inner IPv4 packet, so the payload must fit the effective inner MTU after IPv4 and UDP headers and larger datagrams fail explicitly with `EMSGSIZE`.
An omitted `[Interface] MTU` uses the 1420-byte WireGuard default, which limits UDP payloads to 1392 bytes.
The next fragmentation milestone moves IPv4 fragmentation and reassembly into a separate WireGuard-owned userspace IP adapter, while the MITM remains responsible only for BSD datagram atomicity and error translation.
The first fragmented-datagram contract may advertise a measured maximum below the theoretical 65,507-byte IPv4 UDP limit and must return `EMSGSIZE` above that bound.
Do not enlarge every MITM FIFO slot or WireGuard flow slot to 64 KiB without a measured target memory budget and an explicit bounded transfer design.

The tunnel-facing admission boundary follows a bounded peer-owned ready-to-encrypt FIFO with one serialized encrypted datagram in flight.
Current staging capacity is intentionally conservative and independently budgeted from legacy packet-channel receive capacity.
`QueueFull` retains no rejected IPC payload, and the MITM must retry only after the coalesced `Writable` completion that accompanies any staging-slot retirement, including a nonterminal outer transport drop.
The MITM owns later overload policy, including whether an intercepted BSD operation waits, returns `EAGAIN`, or drops according to an explicit socket-mode policy.
Do not adopt upstream oldest-packet eviction at this boundary because upstream netdevices own ingress policy while this sysmodule is an IPC transport provider.

The requester-only adapter owns eight fixed outbound payload slots globally and permits at most four queued datagrams per tunneled BSD socket.
Each slot stores at most 1472 bytes, the requester-only adapter's declared 1500-byte inner-MTU ceiling, and the adapter rejects larger payloads before queueing them.
One WGNX child client remains owned by each BSD socket, so batch submissions never cross flow or client boundaries and preserve FIFO order for each socket.
The worker submits up to four queued entries through `SendUdpDatagramBatch` when that flow is writable.
On `QueueFull`, it retains the rejected FIFO suffix, suppresses `POLLOUT`, and resumes submission only after the WGNX completion queue reports `Writable`.
The BSD caller sees `EAGAIN` only when the bounded local adapter FIFO cannot admit another payload.
Per-flow accounting keeps these boundaries distinct: `adapter_queued` records local FIFO admission, `adapter_queue_full` records BSD-visible pre-admission rejection, and `queue_full` records a later WGNX staging-pressure disposition.
Consequently, one payload may have a successful BSD send followed by a retained downstream `QueueFull` and internal post-`Writable` resubmission without creating a second requester retry.
For every closed MITM flow, `sends = adapter_queued + adapter_queue_full + too_large` and `adapter_queued = accepted + discarded + queued`.
WireGuard `send_queue_full` is a downstream pressure-event counter and must not be equated with requester-visible retries.

Definition of done:

- a defined ordinary homebrew UDP traffic class completes an echo round trip without app-specific WGNX IPC calls
- MITM client exit, service close, peer teardown, and repeated application launch release all associated flow state
- native descriptor values and close behavior remain coherent across pass-through and tunneled sockets
- nonblocking send and receive, readable and writable polling, timeout, terminal closure, and queue-pressure outcomes match the documented narrow BSD subset
- the WireGuard outer transport and MITM-owned BSD client are proven to bypass interception under the broadest configured tunnel route
- unsupported BSD operations are traceable and fail predictably without destabilizing subsequent clients
- `GetSockName` on a tunneled socket returns the captured ordinary device-facing IPv4 endpoint rather than the WireGuard tunnel tuple
- the initial upstream UDP `Connect` used for endpoint capture produces no direct payload visible at the controlled harness
- the established requester and direct-flow tests remain passing while the MITM is active
- the controlled requester workload is transparently intercepted and rerouted through the tunnel, with accounting agreement across requester, remote harness, MITM, and WireGuard for baseline, paced, and bounded-burst runs
- the first measured throughput ceiling, resource limit reached, and resulting drop or backpressure behavior are recorded before TCP implementation starts

Additional considerations: The MITM must treat wgnx:tun as an optional dependency and remain fail-open until the tunnel exposes an authoritative selected-profile policy.

- MITM autobooted, WG absent: start normally, attempt bounded service discovery, then remain in bypass mode with periodic or event-driven reconnect attempts.
- MITM started while WG absent: identical behavior.
- Both running, peer inactive or unavailable: retain BSD interception and pass traffic through unless the selected profile reports `TunnelBlockedByPolicy` for the new covered socket.
- WG becomes active: obtain a wgnx:tun client, fetch the routing-policy snapshot, and route only matching traffic through the tunnel.
- WG disconnects, restarts, or CMIF calls fail: immediately invalidate local tunnel-client state, stop holding intercepted traffic, and return to bypass mode because the MITM no longer has authoritative policy. Reacquisition must not block BSD request handling.

The initial acquisition path is a traffic-triggered bounded retry controller rather than a periodic poller.
The MITM starts one dedicated tunnel worker and performs one startup probe so absent-service behavior is observable.
Future BSD dispatch only records that traffic was observed when the retry deadline has elapsed and signals the worker, then continues the current request through upstream BSD.
The tunnel worker alone probes `wgnx:tun`, opens and validates its root session, and publishes readiness after confirming the private API version and required capabilities.
It must not reserve one of the bounded child client contexts before active BSD interception needs to create a tunnel flow.
The active interception path asks the same tunnel worker to open and own a child client context only while it has tunneled BSD socket state to service.
Each unavailable or incompatible result returns the controller to bypass with 250 ms, 500 ms, 1 s, 2 s, and then a capped 4 s retry interval.
Any later tunnel CMIF failure invalidates the published client state immediately and returns subsequent BSD requests to the same bypass path until a worker reacquisition succeeds.
The MITM must never perform service lookup, root-session creation, child-session creation, or raw tunnel CMIF on its BSD dispatch stack.
Its BSD handlers may synchronously wait for a bounded operation that the dedicated worker performs, and this wait must be measured before the path is considered viable for broader traffic.

The first active implementation uses a local discovery controller for bounded availability state and one tunnel flow worker for all `wgnx:tun` service-manager, root-session, and child-client ownership.
This avoids concurrent raw libnx service-manager calls through its process-global SM session.
The discovery controller publishes only availability and signals the worker after its retry policy admits an attempt.
The flow worker performs the service-presence query, root acquisition, capability validation, child-client creation, and handle closure.
It creates child clients only when a routed BSD socket needs one.

#### Outstanding Completion Items

- [x] **Measurement logging:** Per-packet MITM and WireGuard diagnostics are gated by explicit target-build switches, leaving state transitions and closure summaries without synchronous SD-card writes on the packet path by default.
- [x] **MITM accounting:** The MITM records bounded per-flow and worker aggregate counters for operation-queue pressure, BSD sends, local-adapter admission and rejection, WGNX dispositions, completion wakes, inbound delivery, MITM inbound-queue drops, writable notifications, and terminal flow outcomes.
- [x] **Writable queue pressure:** Coalesced WGNX `Writable` completions now map to tunneled `POLLOUT`, and the requester retries the same datagram only after that readiness signal rather than treating `EAGAIN` as a terminal workload failure.
- [x] **Quiet controlled harness:** The controlled UDP harness has a quiet aggregate mode and uses a non-threaded UDP server handler, preserving source and workload accounting without a host thread or flushed line per datagram.
- [x] **Narrow BSD semantics:** The nonblocking requester-only operation and error contract is implemented and host-tested, including zero-flag send and receive, `F_GETFL` and `F_SETFL` with the BSD:S `O_NONBLOCK` wire value `0x800`, one-descriptor `POLLIN` and `POLLOUT`, queue pressure, and rejected unsupported operation classes.
  The 2026-08-01 device matrix passed normal paced echo with the requester-recorded device-facing `GetSockName` endpoint, no-reply poll timeout, terminal `POLLHUP` after peer teardown and WGNX shutdown, queue-pressure writable recovery, rejected post-route operation behavior, and a clean later requester launch.
- [x] **Four-mode baseline:** The 2026-08-01 identical 32-datagram, 1200-byte workload passed through native BSD, passive MITM forwarding, direct `wgnx:tun`, and BSD MITM to WireGuard.
- [ ] **Attribution and ceiling:** The local-admission and downstream-pressure accounting contract is reconciled and checked by the Task 4 summary helper, while the first throughput or resource ceiling and its explicit backpressure or drop disposition remain to be measured.
- [x] **Client-context and batching decision:** Preserve one WGNX child client per BSD socket for independent descriptor teardown and completion ownership, while batching up to four FIFO-ordered payloads only within that flow's client context.
- [x] **Lifecycle regression:** The 2026-08-01 run completed a four-flow full BSD MITM workload, orderly requester, MITM, and WireGuard shutdown, restart, and a final clean full BSD MITM echo.

#### Completion Changes Before Device Acceptance

The adapter, route state machine, bounded queues, WGNX batch submissions, and production aggregate metrics already exist.
No MITM or WireGuard production-path change is currently justified solely by an incomplete device matrix.
The requester provides explicit expected-outcome modes so the remaining narrow BSD behaviors can produce a positive test verdict instead of an intentional error that must be inferred from logs.

- [x] **Requester no-reply timeout mode:** The BSD:S-only configuration and Settings control require `echo_replies=false`, send one valid datagram, poll for `POLLIN` until the configured deadline, and report success only when `poll()` returns zero without a receive attempt.
  A reply, `POLLIN`, `POLLHUP`, a poll error, or a send error is a failure in this mode.
- [x] **Requester terminal-flow mode:** The BSD:S-only configuration and Settings control send one echoed setup datagram, then wait in `poll(POLLIN)` for an operator-triggered peer deactivation or WGNX service shutdown.
  It reports success only for `POLLHUP`, then verifies that a later zero-flag `Send` fails with `ECONNABORTED` and that close still succeeds.
  This mode must have a bounded operator window and must not treat a generic timeout as closure.
- [x] **Requester writable-recovery assertion:** The BSD:S-only configuration and Settings control require at least one `EAGAIN` followed by a subsequent `POLLOUT` and a successful retry of the same datagram.
  The workload remains packet-local and retains the existing 16-retry cap.
  A burst that completes without pressure is an inconclusive validation result rather than a successful writable-recovery test.
- [x] **Requester validation coverage:** The modes are mutually compatible only where their expected outcomes cannot conflict, their persisted configuration is validated, and a host-buildable helper independent of libnx covers outcome classification.
  The target scenario remains responsible only for BSD calls and logging the observed result.
- [x] **Requester Settings state:** The expected BSD:S outcome selector now derives its initial and reset selection from the loaded configuration enum.
  Persisted no-reply and terminal-closure selections are therefore displayed correctly instead of appearing as the normal workload.
- [x] **Measurement summary helper:** `nx-reversing.git/tools/summarize_task4.py` extracts requester summaries, harness aggregate summaries, MITM flow summaries, and WireGuard flow summaries into one workload and flow table.
  Its `--check` mode validates the available per-flow local-admission invariants and refuses pre-instrumentation MITM summaries.
  This is not on the packet path and does not replace raw logs.

The following service-close rule is already part of the private WGNX contract and must be verified rather than broadened speculatively.
After an orderly WGNX shutdown wake with no completion record, the MITM performs its normal drain and treats a CMIF failure from that drain or any later tunnel command as terminal service loss.
It must not infer closure solely from `QueueEmpty`, because that is also the normal post-drain state for a live client.
If the device run instead leaves a bounded terminal-flow test pending until its timeout after a confirmed WGNX shutdown, investigate the worker's post-wake command path and fix that concrete discrepancy.

#### Task 4 On-Device Acceptance Sequence

Use a clean deployment of requester, `wg-sysmodule`, `mitm-sysmodule`, and each generated `toolbox.json`.
Build the measurement binaries with requester, WireGuard, and MITM packet-granularity diagnostics disabled so SD-card logging cannot become the workload bottleneck.
Keep state-transition and flow-summary logging enabled.
Use a 1200-byte UDP payload for all echo and burst comparisons while the remote peer advertises an effective inner MTU of 1280 bytes.
Larger replies fragment on that peer and are intentionally unsupported until a later fragmentation design exists.

1. Start the controlled harness in quiet echo mode on a destination reachable both directly and through the peer, such as `192.168.203.24:29000` in the current topology.
   Record the harness source tuple and its per-workload and per-flow summary when it stops.
   Start a second quiet no-echo harness only for the timeout case with `--udp-no-echo`.
2. Establish the selected WireGuard peer with a route that covers the chosen destination and confirm one direct `wgnx:tun` echo before loading the MITM.
   Confirm the remote harness sees `10.13.13.8` for that direct-flow control run.
3. Run one identical 1200-byte, single-flow, paced echo workload in each mode below, using a distinct workload ID for each mode.
   Keep the peer connected in native BSD mode so the physical network condition matches full interception.

   | Mode | Module state | Requester path | Expected harness source |
   | --- | --- | --- | --- |
   | Native BSD | WireGuard connected, MITM absent | BSD:S | Device-facing Wi-Fi IPv4 address |
   | Passive MITM | MITM present, WGNX unavailable or route-uncovered | BSD:S | Device-facing Wi-Fi IPv4 address |
   | Direct WGNX | WireGuard connected, MITM present | `wgnx:tun` | WireGuard interface IPv4 address |
   | BSD MITM to WGNX | WireGuard connected, MITM present | BSD:S | WireGuard interface IPv4 address |

   For every run, retain requester, MITM, WireGuard, and harness summaries.
   The controlled harness must receive exactly the configured sequence set without duplicates or malformed workload records.
   In the full BSD MITM mode, verify the requester log records a non-any device-facing `GetSockName` endpoint and the MITM logs `connect tunneled` with that same visible endpoint.
4. With the MITM and peer active, run the new no-reply timeout mode against the no-echo harness.
   Confirm the requester records the expected zero-result `POLLIN` timeout, then exits and a fresh ordinary BSD MITM echo requester launch succeeds.
5. With the MITM and peer active, run the new terminal-flow mode against the echo harness.
   While the requester waits, deactivate the selected peer through the overlay.
   Confirm `POLLHUP`, the required post-closure `ECONNABORTED` send result, the MITM terminal-flow summary, and a later fresh requester launch after peer reactivation.
   Repeat the same mode with orderly WireGuard sysmodule shutdown if the overlay can issue it while the requester is foregrounded.
   Record whether terminal service loss is observed through a drain or later-command CMIF failure as specified above.
6. With the MITM and peer active, enable the existing post-route rejection check and run a normal echo.
   Confirm `setsockopt(SO_REUSEADDR)` fails with `EOPNOTSUPP`, the echo still succeeds, and the next requester launch remains clean.
7. Run the writable-recovery mode against the quiet echo or no-echo harness with zero pacing and increasing bounded counts, for example 64, 256, then 1024 datagrams at 1200 bytes and one flow.
   Stop increasing offered load when a run records at least one local `EAGAIN`, a later `POLLOUT`, and successful retry of that exact packet.
   If the harness or WGNX ceiling occurs first, record that first explicit disposition as the initial saturation boundary instead of treating loss as success.
8. Repeat the full BSD MITM workload with four flows, then perform an orderly requester exit, MITM shutdown, and WireGuard shutdown through their declared overlay shutdown paths.
   Restart WireGuard, reconnect the peer, restart the MITM, and complete one final full BSD MITM echo.
   Confirm no module sees its own outer transport or control traffic through the BSD MITM and that this final requester process has no stale flow or descriptor state.
9. Run the measurement helper over the collected reports.
   Run `python3 tools/summarize_task4.py --check` over the collected requester, harness, MITM, and WGNX logs.
   Reconcile configured sends, requester accepted sends and echoes, harness unique received and echoed sequences, MITM local admission and rejection, WGNX admitted sends, inbound deliveries, downstream queue-full events, writable notifications, discarded records, and closure reasons.
   Do not equate requester `EAGAIN` retries with downstream `QueueFull` events because an already locally admitted payload can be resubmitted internally after `Writable`.
   Record the smallest workload that reaches an explicit queue, network, or remote-harness limit together with its throughput and disposition.

Task 4 is complete only when every expected-success scenario above passes, every expected-error scenario reports its documented outcome, the four-mode counter table reconciles, and the lifecycle restart leaves a clean final full BSD MITM echo.
The existing direct-WGNX and requester-only passive MITM tests remain regression controls throughout this sequence.
The 2026-08-01 archived device matrix satisfies this acceptance sequence.
The separate UDP performance and feasibility gate below remains open because it requires reconciled pressure accounting plus throughput and latency measurements.


### 5. Apply The UDP Performance And Feasibility Gate

Urgency: mandatory go or no-go gate before TCP implementation.

Measure the completed UDP path before its costs are obscured by TCP state and buffering.
Run the same deterministic workload in four modes:

1. Native BSD without MITM.
2. Passive BSD MITM forwarding to the original service.
3. Direct `wgnx:tun` flow without BSD interception.
4. Full BSD MITM to `wgnx:tun` to WireGuard.

For each mode, record near-MTU throughput, small-packet packets per second, paced traffic, bounded bursts, and multiple concurrent flows.
Record requester and remote counters, IPC call count, event wake count, batch fill, queue and slab high-water marks, all drop dispositions, handler latency, process memory, and sampled CPU time where available.
Disable per-packet filesystem logging for these runs and retain only aggregated counters and state-transition diagnostics.
Replace or augment any remote harness that creates one host thread and synchronous log flush per datagram before treating results as a device ceiling.

Definition of done:

- the four modes use the same workload identity, payloads, pacing, and remote endpoint
- losses and throughput deltas can be assigned to native BSD, passive MITM, private IPC, or WireGuard processing
- the result states whether ordinary batched IPC is viable for TCP exploration under the project memory budget
- any blocker has a measured limit and a bounded failure disposition rather than an unexplained timeout or crash
- shared-memory work is started early only when this gate shows ordinary IPC cannot meet the minimum documented target


### 6. Introduce The WireGuard-Owned Userspace IP Adapter

Urgency: required before TCP or broader IP protocol work.

Keep the current UDP flow IPC and MITM socket contract as the behavioral baseline while replacing the manual WireGuard-side UDP and IPv4 adapter.
Start with a host-only NO_SYS lwIP fit prototype that compiles only the IPv4, pbuf, timeout, netif, UDP, checksum, fragmentation, and reassembly components required by this path.
Do not include TCP, DNS, DHCP, netconn, lwIP sockets, or application-facing lwIP APIs in the first slice.

The adapter owns UDP endpoint state, IPv4 and UDP construction and validation, effective-MTU application, outbound fragmentation, inbound reassembly, and delivery to the existing flow completion contract.
It emits and consumes complete inner IP packets through the shared packet plane without exposing lwIP state to `PeerRuntime` or the cryptographic protocol implementation.
All lwIP operations execute through one serialized post-lock work owner, and no callback, pbuf operation, allocation, or timeout processing occurs while the daemon state mutex is held.

The MITM continues to submit and receive whole UDP datagrams through the private flow service.
It does not receive fragment records, own reassembly timers, inspect IP headers, or change its direct-versus-tunnel state machine.
The first contract advertises a measured bounded datagram maximum and returns `EMSGSIZE` above it without claiming the theoretical IPv4 UDP maximum prematurely.

Use the pinned lwIP revision and minimal Switch configuration in `wg-nx` as implementation references.
Use `netbird-switch` for reproduced lessons about one-time initialization, PCB lifecycle, static pools, shutdown ordering, and avoiding blocking under lwIP ownership.
Do not copy their relay architecture, global mutable ownership, hardcoded MTU, or application-local socket contract.

Definition of done:

- the source revision, BSD license, integrity hash, selected source list, and refresh procedure are recorded
- the manual UDP and IPv4 construction, parsing, and checksum code is removed once lwIP becomes authoritative
- outbound datagrams fragment at the effective inner MTU and inbound valid fragments produce exactly one datagram completion
- out-of-order, duplicate, overlapping, missing, expired, malformed, and resource-exhausted fragment cases have deterministic bounded outcomes
- fragment and PCB state cannot cross flow closure, policy-generation change, peer restart, or activation teardown
- pbuf, fragment, timer, stack, completion, and total memory bounds pass host sanitizer, fuzz, target, stack, and resource gates
- repeated on-device UDP workloads, path transitions, teardown, and restart preserve the Task 4 socket and leak-protection contract


### 7. Discover And Implement A First TCP Path

Urgency: required for useful general application coverage after UDP feasibility is established.

Use the stable UDP flow and BSD MITM path as the lifecycle baseline before attempting TCP.
TCP must not be represented as a sequence of UDP-like datagram submissions because its Horizon-visible socket semantics require ordered byte-stream delivery, connection establishment and failure reporting, half-close behavior, backpressure, and transport-specific teardown.

First reverse and trace the smallest ordinary `bsd:s` TCP client path used by a controlled requester.
Record the required BSD operations and observable behavior for socket creation, nonblocking mode if needed, connect, send, receive, readiness waiting, endpoint queries, shutdown, close, and error propagation.
Use that result to specify a separate versioned private WGNX stream-flow contract rather than widening the UDP API with ambiguous protocol switches.

The first implementation uses a bounded TCP path in the WireGuard-owned userspace IP adapter rather than a TCP stack or packet proxy in the MITM.
It retains the architectural boundary from the UDP work: the MITM owns BSD lifecycle and socket semantics, while the WireGuard sysmodule owns route selection, tunnel source address translation, IP and transport state, packet construction, peer lifecycle, and bounded tunnel-facing resources.
TCP connection state, retransmission, congestion behavior, and tunnel-facing buffering therefore live in the WireGuard-owned userspace IP adapter.
The MITM translates Horizon stream operations, readiness, shutdown, and errors to the versioned private stream-flow contract without parsing or constructing TCP or IP packets.
Use `netbird-switch` and `wg-nx` to study fixed-resource lwIP integration and selective transport fast paths without assuming their application-local relay architecture applies to a system MITM.
Do not expose a partially emulated TCP path to arbitrary `bsd:s` clients until its supported operation subset and failure semantics are defined.

Definition of done:

- controlled requester TCP connect, request, response, orderly shutdown, and error paths work through a real peer without app-specific WGNX IPC calls
- the TCP flow contract defines ownership, readiness, bounded send and receive buffering, peer-activation invalidation, close and half-close behavior, and all terminal error categories
- host and device tests cover repeated application launch, remote refusal, remote close, peer teardown, Wi-Fi interruption and recovery, queue pressure, and stale completion rejection
- unsupported BSD TCP operations are explicitly traceable and fail predictably without destabilizing subsequent clients


### 8. Evaluate Optional SSL MITM Scope

Urgency: deferred decision after the controlled TCP path is stable.

Evaluate `ssl:*` MITM only after the first TCP path is stable enough to carry a controlled TLS client connection.
The first question is whether BSD-level interception already routes the desired encrypted application traffic through the tunnel without touching TLS semantics.
If it does, do not add an SSL MITM merely for tunnel routing.

Only investigate an SSL MITM where it provides a concrete missing integration capability, such as traffic classification unavailable at BSD level or an application path that bypasses the BSD service behavior covered by the TCP MITM.
Treat certificate handling, client identity, session resumption, and TLS-version behavior as separate high-risk compatibility work rather than incidental extensions to transport routing.

Definition of done:

- a documented trace-based decision records whether `ssl:*` MITM is needed for transparent tunnel routing
- when BSD interception is sufficient, a controlled TLS request succeeds through the TCP path without SSL interception
- any decision to implement SSL MITM has a separately approved contract, compatibility matrix, and explicit certificate and security model before code is written


### 9. Harden And Decide On Shared-Memory Experimentation

Urgency: required before broad deployment, with an earlier trigger only when the UDP gate rejects ordinary IPC.

Repeat the Step 5 measurements after TCP support and long-lived lifecycle work so later protocol costs can be compared with the UDP baseline.
Record IPC request rate, payload-copy count, flow count, queue pressure, packet drops, end-to-end UDP and TCP latency where applicable, CPU time where available, and memory consumption in both sysmodules.
Exercise repeated clients, backpressure, peer transition, Wi-Fi interruption, and recovery with the MITM active.

Only after the ordinary IPC path survives these tests should the project experiment with shared memory for payload transfer.
Shared memory must retain the same bounded ownership, generation tagging, backpressure, and teardown guarantees as the IPC implementation.
Control-plane operations and lifecycle notifications remain ordinary IPC.
The first shared-memory implementation is an optional transport optimization behind a build or runtime experiment switch, not a replacement for the proven IPC path.
Use fixed rings and payload pools with one explicit producer and one explicit consumer per direction.
If multiple MITM service workers submit traffic, serialize them through an owned producer instead of silently turning the first ring into a multi-producer design.
Shared memory can remove the payload copy and per-datagram CMIF command between the two sysmodules, but it cannot remove the application-to-MITM BSD IPC cost.
Before building rings, run a target-side lifecycle spike that creates, shares, maps, accesses, unmaps, and destroys a bounded region across the two sysmodules.
The existing SVC permissions make this plausible but do not prove cross-sysmodule handle transfer, cache behavior, or teardown safety.

Definition of done:

- an evidence-backed decision records whether ordinary IPC is adequate or shared memory is justified
- a target-side shared-memory lifecycle spike passes before ring implementation begins
- any shared-memory experiment has fixed rings or pools, explicit producer and consumer ownership, generation-safe teardown, and measurable fallback behavior
- the shared-memory experiment is compared against the same ordinary-IPC workload and can be disabled without changing flow semantics
- integration limitations, next protocol target, and native-routing research findings are documented

## Deferred Work

DNS behavior, inbound listener APIs, generic IP protocols beyond UDP and TCP, and public API or security-model design are outside this first plan.
Each needs its own contract and test matrix after the corresponding outbound flow path is stable.

The optional SSL MITM evaluation is a decision stage rather than a commitment to TLS interception.
TLS semantics must remain untouched when the BSD transport path already provides transparent routing.

Native interface and route integration remains a research track in `nx-reversing.git`.
It should be reconsidered only when reversing establishes a supported route, interface, or lower-layer ownership model that does not replace Horizon's active network path destructively.

## Outstanding Decisions And Required Evidence

These items do not fit entirely inside one implementation step and remain explicit gates rather than implicit follow-up work.

### Minimum Performance Target

Urgency: critical before executing Step 5.

Define the minimum acceptable throughput, small-packet rate, latency, CPU use, and combined sysmodule memory budget before collecting the UDP feasibility measurements.
Without a target, the benchmark can describe overhead but cannot make the required go or no-go decision for TCP.

### CMIF Client-Context Mechanics

Urgency: critical during Step 1 and before freezing the current `TunApiVersion` contract.

Prototype the exact libstratosphere object and cloned-session shape used to share one logical tunnel-client context across concurrent MITM workers.
The prototype must demonstrate final-reference cleanup, bounded kernel-handle use, and no lost completion wake during concurrent drain and close.

### Generic Packet-Source Boundary

Urgency: required before Step 6 and before any claim of arbitrary IP support.

Define the internal interface between the WireGuard-owned userspace IP adapter and the shared inner-packet plane after the UDP implementation has provided concrete ownership and backpressure requirements.
The interface must accept complete packets emitted by the userspace IP adapter and support a future lower-layer complete-packet source without forcing BSD payload adapters to fabricate packet ownership they do not have.
It must apply outbound route authorization before peer submission and inbound peer AllowedIPs source authorization before any plaintext consumer.
Do not expose this internal boundary as a public raw-packet API merely to avoid the design decision.

### Production Diagnostic Budget

Urgency: required during Steps 3 and 4, before performance testing.

Define bounded counters, state-transition records, sampling gates, and flush policy separately from packet storage.
Per-packet file logging and synchronous flushes must remain behind an explicit debug mode so observation does not dominate the path being measured.

### Public Policy And Security Model

Urgency: deferred until the transparent path is viable, but required before a stable public release.

The private service remains permissive during research.
Before advertising it as a supported third-party interface, specify caller expectations, resource fairness, denial-of-service behavior, compatibility guarantees, and whether any process identity or service ACL policy is appropriate.

## External Implementation References

The local reference clones under `workspace/repos/` inform implementation research, but neither is a replacement for the WireGuard sysmodule or the separate `bsd:s` MITM architecture in this document.

[`netbird-switch`](../workspace/repos/netbird-switch/) provides a Switch-specific userland reference for bounded UDP proxying, lwIP integration, BSD socket shutdown ordering, and the restricted nonblocking flag behavior observed through Horizon BSD services.
Its own documented future direction is a `bsd:u` MITM, but this project must apply the relevant lifecycle and BSD-semantic findings to `bsd:s` instead.
Its application-local TCP and UDP proxy and relay-oriented architecture must not be imported into the transparent system-service path.
Its lwIP configuration, PCB lifecycle, static-pool, initialization, and shutdown lessons may inform the separate WireGuard-owned IP adapter after they are reproduced under this project's resource and lock-safety gates.

[`wg-nx`](../workspace/repos/wg-nx/) provides an independent Switch WireGuard and lwIP relay reference, including optional NEON-oriented performance work and fixed-resource packet handling ideas.
It does not provide Horizon service interception, NIFM-directed recovery policy, generation-safe private flow IPC, or flow ownership suitable for this project.
Revisit it as a source-list, configuration, bounded packet storage, relay behavior, and performance reference without copying its global ownership model or merging lwIP into the WireGuard protocol core.
