# Task 7 TCP Flow Foundation Implementation Guide

## Goal

This guide covers the first three Task 7 slices as one coordinated repository cutover.
It reshapes the private `wgnx:tun` contract for explicit connected IPv4 TCP streams, adds a direct Toolbox client for that contract, and implements TCP in the WireGuard-owned lwIP adapter.
The result is a bounded direct `wgnx:tun` TCP request and response through a real WireGuard peer without BSD interception.
The BSD MITM TCP translation is the next slice and is deliberately outside this guide.

`wgnx:tun` remains a private active-development API.
No compatibility shim, deprecated command, dual-version handler, or migration path is required.
Every incompatible command, record, capability, lifecycle, or semantic change in this cutover increments `TunApiVersion` and updates every in-tree producer, consumer, test, and document together.

## Confirmed Evidence

The 2026-08-10 controlled Toolbox trace admitted both `bsd:s` root sessions and captured a successful TCP exchange through native BSD.
The observed command sequence was `RegisterClient`, `StartMonitoring`, `Socket`, two `SetSockOpt` calls, `Connect`, `GetSockName`, `Send`, `Poll`, `Recv`, and `Close`.
The client opened `AF_INET`, `SOCK_STREAM`, `IPPROTO_TCP`, connected to the configured IPv4 endpoint, sent `NXRV TCP <workload-id>\r\n`, received `NXRV TCP ACK\r\n`, and closed cleanly.
This is enough evidence for the first connected-client stream contract and direct WGNX scenario.
It does not yet characterize nonblocking connect, `Shutdown`, partial writes, remote refusal, reset, or timeout behavior at the BSD boundary, so those translations remain MITM acceptance work rather than assumptions in this slice.

## Version 3 Baseline

The version 3 baseline was verified locally on 2026-08-10 with `make -C wg-sysmodule verify`.
The aggregate gate completed formatting, static analysis, clang-tidy, warnings, host tests, ASan/UBSan, fuzz, target, stack, and resource checks.
The private wire contract has two root commands and nine client commands, a 64-byte capability record, 16-byte connected-open request, 24-byte open result, 24-byte datagram descriptor, 16-byte datagram disposition, 48-byte completion record, and 40-byte flow-state result.
Its client-actionable behavioral baseline is four client contexts, four flows per client, 16 total flows, 1,472 bytes of UDP payload storage, a 16-record completion queue, eight batch entries, 16 policy routes, and the documented post-lwIP UDP latency and throughput results in `docs/PERF.md`.
The Task 6 target footprint baseline is 1,401,026 static bytes, a 263,469-byte NSO, and a 264,529-byte NSP within the reviewed limits.

## Current Code Boundary

| Current source                                                           | Responsibility to preserve                                                                                                   | Task 7 foundation change                                                                                                                                  |
|--------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| `common/include/wgnx/tunnel_protocol.hpp`                                | Private API version 3, client contexts, route snapshots, flow handles, UDP records, completions, and capabilities            | Replace version 3 with a compact version 4 contract that shares genuine flow concepts while keeping datagram and stream operations semantically distinct. |
| `common/include/wgnx/tunnel_client.hpp`                                  | Move-only root and child clients plus checked CMIF wrappers                                                                  | Cut over all wrappers to version 4 and provide a one-datagram convenience wrapper over the sole batched UDP wire command.                                 |
| `wg-sysmodule/src/tunnel_service.*`                                      | CMIF validation and translation into runtime operations                                                                      | Replace the version 3 command table in one cutover and add connected TCP open, stream write, and write-shutdown commands.                                 |
| `wg-sysmodule/src/runtime/tunnel_flow_plane.*`                           | Client ownership, policy, routes, virtual tuples, generation-safe handles, completion reservation, and terminal invalidation | Add an explicit flow kind and TCP lifecycle without moving TCP state or packet parsing into the flow plane.                                               |
| `wg-sysmodule/src/ip/userspace_ip_adapter.*`                             | Sole lwIP netif, UDP PCBs, pbuf ownership, callbacks, timers, and copied output collectors                                   | Enable raw-API TCP PCBs and callbacks while retaining `NO_SYS=1`, one serialized owner, and complete IPv4 packet output.                                  |
| `wg-sysmodule/src/runtime/userspace_ip_adapter_owner.*`                  | One generation-tagged operation slot on `wgnx-submit`                                                                        | Add bounded TCP open, write, shutdown, close, input, and timeout operations without adding a thread or lwIP mutex.                                        |
| `wg-sysmodule/src/runtime/daemon_runtime.*`                              | Locked reservation, post-lock adapter execution, generation-checked commit, and packet-batch submission                      | Compose TCP operations through the existing three-phase boundary and preserve atomic complete-IP publication.                                             |
| `wg-sysmodule/src/ip/lwipopts.h` and `common/include/wgnx/lwip_budget.h` | Minimal UDP-only lwIP feature and memory selection                                                                           | Add only raw TCP and explicit TCP pools, windows, queues, segments, and timeout capacity backed by measured fixed limits.                                 |
| `nx-reversing.git/toolbox/src/wgnx_tunnel_scenario.*`                    | Direct UDP flow and contract-validation client                                                                               | Add a direct TCP scenario using the same service discovery, API validation, profile, workload ID, event, and reporting conventions.                       |
| `nx-reversing.git/toolbox/src/bsd_system_tcp_scenario.*`                 | Native BSD TCP control case                                                                                                  | Keep it as the native comparison and share only request, reply, and result conventions where that removes duplication.                                    |

The required ownership remains:

```text
Toolbox direct TCP scenario
        |
        v
private wgnx:tun connected-stream IPC
        |
        v
project-owned flow state and bounded completion queues
        |
        v
serialized lwIP TCP PCB on wgnx-submit
        |
        v
complete IPv4 packets through PacketDataPlane
        |
        v
peer-owned WireGuard staging, encryption, and outer UDP transport
```

## Version 4 Contract Direction

The API should combine only concepts whose semantics are genuinely shared.
Client contexts, policy snapshots, flow handles, completion events, generation fields, local and remote endpoints, lifecycle queries, closure, and terminal invalidation remain common.
UDP datagram submission and TCP stream writing remain separate commands because datagram atomicity and byte-stream progress are different contracts.

Use separate `OpenConnectedUdpFlow` and `OpenConnectedTcpFlow` commands with one shared `OpenConnectedFlowRequest` and one shared `OpenFlowResult` layout.
The command ID, rather than a caller-provided protocol switch, selects the transport and prevents an invalid or ambiguous flow kind.
Add `FlowKind` to flow-state and completion records so a drained mixed-flow completion batch is self-describing.

Replace `DatagramDescriptor` and `DatagramDisposition` with transport-neutral payload range and result records that can be used by transport-specific commands.
The result must carry the client tag, status, and accepted byte count.
A successful UDP disposition accepts the complete datagram or zero bytes, while a TCP write may initially retain the simpler all-or-nothing bounded-chunk rule and report zero with `QueueFull` when lwIP cannot accept the whole chunk.
The MITM can later split a larger BSD stream send into bounded writes and return accumulated progress without weakening the private API.

Keep one batched UDP wire command and implement the single-datagram client helper as a one-entry batch call.
This removes duplicate CMIF handlers while preserving the measured UDP batching path.
Add one non-batched TCP stream-write command for the first implementation and add stream batching only if measurement demonstrates a need.

Retain one completion drain and one completion event per logical client context.
Use distinct completion types for inbound UDP datagrams, inbound TCP stream data, flow-state changes, policy changes, and restored write capacity.
Completion draining must remain ordered and atomic with event clearing, and control completions must retain reserved capacity under data pressure.

Represent TCP connection progress explicitly rather than overloading the current UDP meaning of `FlowState::Open`.
The common lifecycle must distinguish at least `Connecting`, `Open`, `Closing`, and `Closed`.
The flow-state result must separately report whether the local write side and remote write side are open or closed so half-close does not require an expanding set of combined states.
Add a write-shutdown command that queues a FIN after previously accepted stream bytes and is idempotent once the local write side is closed.

Keep immediate operation status separate from terminal transport cause.
Immediate statuses cover malformed input, unsupported operation, route or peer unavailability, quota exhaustion, queue pressure, stale handles, wrong flow kind, not connected, write side closed, and output-buffer limits.
Terminal reasons cover client close, orderly remote close, reset during connect, reset after connect, connect timeout, route loss, peer or policy invalidation, local resource failure, and sysmodule shutdown.
The later BSD adapter will map these closed categories to errno values without exposing lwIP `err_t` values over IPC.

The advertised local endpoint must come from the WireGuard-owned virtual tuple and actual lwIP PCB binding.
The TCP path must never open a native BSD connection merely to obtain a visible local address or port because that would create a direct connection outside the tunnel.

Prune `Capabilities` to consumer-actionable limits during the version bump.
Retain the API version, capability mask, effective inner MTU, maximum UDP datagram bytes, maximum TCP write bytes, client and flow limits, completion capacity, maximum completion batch, and maximum policy routes.
Remove internal storage details such as packet-slab counts, kernel-handle counts, and tuple-quarantine capacity unless an in-tree client uses them to make a required decision.
Advertise connected IPv4 UDP and connected IPv4 TCP independently.

## Implementation Checklist

### Contract Cutover

- [x] **1. Record the version 3 baseline and finalize the version 4 wire contract.**

  Run the existing WireGuard and Toolbox host, sanitizer, warning, target, stack, static-analysis, and resource gates before changing layouts.
  Record current structure sizes, command IDs, capability fields, queue capacities, UDP latency and throughput baselines, and the latest target footprint.
  Define the exact version 4 command IDs, enums, records, size assertions, status semantics, state transitions, completion ordering, and shutdown behavior before implementing runtime TCP state.
  Treat existing behavior as a correctness baseline, not a compatibility requirement.

  The resulting version 4 contract direction is recorded above and will replace rather than preserve the version 3 surface.

- [x] **2. Replace the private protocol and client wrappers atomically.**

  Increment `TunApiVersion` from 3 to 4 and rewrite `tunnel_protocol.hpp`, `tunnel_client.hpp`, the CMIF interfaces, and the shared batch helper in one cutover.
  Use shared open, payload-range, payload-result, flow-state, and endpoint records only where their semantics are transport-neutral.
  Retain separate UDP batch and TCP stream-write commands, remove the duplicate single-UDP wire command, and add connected TCP open plus write-shutdown commands.
  Renumber commands compactly if that produces a clearer version 4 surface.
  Update all layout assertions and reject wrong-kind operations deterministically.

  Version 4 now uses shared `OpenConnectedFlowRequest`, `OpenConnectedFlowResult`, `PayloadRange`, and `PayloadResult` records.
  The client retains a one-range UDP helper over the batch wire command, while the service exposes separate TCP open, write, and write-shutdown commands for the adapter implementation.

- [x] **3. Update every existing producer, consumer, test, and document to version 4 before adding TCP behavior.**

  Migrate the WireGuard service, UDP flow plane, MITM UDP worker, Toolbox UDP workload, contract-validation scenario, API-version logging, host tests, and documentation together.
  Preserve UDP route selection, datagram atomicity, batching, queue-full recovery, completion-event behavior, clone lifetime, shutdown wake, terminal invalidation, and measured capability limits.
  Do not keep version 3 structures, command handlers, branches, aliases, or compatibility tests.
  Require the complete existing UDP host and target verification gate to pass after the cutover.

  The WireGuard service, runtime, MITM UDP worker, Toolbox UDP scenario, contract tests, protocol specification, and integration plan now consume only version 4 layouts and command IDs.
  UDP behavior remains unchanged, and TCP commands return `UnsupportedOperation` until the WireGuard-owned lwIP implementation lands.

### Direct Toolbox TCP Client

- [x] **4. Add a protocol-native direct TCP scenario to Toolbox.**

  Add `DirectTunnelTcp` beside the native `BsdSystemTcp` control scenario and reuse the active profile's tunnel IPv4 destination, TCP port, receive deadline, workload ID, request bytes, and expected ACK.
  Open the root and child services, validate API version 4 and the connected-TCP capability, obtain the completion event, open one TCP flow, and wait for `Open` before writing.
  Send the complete tagged request through bounded write calls, receive ordered stream completions until the complete ACK is assembled, observe orderly remote write closure when the harness closes, and close the flow.
  Log the advertised local endpoint, connection time, accepted and received bytes, write retries, event wakes, state transitions, terminal reason, and close result.

  Toolbox now provides `DirectTunnelTcp` with an INI-selectable scenario and the active profile's tunnel endpoint and TCP port.
  It checks the API and TCP capability, waits for the asynchronous open transition, validates the WireGuard-owned virtual local endpoint, writes `NXRV TCP <id>\r\n`, requests a local half-close, validates the ACK and remote EOF, then closes the flow.
  Until the lwIP TCP adapter advertises `ConnectedIpv4Tcp`, the scenario fails at the capability boundary without opening a native BSD socket.

- [x] **5. Make the scenario fail precisely at every contract boundary.**

  Distinguish service absence, API mismatch, missing capability, route rejection, peer unavailability, connect failure, deadline expiry, queue pressure, stale handle, premature EOF, reset, malformed reply, and terminal service loss.
  Preserve the already implemented rule that a completion-event wake followed by CMIF failure is terminal sysmodule shutdown.
  Advance and persist the workload ID before starting the run, and keep the native BSD TCP scenario unchanged as the comparison path.
  Add host coverage for configuration parsing, validation, scenario selection, and any transport-neutral request or reply helper extracted from the existing native scenario.

  Direct TCP diagnostics now distinguish service absence, API mismatch, unavailable TCP capability, immediate protocol statuses, terminal flow cause, separate connect and reply deadlines, premature EOF, malformed replies, and shutdown after a completion wake.
  The harness provides a configurable stalled established TCP endpoint for deadline evaluation without conflating it with a SYN blackhole.
  Host tests execute the production runtime INI loader for TCP scenario selection and invalid-value fallback, and the workload ID remains reserved and persisted before the worker starts.

### WireGuard-Owned lwIP TCP

- [x] **6. Enable the minimal raw lwIP TCP source and configuration set with explicit budgets.**

  The deliberately narrow Task 6 vendor tree does not contain `tcp.c`, `tcp_in.c`, or `tcp_out.c`, so import exactly those files from the already selected lwIP 2.2.1 tag and commit.
  Update `UPSTREAM.md`, the selected-file manifest, and integrity hashes in the same change, then compile the added sources in host, sanitizer, fuzz, warning, and target builds.
  Keep `NO_SYS=1`, raw callbacks, one netif, no lwIP sockets, no netconn, no altcp, no listener API in the project contract, no DNS, and no new thread.
  Define fixed `MEMP_NUM_TCP_PCB`, `MEMP_NUM_TCP_SEG`, send-buffer, send-queue, receive-window, out-of-order queue, MSS, and timeout limits in `lwip_budget.h` and mirror them in `resource_budget.hpp`.
  Derive MSS from the active effective inner MTU and begin with the smallest limits that support the single controlled flow plus deterministic pressure tests.
  Accept final values only after target footprint and queue-exhaustion evidence.

  The pinned lwIP 2.2.1 source set now includes unmodified `tcp.c`, `tcp_in.c`, and `tcp_out.c`, with refreshed provenance hashes for 182 upstream files.
  `NO_SYS=1` remains in force with raw TCP only, one PCB, eight segments, two-MSS send and receive windows, no out-of-order queue, and twelve timeout slots.
  The compile-time 1,380-byte MSS is the default-MTU ceiling, while the forthcoming adapter binds each PCB with an active-MTU cap before `tcp_connect()`.
  Host, ASan/UBSan, warnings, target stack, and footprint gates pass with a 1,389,090-byte static image, 269,504-byte NSO, and 270,564-byte NSP.

- [x] **7. Add TCP PCB ownership and copied callback results to `UserspaceIpAdapter`.**

  Give each adapter flow slot an explicit kind and a UDP or TCP PCB without exposing lwIP types outside the adapter.
  Bind the TCP PCB to the flow plane's virtual local IPv4 address and port, register connected, receive, sent, error, poll, and shutdown callbacks, and start `tcp_connect()` to the fixed remote endpoint.
  Callbacks may only update bounded adapter-owned state and copied collectors.
  They must not call daemon state, packet-plane, peer, logging, CMIF, platform I/O, or another thread.
  Remove or abort every PCB during reset so no callback or queued segment survives adapter epoch change.

  Each adapter slot now owns either a UDP PCB or a raw TCP PCB, with the TCP PCB bound to the supplied virtual tuple and its MSS capped to the active adapter MTU.
  Connected, receive, sent, poll, and error callbacks publish only fixed copied stream records or TCP events, while collector pressure returns `ERR_MEM` without acknowledging discarded receive bytes.
  Reset and close detach callbacks and abort TCP PCBs, and the owner-size bound rises from 16 KiB to 24 KiB to hold four copied 1,460-byte stream records alongside the existing UDP collectors.
  Host coverage verifies one TCP PCB emits a SYN through the normal complete-IP packet collector and rejects stream writes before connection completion.

- [x] **8. Extend the serialized owner and daemon three-phase boundary for TCP operations.**

  Add generation-tagged open, write, write-shutdown, close, input, and timeout operations to the existing owner lane.
  Preserve the one accepted data operation slot unless measurement proves it inadequate, and keep reset and close control work coalesced or reserved so data pressure cannot suppress lifecycle cleanup.
  Reserve and validate under the daemon mutex, execute lwIP after releasing it, and commit results under the mutex only when client, flow, peer, policy, adapter epoch, and operation generation still match.
  Drain every complete IPv4 output collector through atomic `PacketDataPlane` batch admission and never publish an individual TCP segment from inside a netif callback.

  TCP open, write, write-shutdown, close, input, receive-credit, and timeout work now share the one-generation owner data slot, while reset and fixed control close work remain reserved ahead of it.
  Input carries peer, policy, and adapter-epoch identities and is rejected before lwIP when any is stale.
  The daemon commits the reserved TCP open only after owner execution and routes complete copied output packets through one atomic packet-plane batch after the owner returns.
  Host coverage verifies that a tagged TCP open emits a copied SYN and that reserved TCP cleanup preempts ordinary data work.

- [x] **9. Implement asynchronous connect state and virtual endpoint publication.**

  Reserve the route, peer generation, virtual local tuple, completion capacity, and adapter token before queuing TCP open.
  Return a valid flow in `Connecting` after the open operation is accepted, publish `Open` only from the successful lwIP connected callback, and emit one ordered state-change completion.
  Publish refusal, reset, timeout, route failure, resource failure, cancellation, and stale completion as closed terminal outcomes.
  Return the same actual lwIP-bound virtual local endpoint from `GetFlowState` throughout the flow lifetime.

  The flow plane reserves the complete peer, policy, virtual tuple, and owner token before queuing the raw TCP PCB creation.
  A successful owner open commits the flow as `Connecting`, and only the serialized lwIP connected callback publishes the ordered `Open` completion.
  `GetFlowState` exposes the same virtual tuple from reservation through closure, while reservation failure, stale callback, reset, and timeout remain closed outcomes.
  Host coverage verifies the asynchronous `Connecting` to `Open` transition, its one completion, stream flags, and stable virtual endpoint.

- [x] **10. Implement bounded stream writes and writable recovery.**

  Copy one caller chunk into owner storage, call `tcp_write(..., TCP_WRITE_FLAG_COPY)`, and call `tcp_output()` from the serialized owner.
  Admit the complete bounded chunk or return zero accepted bytes with `QueueFull` for the first contract.
  Record a writable waiter only after an actual capacity rejection and publish one coalesced writable completion when `tcp_sent` or another TCP transition restores sufficient capacity.
  Preserve byte order across retries, never duplicate accepted bytes, and reject writes while connecting, after local write shutdown, or after terminal closure with distinct statuses.

  The owner copies one bounded write into its single data slot and calls `tcp_write(..., TCP_WRITE_FLAG_COPY)` followed by `tcp_output()` after leaving the daemon mutex.
  Once `tcp_write()` succeeds, the write reports complete acceptance even when output is deferred, so a caller cannot duplicate bytes by retrying a range already owned by lwIP.
  Capacity rejection reports `QueueFull`, marks one writable waiter, and the copied `tcp_sent` callback publishes one coalesced `Writable` completion when capacity returns.
  Host coverage verifies the accepted TCP write identity and one writable recovery after repeated capacity notifications.

- [x] **11. Implement bounded receive delivery and TCP backpressure.**

  Copy received pbuf chains into bounded stream-data collectors in order and publish them through the existing completion-drain payload buffer.
  Call `tcp_recved()` only for bytes successfully admitted to project-owned receive storage.
  When completion or payload storage is full, retain TCP backpressure without acknowledging discarded bytes, and resume delivery after the client drains capacity.
  Treat a null receive pbuf as orderly remote write closure, distinguish it from reset, and keep already admitted bytes drainable before the terminal or half-close notification.

  Current state: the adapter retains copied stream bytes without calling `tcp_recved()`.
  The daemon queues fixed receive-credit intents only after the flow plane accepts the corresponding stream completion, and the serialized owner applies that credit before ordinary data work.
  This prevents lwIP from reopening the receive window for data rejected by bounded completion storage.

  Copied pbuf chains enter fixed stream collectors in order, and collector pressure returns `ERR_MEM` without freeing or acknowledging the rejected lwIP receive pbuf.
  Receive credits are emitted only after the flow plane owns a corresponding completion record and are serialized ahead of ordinary data work.
  A null pbuf produces the distinct remote-write-close state transition after already admitted bytes, while reset remains a terminal close reason.
  Host coverage verifies stream-completion pressure, preservation after an undersized drain buffer, and delivery of all admitted bytes before the remote half-close completion.

- [ ] **12. Implement half-close, close, timeout, and invalidation semantics.**

  Queue local write shutdown after previously accepted bytes, make repeated shutdown idempotent, and continue receiving until remote EOF or terminal error.
  Define `CloseFlow` as client ownership release with bounded cleanup, including the policy for pending unsent bytes and any graceful-close state retained after the client no longer receives data.
  Drive TCP retransmission and connection timers only through the existing serialized `sys_check_timeouts()` path.
  On client destruction, policy change, peer activation change, peer deactivation, adapter reset, or sysmodule shutdown, abort or close the PCB, retire pending operations, scrub copied stream storage, quarantine the virtual tuple, and reject stale callbacks.

  Current state: a connecting flow that remains unopened for five seconds now closes with the terminal `ConnectTimedOut` reason.
  The timeout is evaluated after serialized lwIP timer work and its PCB is aborted through a fixed reserved control-close lane, so pending data work cannot suppress cleanup or reset another TCP flow.
  The remaining half-close and invalidation combinations remain outstanding.

- [ ] **13. Add deterministic correctness, pressure, and resource coverage.**

  Extend protocol layout tests, flow-plane tests, adapter tests, owner tests, runtime composition tests, and the adapter-input fuzz target.
  Use a deterministic lwIP-backed test peer or an equivalent production-lwIP loopback fixture so production code never gains a handmade TCP parser or state machine.
  Cover connect success, ordered request and response, segmentation, retransmission timer progress, partial remote delivery, send pressure and writable recovery, receive pressure, orderly EOF, local half-close, reset while connecting, reset after connection, timeout, stale callback, policy invalidation, peer restart, client destruction, and repeated flow reuse.
  Require ASan and UBSan, warnings, format, static analysis, clang-tidy, target build, stack ceilings, fixed-capacity assertions, and a reviewed footprint delta.

- [ ] **14. Complete the direct real-peer acceptance gate and record the boundary for MITM work.**

  Run the native BSD TCP scenario as a control, then run the direct `wgnx:tun` TCP scenario against the same harness through the tunnel IPv4 address.
  Require a successful connection, exact request and ACK bytes, a nonzero virtual local endpoint, ordered stream accounting, orderly closure, zero unexplained drops, and complete resource cleanup.
  Repeat after one peer deactivate and reactivate cycle, then test one closed remote port to confirm a bounded terminal connection failure and a successful subsequent connection.
  Archive Toolbox, harness, and WireGuard logs and record the target footprint and first latency result.
  Stop before BSD TCP interception and use the completed version 4 stream contract as the sole transport boundary for that next slice.

## Verification Gates

Run the existing aggregate WireGuard gate after each coherent WireGuard change:

```sh
make -C wg-sysmodule verify
```

Run the Toolbox host tests, target build, and formatting gate after each Toolbox change:

```sh
cmake --build --preset host-tests
ctest --test-dir build-host-tests --output-on-failure
cmake --build --preset toolbox
cmake --build build --target format-check
```

The version 4 cutover is not complete while any in-tree module advertises version 3, retains a version 3 command path, or interprets a changed record using an old layout.
The TCP implementation is not accepted merely because lwIP completes a handshake in an isolated test.
It must pass through the production adapter owner, packet plane, WireGuard peer, direct `wgnx:tun` client, and controlled real peer with bounded resource accounting.

## Scope After This Guide

The next Task 7 slice adds TCP handling to the MITM sysmodule.
That work maps the traced Horizon `bsd:s` stream operations, blocking and nonblocking behavior, readiness, errno values, endpoint queries, half-close, and close semantics onto the completed private TCP flow contract.
It must not add TCP packet parsing, retransmission, congestion control, native TCP anchor connections, or another userspace stack to the MITM.
