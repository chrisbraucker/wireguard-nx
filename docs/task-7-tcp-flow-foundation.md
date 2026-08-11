# Task 7 TCP Flow Foundation Implementation Guide

## Goal

This guide covers the Task 7 TCP foundation and its narrow Toolbox-only BSD:S MITM continuation as one coordinated repository cutover.
It reshapes the private `wgnx:tun` contract for explicit connected IPv4 TCP streams, adds a direct Toolbox client for that contract, implements TCP in the WireGuard-owned lwIP adapter, and translates the first BSD:S stream-operation subset.
The result is a bounded direct or Toolbox-intercepted TCP request and response through a real WireGuard peer without a native TCP anchor connection.

`wgnx:tun` remains a private active-development API.
No compatibility shim, deprecated command, dual-version handler, or migration path is required.
Every incompatible command, record, capability, lifecycle, or semantic change in this cutover increments `TunApiVersion` and updates every in-tree producer, consumer, test, and document together.

## Confirmed Evidence

The 2026-08-10 controlled Toolbox trace admitted both `bsd:s` root sessions and captured a successful TCP exchange through native BSD.
The observed command sequence was `RegisterClient`, `StartMonitoring`, `Socket`, two `SetSockOpt` calls, `Connect`, `GetSockName`, `Send`, `Poll`, `Recv`, and `Close`.
The client opened `AF_INET`, `SOCK_STREAM`, `IPPROTO_TCP`, connected to the configured IPv4 endpoint, sent `NXRV TCP <workload-id>\r\n`, received `NXRV TCP ACK\r\n`, and closed cleanly.
This is enough evidence for the first connected-client stream contract and direct WGNX scenario.
The trace does not characterize nonblocking connect, `Shutdown`, partial writes, remote refusal, reset, or timeout behavior at the BSD boundary.
The MITM continuation therefore implements only its explicit narrow contract and leaves those untraced behaviors to the focused acceptance and later compatibility work.

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

- [x] **12. Implement half-close, close, timeout, and invalidation semantics.**

  Queue local write shutdown after previously accepted bytes, make repeated shutdown idempotent, and continue receiving until remote EOF or terminal error.
  Define `CloseFlow` as client ownership release with bounded cleanup, including the policy for pending unsent bytes and any graceful-close state retained after the client no longer receives data.
  Drive TCP retransmission and connection timers only through the existing serialized `sys_check_timeouts()` path.
  On client destruction, policy change, peer activation change, peer deactivation, adapter reset, or sysmodule shutdown, abort or close the PCB, retire pending operations, scrub copied stream storage, quarantine the virtual tuple, and reject stale callbacks.

  A connecting flow that remains unopened for five seconds closes with the terminal `ConnectTimedOut` reason.
  The timeout is evaluated after serialized lwIP timer work and its PCB is aborted through a fixed reserved control-close lane, so pending data work cannot suppress cleanup or reset another TCP flow.
  Local write shutdown is idempotent at both the raw PCB and flow-state boundary, continues receiving until remote EOF or a terminal error, and rejects later writes with `LocalWriteClosed`.
  Client destruction, policy and peer transitions, adapter reset, and shutdown abort or retire adapter state, quarantine the virtual tuple, and make stale callbacks harmless.
  Host coverage verifies connect timeout, repeated local shutdown, remote half-close, peer invalidation, and the distinct terminal reasons.

- [x] **13. Add deterministic correctness, pressure, and resource coverage.**

  Extend protocol layout tests, flow-plane tests, adapter tests, owner tests, runtime composition tests, and the adapter-input fuzz target.
  Use a deterministic lwIP-backed test peer or an equivalent production-lwIP loopback fixture so production code never gains a handmade TCP parser or state machine.
  Cover connect success, ordered request and response, segmentation, retransmission timer progress, partial remote delivery, send pressure and writable recovery, receive pressure, orderly EOF, local half-close, reset while connecting, reset after connection, timeout, stale callback, policy invalidation, peer restart, client destruction, and repeated flow reuse.
  Require ASan and UBSan, warnings, format, static analysis, clang-tidy, target build, stack ceilings, fixed-capacity assertions, and a reviewed footprint delta.

  Current state: the deterministic host suite now completes a real lwIP TCP handshake through the production adapter, emits one request segment, and delivers two ordered remote stream segments before receive acknowledgement, EOF, and idempotent local half-close.
  The existing flow-plane and adapter-owner cases cover bounded send and receive pressure, writable recovery, connect timeout, reset and invalidation retirement, stale generations, client destruction, and flow reuse.
  The adapter-input fuzz target now opens both bounded UDP and TCP flows before input, so malformed and valid inner IPv4 traffic reaches the TCP receive and reset boundaries without introducing a project TCP parser or state machine.
  The aggregate host, sanitizer, warning, static-analysis, tidy, target, stack, and footprint gates remain required for every future TCP change.

- [ ] **14. Complete the direct real-peer acceptance gate and record the boundary for MITM work.**

  Run the native BSD TCP scenario as a control, then run the direct `wgnx:tun` TCP scenario against the same harness through the tunnel IPv4 address.
  Require a successful connection, exact request and ACK bytes, a nonzero virtual local endpoint, ordered stream accounting, orderly closure, zero unexplained drops, and complete resource cleanup.
  Repeat after one peer deactivate and reactivate cycle, then test one closed remote port to confirm a bounded terminal connection failure and a successful subsequent connection.
  Archive Toolbox, harness, and WireGuard logs and record the target footprint and first latency result.
  The completed follow-on MITM implementation uses the version 4 stream contract as its sole transport boundary.
  Its focused acceptance routine is included below and remains separate from Item 14's direct-path evidence.

## On-Device Acceptance Guide

This guide first validates the production direct path with the MITM sysmodule disabled.
It then validates the narrow Toolbox-only BSD TCP translation against that direct baseline.
It does not validate general BSD TCP compatibility, additional program IDs, or transparent application routing.

### Shared Setup

1. Build and deploy the current `wg-sysmodule` and Toolbox from the same version 4 headers.
   Start the WireGuard sysmodule, activate the configured peer, and wait until the tunnel has an endpoint and an established session.
   Disable the MITM sysmodule for the direct-path phases so `wgnx:tun` is the only tested tunnel client.

2. On the controlled remote host, start the existing harness on an address reachable through the peer's tunnel routing.

   ```sh
   python3 nx-reversing.git/tools/requester_harness.py --listen-host 0.0.0.0 --tcp-ack-port 28080 --tcp-stall-port 28082
   ```

   The harness must show that TCP port `28080` is listening before any device run starts.
   Choose a distinct unused remote TCP port, such as `28081`, for the refusal test and do not start a listener there.

3. In Toolbox, create or select one profile with `tunnel_destination_ipv4` set to the remote tunnel IPv4 address and `tcp_destination_port=28080`.
   Set `tcp.receive_deadline_ms=5000` unless the Wi-Fi path needs a longer, explicitly recorded deadline.
   Record the active profile, peer endpoint, Toolbox build, WireGuard build, and the workload ID shown immediately before each run.
   Toolbox reserves and persists that ID before starting, so never reuse an ID after a failed or interrupted run.

4. Start a fresh log capture for each run and retain the Toolbox log, harness log, and WireGuard sysmodule log together under one run directory in `workspace/reports/`.
   Preserve the unedited raw logs and record the current target footprint from the most recent `make -C wireguard-nx.git/wg-sysmodule resource-report` output beside them.

### Item 7 Focused Adapter Acceptance

1. Select `Direct tunnel TCP exchange` on Toolbox's Main page and run it once against the active profile.
   The expected Toolbox result is `[OK] wgnx_tunnel_tcp_exchange` with `api=4`, a nonzero `virtual_local_port`, `accepted=` equal to the request length, `reply=validated`, `eof=observed`, and `close=ok`.

2. Confirm that the harness received exactly `NXRV TCP <workload-id>\r\n` and replied with exactly `NXRV TCP ACK\r\n`.
   Confirm in the WireGuard log that the flow opened, connected, emitted tunnel IPv4 TCP packets, accepted the reply, observed remote EOF, and retired its PCB without an input rejection, collector overflow, or unexplained drop.

3. Repeat the same direct run once after stopping and restarting the WireGuard sysmodule.
   Both runs must succeed with separate workload IDs, and the second run must establish a new virtual local endpoint rather than using stale client, flow, or adapter state.

### Item 14 Direct Real-Peer Acceptance

1. Establish the native control first.
   Change only the scenario to `BSD system TCP exchange` and set `bsd_destination_ipv4` to the remote host address that is reachable through the normal native route, while retaining TCP port `28080`.
   Run once with the MITM disabled and require the same exact request and ACK bytes plus a clean native socket close.

2. Restore `Direct tunnel TCP exchange` and the remote tunnel IPv4 destination, then run it once through the active peer.
   Require the complete Item 7 success string, exact harness request and reply, one nonzero virtual local endpoint, ordered stream delivery before EOF, and no unexplained WireGuard, adapter, or packet-plane drops.

3. Deactivate the peer after the successful direct run, reactivate it, wait for a new tunnel session, and run the same direct scenario again.
   Require a new successful round trip with a new workload ID and complete cleanup of the earlier flow before accepting the recovery path.

4. Change only the active profile's TCP port to the known closed remote port and run the direct scenario once.
   Require a bounded terminal connection failure before the configured deadline and record its terminal reason from the Toolbox and WireGuard logs.
   Restore port `28080` and require one further successful direct TCP exchange to prove that the failure did not poison later flow creation.

5. Mark Item 14 complete only when all five runs have matching raw logs and all direct runs show API version 4, the expected exact bytes, orderly EOF and close, zero unexplained drops, and released resources.
   The current Toolbox TCP scenario does not emit a monotonic latency metric, so record latency as `not measured by this scenario` rather than inventing one.
   Add a dedicated timestamped TCP measurement only when latency is needed as a decision metric, then rerun the accepted direct case.

### Toolbox BSD TCP MITM Acceptance

Run this sequence immediately after one accepted direct Item 14 exchange so both paths use the same peer, harness, profile, build set, and network conditions.

1. Keep the active peer and harness listener on TCP port `28080` unchanged.
   Confirm the direct baseline used `tunnel_destination_ipv4` set to the remote tunnel IPv4 address and completed with the exact expected request and reply.

2. Deploy and start the MITM sysmodule built with `TOOLBOX_FORWARDER_PROGRAM_ID` set to the installed Toolbox forwarder program ID.
   Retain a new MITM log beside the Toolbox, harness, and WireGuard logs.
   Confirm its startup log reports the Toolbox-only BSD:S interceptor before starting the run.

3. In the same Toolbox profile, set `bsd_destination_ipv4` to that same remote tunnel IPv4 address and keep `tcp_destination_port=28080`.
   Select `BSD system TCP exchange` and run it once with a new workload ID.

4. Require Toolbox to report `[OK] bsd_system_tcp_exchange` with a nonzero local endpoint, the exact `NXRV TCP <workload-id>\r\n` request, the exact `NXRV TCP ACK\r\n` reply, and clean close.
   Require the harness to record exactly one corresponding request and ACK.
   Require the MITM log to show Toolbox admission, a TCP `wgnx:tun` flow open, a successful tunneled TCP connect, and flow retirement on close.
   Reject the run if the MITM log shows a direct TCP connect or a TCP anchor attempt.
   Require the WireGuard log to show one TCP flow with the same remote tuple, virtual local tuple, ordered reply delivery, EOF, and release without an adapter, packet-plane, or completion rejection.

5. Stop or disable the MITM sysmodule, then repeat `Direct tunnel TCP exchange` once using a third workload ID.
   The post-MITM direct run must succeed with the same exact bytes and a new virtual local endpoint.
   This confirms that the MITM's retained BSD descriptor and flow cleanup did not contaminate a later direct client flow.

6. Archive the three grouped runs as `tcp_direct_baseline`, `tcp_bsd_mitm`, and `tcp_direct_after_mitm`.
   Mark the MITM acceptance complete only when all three have matching Toolbox, harness, and WireGuard accounting and the MITM run has the expected MITM lifecycle evidence.

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

## Task 7 BSD TCP MITM Continuation

The MITM continuation adds the smallest BSD:S TCP translation needed for the controlled Toolbox process to use the completed version 4 `wgnx:tun` TCP contract.
The MITM remains a BSD operation translator and never parses TCP, retransmits, maintains congestion state, or opens a native TCP anchor connection.
The WireGuard sysmodule remains the sole owner of TCP state, virtual local tuples, IPv4 packets, fragmentation, and transport recovery.

Only the build-configured Toolbox forwarder program ID is admitted to the BSD:S MITM.
All other program IDs, including Horizon system clients, continue to use the original BSD:S service.
The initial translated subset is `socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)`, `connect`, `getsockname`, `getpeername`, `send`, `recv`, `poll`, `shutdown(SHUT_WR)`, and `close`.
Unsupported stream options, mixed direct and virtual polling, non-IPv4 sockets, UDP `sendto` semantics, and non-Toolbox processes remain outside this slice.

### Implementation Checklist

- [x] **1. Make the build-time Toolbox allowlist explicit.**

  `mitm-sysmodule/local.mk.example` documents the ignored local override and target builds reject a missing `TOOLBOX_FORWARDER_PROGRAM_ID`.
  Horizon builds use `ams::ncm::ProgramId` for the configured Toolbox, WireGuard, and MITM identities, while host policy tests use a layout-compatible test-only value type.
  Requester-forwarder naming is now Toolbox-forwarder naming and host policy tests prove that only the configured ID is admitted while the WireGuard and MITM IDs remain excluded.

- [x] **2. Generalize the worker's API v4 boundary by flow kind.**

  The current UDP batching path remains unchanged.
  `TunnelFlowWorker` records UDP or TCP flow kind per fixed flow slot, tracks the advertised TCP capability separately, validates bounded `InboundTcpStream` records, and closes a flow on a completion flow-kind mismatch.
  The worker retains its four-flow, one-thread, fixed-buffer limits and closes every client and event handle on terminal results.

- [x] **3. Add the bounded TCP open and endpoint path.**

  TCP opens use `OpenConnectedTcpFlow`, the existing per-client completion event, and a six-second worker-side guard.
  A successful flow-state query supplies the nonzero virtual tuple returned by `getsockname`.
  The BSD descriptor remains unconnected and exists only for descriptor lifecycle and close.

- [x] **4. Translate Toolbox stream operations through `wgnx:tun`.**

  TCP writes are one bounded `WriteTcpStream` submission and retain the API's complete-or-`EAGAIN` admission contract.
  Stream records support ordered partial `recv` copies, remote orderly close returns BSD EOF, and `shutdown(SHUT_WR)` maps to `ShutdownTcpWrite`.
  `close` retires the private flow before the retained BSD descriptor is closed.

- [x] **5. Keep virtual socket metadata coherent.**

  TCP `getsockname` uses the advertised tuple and `getpeername` uses the original request destination.
  `recvfrom` is explicitly rejected for TCP and the UDP anchor behavior is unchanged.
  Virtual `bind`, post-connect `setsockopt`, and unsupported shutdown directions retain the existing explicit errno policy.

- [x] **6. Add deterministic host coverage and run the aggregate gate.**

  Host coverage checks Toolbox policy allowlisting, TCP completion bounds, partial ordered stream reads, EOF errno mapping, and named TCP transport state.
  `make -C mitm-sysmodule verify` passes with the configured Toolbox forwarder ID.

### Acceptance and Limits

The authoritative on-device routine is the back-to-back direct and BSD MITM TCP acceptance sequence above.
It requires the exact request and ACK through the peer, a nonzero virtual local endpoint, orderly EOF and close, matching Toolbox, harness, MITM, and WireGuard evidence, and no direct TCP connect or TCP anchor attempt in the MITM logs.
The general BSD TCP compatibility matrix, additional program IDs, nonblocking connect, and transparent OS-wide routing remain later work.

### Deferred UDP Anchor Cleanup

- [ ] Replace the UDP BSD:S connection anchor with the existing `wgnx:tun` virtual tuple.

  API v4 already exposes the WireGuard-allocated virtual UDP address and port through `GetFlowState`.
  The MITM should obtain that tuple after `OpenConnectedUdpFlow`, return it from `getsockname`, and stop forwarding the successful UDP `connect` to BSD:S solely to capture a physical-interface endpoint.
  This removes unrelated native BSD routing and descriptor state, makes UDP and TCP ownership symmetric, and leaves the WireGuard sysmodule as the sole owner of tunneled endpoint allocation.
  It changes visible UDP metadata from the physical BSD endpoint to the tunnel-owned virtual endpoint, so it requires the existing UDP device acceptance matrix plus endpoint-query regression coverage before adoption.
