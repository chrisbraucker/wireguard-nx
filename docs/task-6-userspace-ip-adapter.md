# Task 6 Userspace IP Adapter Implementation Guide

## Goal

Task 6 replaces the handmade IPv4 and UDP codec in the WireGuard sysmodule with a bounded lwIP adapter while retaining the MITM socket behavior, WireGuard protocol core, and complete-inner-packet boundary.
The private UDP flow IPC may change wherever the lwIP ownership model or current development goals require a cleaner contract.
Every incompatible command, layout, semantic, capability, or lifecycle change must increment `TunApiVersion` and update the WireGuard sysmodule, MITM sysmodule, requester, tests, and documentation together.
No backward-compatibility adapter is required while this remains an active-development private API.
The first completed slice remains IPv4 and UDP only, but gains mature checksum handling, UDP PCB ownership, effective-MTU application, outbound IPv4 fragmentation, inbound reassembly, and timeout-driven cleanup.
TCP, DNS, DHCP, netconn, lwIP sockets, IPv6, and additional application-facing APIs remain outside this task.

The production import should pin the current stable lwIP release rather than an unversioned development branch.
As of 2026-08-01, that release is lwIP 2.2.1 at tag `STABLE-2_2_1_RELEASE`, whose annotated tag resolves to commit `77dcd25a72509eb83f72b033d219b1d40cd8eb95`.
The local `workspace/repos/wg-nx` reference pins newer development commit `8e75a40acfea6b05ee643099e41f3b2e11ee464d`, so its Switch port and build choices are useful references but should not silently replace the stable production pin.

## Current Code Boundary

The existing code already has the correct external architecture, but `TunnelFlowPlane` currently combines tested flow state with the codec that Task 6 must replace.

| Current source                                                      | Responsibility to preserve                                                                                                    | Task 6 change                                                                                                                                                                                                        |
|---------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `common/include/wgnx/tunnel_protocol.hpp`                           | Current API version 3 records, statuses, capabilities, flow handles, batches, completions, and fixed storage maxima           | Change the contract when that produces a cleaner lwIP boundary, increment `TunApiVersion` for incompatible changes, and advertise the measured 1,472-byte datagram maximum independently of the active fragment MTU. |
| `wg-sysmodule/src/tunnel_service.cpp`                               | CMIF buffer validation and single or batched UDP commands                                                                     | Submit one adapter operation per CMIF batch and retain the current ordered per-descriptor dispositions.                                                                                                              |
| `wg-sysmodule/src/runtime/tunnel_flow_plane.*`                      | Clients, routes, virtual tuples, generations, tombstones, completion reservation, inbound slabs, counters, and writable state | Retain these owners, but remove IPv4 and UDP construction, parsing, checksums, packet identifiers, and outbound packet slabs once lwIP is authoritative.                                                             |
| `wg-sysmodule/src/runtime/daemon_runtime.cpp`                       | State-lock boundary and composition                                                                                           | Split flow operations into a locked validation or reservation phase, a post-lock adapter phase, and a generation-checked locked commit.                                                                              |
| `wg-sysmodule/src/runtime/runtime_effect_executor.*`                | Decrypted packet publication after peer authentication                                                                        | Copy authorized plaintext into bounded adapter work, then return before lwIP input, callbacks, or pbuf lifetime begins.                                                                                              |
| `wg-sysmodule/src/runtime/horizon_dispatcher.*`                     | Existing ordered `wgnx-submit` work lane                                                                                      | Add one adapter work item to this lane and do not create another thread.                                                                                                                                             |
| `wg-sysmodule/src/runtime/packet_data_plane.*` and `runtime/peer/*` | Complete inner-IP validation and bounded peer staging                                                                         | Add an all-or-none internal packet-batch admission needed to stage every fragment of one UDP datagram atomically.                                                                                                    |
| `wg-sysmodule/src/runtime/timer_scheduler.*`                        | Concrete timer expiry and ordered timer work                                                                                  | Use one auxiliary timer only to enqueue timeout work onto `wgnx-submit`, where `sys_check_timeouts()` remains serialized with every other lwIP call.                                                                 |
| `wg-sysmodule/src/wireguard/inner_packet.*`                         | Generic complete-IP validation and the experimental raw packet API                                                            | Keep this boundary independent of lwIP and do not expose lwIP types to the WireGuard protocol core.                                                                                                                  |

The required end-to-end ownership is:

```text
BSD MITM or direct flow client
        |
        v
private UDP flow IPC and project-owned flow state
        |
        v
serialized lwIP adapter on wgnx-submit
        |
        v
complete IPv4 packet batch
        |
        v
PacketDataPlane and peer-owned WireGuard staging
        |
        v
opaque WireGuard encryption and outer UDP transport
```

## Implementation Checklist

- [x] **1. Record the behavioral, resource, performance, and device baselines and choose the Task 6 API shape.**

  Run `make -C wg-sysmodule verify`, retain the current resource report, and preserve passing protocol, flow-plane, packet-plane, lifecycle, and Task 4 device results.
  Treat ordered batch dispositions, route selection, leak protection, stale handles, tuple quarantine, completion reservation, `QueueFull`, `Writable`, zero-checksum IPv4 UDP acceptance, and completion-drain atomicity as correctness baselines rather than API compatibility requirements.
  Review the version 3 commands and records against the concrete lwIP ownership flow before implementation and change them where doing so removes translation or ambiguous ownership.
  Increment `TunApiVersion` whenever an incompatible Task 6 contract change lands.
  Update every in-tree producer and consumer in the same cutover and do not retain compatibility branches for older private API versions.
  Preserve the MITM `EMSGSIZE` contract and record the direct-WGNX and full-MITM throughput and latency baselines from `docs/PERF.md`.
  Baseline verification on 2026-08-02 passes the 50-case host suite, warnings, ASan/UBSan, format, static analysis, clang-tidy, target build, stack checks, and footprint report.
  The target footprint is 1,300,874 static bytes, 251,859-byte NSO, and 252,919-byte NSP, all within the existing gate.
  The API remains at version 3 because lwIP can replace the codec without changing the private flow records or their semantics.

- [x] **2. Vendor the pinned minimal lwIP source set with reproducible provenance.**

  Import lwIP 2.2.1 under `wg-sysmodule/src/ip/third_party/lwip/` from tag `STABLE-2_2_1_RELEASE` at commit `77dcd25a72509eb83f72b033d219b1d40cd8eb95`.
  Preserve upstream `COPYING` and record the BSD-3-Clause license, retrieval URL and date, source archive and imported-file SHA-256 values, selected source list, and refresh procedure in a neighboring `UPSTREAM.md`.
  Retain the complete upstream `src/include/` tree and initially compile `def.c`, `init.c`, `inet_chksum.c`, `ip.c`, `mem.c`, `memp.c`, `netif.c`, `pbuf.c`, `timeouts.c`, `udp.c`, `ipv4/ip4.c`, `ipv4/ip4_addr.c`, and `ipv4/ip4_frag.c`.
  Compile `stats.c` only while `LWIP_STATS=1`, and omit `sys.c` because it provides no implementation in the selected `NO_SYS=1` configuration.
  Keep first-party configuration, platform hooks, wrappers, and tests outside the import, and exclude only vendored files from project style and static-analysis rules.
  The unmodified 2.2.1 import, archive digest, per-file manifest, selected source list, license, and refresh procedure now live in `wg-sysmodule/src/ip/third_party/lwip/`.

- [x] **3. Define the minimal `NO_SYS=1` configuration and explicit resource limits.**

  Add first-party `lwipopts.h`, `arch/cc.h`, and `sys_now()` adapters under `wg-sysmodule/src/ip/`, with an injectable host clock and Horizon monotonic-millisecond clock.
  Enable timers, IPv4, UDP, checksums, `IP_FRAG`, `IP_REASSEMBLY`, one netif, internal lwIP memory, and bounded statistics.
  Disable TCP, raw PCBs, ICMP, ARP, Ethernet framing, forwarding, IPv4 options, IGMP, DHCP, DNS, AutoIP, netconn, sockets, and IPv6.
  Set `IP_REASS_FREE_OLDEST=0` so pressure rejects new fragment work instead of silently evicting an older datagram.
  Put C-visible limits in one first-party budget header and expose the same constants to `wgnx/resource_budget.hpp` for compile-time checks.
  Begin measurements with at most 16 UDP PCBs, four concurrent reassemblies, eight retained reassembly pbufs, eight fragment-reference pbufs, a 24-entry 1,600-byte pbuf pool, and a 32 KiB heap, but treat every value as a prototype hypothesis rather than a final requirement.
  Require `PBUF_POOL_SIZE > 2 * IP_REASS_MAX_PBUFS` and accept a final value only after deterministic exhaustion tests and target footprint evidence.
  `lwipopts.h` now selects this narrow `NO_SYS=1` IPv4 and UDP configuration, while the C-visible budget header and `wgnx::resource_budget` share the initial limits.
  The vendored sources compile as C in both host and target builds, with `sys_now()` bound to an injectable host clock or Horizon's monotonic millisecond clock.

- [x] **4. Prove the isolated host adapter before composing it with daemon state.**

  Build a host-only adapter test around the production vendored source set, one netif, the real configuration, and a deterministic clock without platform sockets or WireGuard state.
  Prove one-time `lwip_init()`, deterministic adapter epoch reset, connected PCB creation and removal, unfragmented send and receive, fragmented send, in-order and out-of-order reassembly, expiry, and bounded allocation failure.
  Make the netif output callback collect complete IPv4 packets and the UDP callback collect copied datagrams so the prototype establishes ownership without introducing daemon callbacks.
  `UserspaceIpAdapter` now owns one netif, UDP PCBs, pbuf input and output, fragment reset, and copied result collectors without daemon callbacks.
  Its deterministic host test covers one-time initialization, connected PCB creation and removal, bounded PCB exhaustion, unfragmented output, three-fragment output, out-of-order reassembly, reset, expiry, and collector backpressure.

- [x] **5. Add one bounded serialized adapter owner on the existing submission lane.**

  Introduce `UserspaceIpAdapter` as the sole owner of lwIP initialization, the IPv4 netif, UDP PCBs, pbuf activity, fragment state, result collectors, counters, and operation slots.
  Do not expose `netif`, `udp_pcb`, `pbuf`, or lwIP error types outside this boundary.
  Extend `HorizonDispatcher` with one adapter work item on the existing ordered `wgnx-submit` lane and increase only that lane's bounded capacity when measurements require it.
  Do not add a thread or global lwIP mutex because ordered work execution is the single lwIP owner.
  Use owned generation-tagged operation slots and a reserved or coalesced lifecycle-control path so data pressure cannot suppress close or reset work.
  A CMIF command may wait for accepted adapter work only after releasing `DaemonRuntime::m_state_mutex`, and shutdown must complete every accepted waiter exactly once.
  Process one `SendUdpDatagramBatch` as one adapter operation while preserving the current admitted-prefix and queue-full-suffix ordering.
  Restrict lwIP callbacks to copying into adapter-owned collectors without calling daemon state, packet-plane, peer, logging, CMIF, or platform-I/O code.
  `UserspaceIpAdapterOwner` now owns the adapter and coalesces its configuration and reset controls until the dedicated `wgnx-submit` work item runs them.
  The owner is composed by `DaemonRuntime`, and shutdown queues its reset through that same work item.
  The explicit daemon-runtime ceiling is now 288 KiB to cover the measured bounded adapter owner instead of hiding this storage in an untracked allocation.
  The current target footprint is 1,401,026 static bytes, a 263,469-byte NSO, and a 264,529-byte NSP within the reviewed 1,572,864, 294,912, and 294,912-byte limits.
  The host test proves that configuration is not executed by the producer, repeated configuration coalesces to one owner execution, and reset leaves the one-time lwIP initialization intact.

- [x] **6. Integrate flow reservation, PCB lifetime, closure, and tuple quarantine.**

  Keep client and flow slots, flow handles, policy generations, route selection, virtual ports, tuple tombstones, counters, and completion storage in `TunnelFlowPlane`.
  Represent each PCB outside the adapter only with a stable token containing the flow slot and allocation generation.
  Open a flow by reserving and validating under the daemon mutex, creating and binding the PCB post-lock, then committing only if client, flow, peer activation, and policy identities remain current.
  Bind the PCB to the captured tunnel address and virtual source port, connect it to the requested remote endpoint, bind it to the one netif, and use the stable token as the receive callback argument.
  Map PCB exhaustion to `FlowQuotaExhausted`, preserve existing typed argument and route failures, and immediately remove a PCB whose reservation becomes stale before commit.
  Remove a closed flow's PCB with one post-lock operation and remove a destroyed client's PCBs with one bounded close batch.
  Preserve the 60-second reverse-tuple quarantine and prove it exceeds lwIP's default maximum fragment-reassembly lifetime so delayed fragments cannot target a replacement flow.
  Do not try to purge one flow through `ip_reass_tmr()` because it advances every global reassembly timer and cannot selectively remove a tuple.
  `TunnelFlowPlane` now reserves a pending flow with its handle as the stable adapter token, and keeps that token inaccessible until a post-lock PCB open succeeds and a locked identity recheck commits it.
  Failed or stale reservations are removed without exposing a handle or quarantining an unused tuple.
  Normal close and client destruction collect their committed tokens under the state lock and remove PCBs through one bounded adapter operation at a time after releasing it.
  The direct flow-plane regression proves pending reservations cannot expose their token, committed reservations do, and a policy-generation change rejects a stale reservation.

- [x] **7. Replace outbound UDP and IPv4 construction with lwIP at the effective inner MTU.**

  Allocate a `PBUF_TRANSPORT` payload for each accepted descriptor, copy the whole UDP datagram once, and call `udp_send()` on its connected PCB.
  Set the netif MTU from the active effective inner MTU and let lwIP own IPv4 and UDP headers, checksums, packet identifiers, and fragmentation.
  Make the netif output callback copy each emitted complete IPv4 packet into one bounded per-operation collector and return `ERR_BUF` before exceeding its packet or byte capacity.
  Do not submit from the callback because a later fragment failure would otherwise expose only part of one BSD datagram.
  Keep the first payload backing-store ceiling at 1,472 bytes, which requires no more than three IPv4 fragments at the supported 576-byte minimum MTU.
  Advertise the measured 1,472-byte maximum independently of the active fragment MTU and return `DatagramTooLarge` above it.
  `TunnelFlowPlane` now validates and reserves a send without constructing an IPv4 or UDP packet, and carries only the stable adapter token into the post-lock owner operation.
  The owner copies one payload into its bounded operation slot, calls `udp_send()` on the connected lwIP PCB, and exposes the complete netif output collector only after that call returns.
  `DaemonRuntime` converts that completed collector into the atomic packet batch before it executes WireGuard effects, so netif callbacks cannot publish partial fragments.
  The owner regression sends the 1,472-byte bounded payload at a 576-byte MTU and proves that lwIP produces exactly three collected IPv4 packets.
  The private API now advertises the measured 1,472-byte maximum, while lwIP applies the active effective inner MTU solely as its fragmentation threshold.

- [x] **8. Add atomic fragment-batch admission and preserve writable backpressure.**

  Add one all-or-none internal packet-batch admission that validates every collected packet and preflights free peer staging slots under the existing state lock.
  Reuse the current `InnerPacketStagedEvent` path for admitted fragments while producing no more than one outbound-processing effect for the batch.
  Admit no fragment when peer identity is stale or any fragment cannot fit, and map lwIP allocation, collector, operation-slot, or peer-staging pressure to the existing `QueueFull` disposition.
  Record the fragment-slot requirement of a rejected datagram and emit its coalesced `Writable` completion only when the peer queue can admit the entire retry atomically.
  Preserve current descriptor ordering and do not convert recoverable data pressure into a CMIF transport failure.
  `PacketDataPlane` now validates an internal batch before it is dispatched, and the peer runtime preflights its staging capacity before copying any fragment.
  The batch event stages every packet before it runs outbound processing once, so a later fragment cannot leave a partial datagram in the peer queue.
  The deterministic packet-plane regression fills staging to two free slots, proves that a three-packet batch leaves that queue unchanged, and then admits a two-packet batch.

- [x] **9. Fence decrypted-packet admission before any packet enters lwIP.**

  Preserve peer `AllowedIPs` source authorization before copying decrypted plaintext into bounded adapter work.
  Tag each input with peer identity, activation generation, policy generation, and adapter epoch while the daemon state is locked.
  Revalidate those identities immediately before `netif->input`, not only when publishing the result, so a stale queued fragment can never join new-generation reassembly state.
  Drop stale work with an explicit aggregate disposition and do not allocate a pbuf or mutate lwIP state for it.
  Allocate and populate the raw-input pbuf only on the serialized adapter owner, then transfer ownership according to lwIP's `netif->input` contract.
  `RuntimeEffectExecutor` now performs only AllowedIPs authorization and debug-probe handling before it copies a packet into the owner's one bounded input slot.
  The slot records peer identity, current flow-policy generation, and adapter epoch.
  The adapter worker revalidates all three under the daemon mutex directly before its post-lock `netif->input` call and explicitly drops stale input without allocating a pbuf.
  Item 10 consumes the copied lwIP UDP callback result after this fence.

- [x] **10. Replace inbound UDP parsing while preserving the existing consumer order.**

  Preserve the current decrypted receive order of `AllowedIPs` authorization, debug-probe handling, tunnel UDP delivery, and fallback to the generic `PacketDataPlane` consumer.
  Let lwIP retain valid IPv4 fragments until reassembly, and let a connected UDP PCB claim only a datagram matching its current local and remote tuple.
  In the UDP callback, copy chained payload data with `pbuf_copy_partial()` into the existing bounded inbound slab and record only the adapter token, remote endpoint, payload size, and a closed callback outcome.
  After lwIP returns and releases its pbufs, commit under the daemon mutex only after revalidating flow allocation, client generation, peer activation, policy generation, adapter epoch, tuple, per-flow quota, and completion reservation.
  Publish exactly one `InboundDatagram` completion for a valid reassembly and never retain a callback pointer or pbuf reference in project state.
  Pass complete valid packets that are not claimed as tunnel UDP, including unmatched UDP, to the existing raw packet consumer rather than dropping them or misrepresenting them as a flow delivery.
  Preserve zero-checksum IPv4 UDP acceptance and give invalid checksums, malformed lengths, unsupported options, invalid fragments, oversized payloads, unknown tuples, stale state, and completion pressure deterministic bounded dispositions.
  The lwIP UDP callback now copies only one bounded datagram collector record and reports explicit callback-copy or capacity rejection without entering daemon state.
  After `netif->input` returns, the daemon validates the callback token, current client and flow allocation, peer identity, policy generation, remote endpoint, inbound quota, and completion reservation before it publishes one completion.
  Unfragmented packets without a callback record remain on the existing generic raw-packet path, while callback rejection, stale flow state, unknown tokens, completion pressure, and a fragment still retained by lwIP are dropped with a bounded disposition.
  The existing raw packet boundary accepts complete packets only, so this UDP-only slice does not publish an unmatched fragment before reassembly and does not add a raw-PCB path for reassembled non-flow traffic.
  The production decrypted receive path no longer calls the handmade IPv4 or UDP parser, which remains temporarily for isolated host regression coverage until the Task 6 codec deletion.

- [x] **11. Integrate timeout scheduling, adapter epochs, and lifecycle resets.**

  Implement `sys_now()` with the same wrap-safe monotonic millisecond semantics on host and target and advance the host clock explicitly in tests.
  Use `sys_timeouts_sleeptime()` to arm one auxiliary Horizon timer whose callback only queues timeout work onto `wgnx-submit`.
  Run `sys_check_timeouts()` on the serialized owner and rearm from the next reported deadline without holding the daemon mutex or timer-manager lock.
  Close a flow by removing its PCB and retaining its tuple quarantine without globally advancing reassembly timers.
  Increment the adapter epoch and reset all PCB and fragment state on policy invalidation, peer restart, activation teardown, and sysmodule shutdown.
  Perform global fragment expiry or reset only at those adapter-epoch boundaries because upstream exposes no safe selective reassembly purge API.
  Record collateral fragment drops during an epoch reset instead of patching upstream reassembly internals.
  The adapter queries `sys_timeouts_sleeptime()` after every serialized operation, and the existing timer scheduler arms one auxiliary timer in the same monotonic-millisecond unit.
  Its timer callback only coalesces a `RunTimeouts` owner operation and queues the existing `wgnx-submit` work item, where `sys_check_timeouts()` runs without the daemon mutex.
  Peer deactivation queues the owner reset before the next activation can use the adapter, which increments the adapter epoch and clears every PCB, result collector, and retained reassembly state.
  Adapter reset does not rerun `sys_timeouts_init()`, because lwIP initializes its cyclic timeout list once in `lwip_init()` and repeated initialization exhausts the fixed timeout pool.
  The next accounting item records reset and retained-fragment dispositions without changing lwIP internals.

- [x] **12. Add bounded pressure, reassembly, callback, and lifecycle accounting.**

  Keep `LWIP_STATS=1` when its target cost is acceptable and report project-owned aggregate counters when an upstream counter does not express the required disposition.
  Cover pbuf and heap use, PCB use, operation slots, collector use, fragment transmit and receive, fragment drops, memory errors, reassembly success and failure, timeouts, resets, stale generations, callback delivery, peer staging, and completion pressure.
  Record current and high-water values plus the first explicit rejection reason so pressure can be reconciled across requester, MITM, flow plane, adapter, packet plane, peer, and WireGuard transport.
  Keep per-packet filesystem logging disabled and flush summaries outside the daemon state mutex at existing diagnostic boundaries.
  `UserspaceIpAdapter` now retains fixed current or high-water flow and callback occupancy plus cumulative input, pbuf, collector, reassembly, timeout, reset, and first-rejection counters.
  An adapter reset records whether it discarded retained fragment work and emits one lifecycle summary after the lwIP operation finishes, without packet-path filesystem logging.
  Existing flow, completion, peer-staging, dispatcher, and WireGuard counters remain their current owners and are reconciled with these adapter counters during device validation.

- [x] **13. Extend local regression, sanitizer, fuzz, static, stack, and resource gates.**

  Update protocol ABI tests to the selected Task 6 version and retain route, client, handle, tombstone, completion, writable, leak-protection, packet-plane, protocol, recovery, timer, and lifecycle tests against production code.
  Compare lwIP-emitted packets by endpoints, lengths, checksums, MTU, fragment offsets, more-fragments flags, reconstructed payload, and disposition rather than incidental packet identifiers.
  Add deterministic cases for MTUs 1,420, 1,280, and 576, two- and three-fragment output, in-order and out-of-order input, duplicates, overlaps, missing fragments, expiry, malformed packets, every bounded resource exhaustion, callback pressure, stale pre-input work, and atomic peer-queue rejection.
  Close a flow, change policy, restart the peer, and tear down activation with partial reassembly and queued input, then prove no delayed fragment reaches a replacement flow or new adapter epoch.
  Extend the existing inner-IPv4 fuzz target or add one adapter-input fuzz target that resets retained state between cases and executes the production wrapper.
  Run `test`, `test-sanitize`, `test-warnings`, supported `test-tsan`, `fuzz-run`, `format-check`, `static-check`, `tidy-check`, the target build, stack checks, and the resource report before device deployment.
  Vendor files may be excluded from style tools, but every first-party wrapper, ownership transition, budget, and disposition mapping remains in the aggregate gate.
  The 52-case host suite now covers owner timeout coalescing, tagged input, lwIP reassembly, zero UDP checksums, retained fragments, callback pressure, adapter accounting, and generation-checked callback delivery.
  `adapter_input_fuzz` executes the production adapter and its vendored lwIP source set with a fresh reset around every input.
  On 2026-08-02, warnings, ASan/UBSan, TSAN, static analysis, clang-tidy, formatting, a five-second run per fuzz target, target build, stack checks, and the footprint gate passed.
  The adapter fuzzer first exposed repeated timeout initialization and then completed a 1.88-million-input post-fix run without a fault.

- [x] **14. Cut over once, remove the handmade codec, and synchronize architecture documentation.**

  Delete `BuildUdpPacket`, `ParseIpv4Endpoint`, local internet and UDP checksum helpers, `m_next_ipv4_identification`, and obsolete outbound packet storage after every production send and receive uses lwIP.
  Do not retain a runtime switch or fallback to the handmade path because two authoritative packet implementations would duplicate correctness and test ownership.
  Re-run the local aggregate gate after deletion so no test or target-only path still depends on the removed codec.
  Update `docs/runtime-architecture.md`, `docs/runtime-resource-budgets.md`, `docs/packet-api.md`, `TASK_4_TODO.md`, and `HORIZON_INTEGRATION_PLAN.md` with the measured adapter ownership, capacities, lifecycle, fallback order, and diagnostics.
  `TunnelFlowPlane` now retains only project-owned flow, policy, tuple-quarantine, completion, and accounting state.
  The legacy inbound IPv4 parser, UDP checksum validation, checksum helpers, packet-identification state, and their test-only packet builders are removed.
  The host flow-plane test now reaches it only through the generation-tagged UDP callback contract, while the production lwIP adapter test remains authoritative for IPv4 validation, UDP checksum handling, fragmentation, and reassembly.
  The 52-case host suite, ASan/UBSan, warnings, formatting, static analysis, clang-tidy, and five-second fuzz sweep pass after this cutover.
  The target build, stack checks, and footprint gate also pass, with 1,387,986 static bytes, a 269,218-byte NSO, and a 270,278-byte NSP.
  Item 15 remains the complete on-device acceptance gate.

- [ ] **15. Run the complete on-device functional, lifecycle, fragmentation, pressure, latency, and throughput matrix.**

  Repeat the Task 4 direct-WGNX and full BSD MITM UDP scenarios with established unfragmented payloads, then with a 1,472-byte payload and effective MTUs that force two and three fragments.
  Exercise in-order and intentionally reordered fragments where the peer harness permits, missing-fragment expiry, queue pressure and writable recovery, terminal closure, policy change, peer restart, Wi-Fi path transition, clean module shutdown and restart, multiple flows, sustained throughput, and echo latency.
  Disable packet logging and reconcile requester, harness, MITM, flow-plane, adapter, pbuf, fragment, completion, peer-staging, and WireGuard counters.
  Archive the first explicit pressure disposition and investigate every unexplained loss, timeout, stale delivery, or counter mismatch.
  Task 6 is complete only when device runs preserve BSD datagram atomicity and Task 4 lifecycle behavior, all local gates pass, the handmade codec is absent, and the final resource report records the bounded lwIP cost.

### Condensed Regression Acceptance Matrix

This matrix validates the lwIP cutover against the working UDP path before the separate throughput and latency characterization.
It deliberately reuses the established requester, controlled echo harness, and Task 4 report helper.
It does not require a new performance ceiling or a new packet generator.

Before every run, deploy the matching `wg-sysmodule`, `mitm-sysmodule`, and toolbox build, with packet-granularity logging disabled and aggregate flow summaries enabled.
Start the harness with `python3 tools/requester_harness.py --udp-ports 29000 --udp-quiet` on the remote host.
Use a fresh workload ID and a separate report directory for every matrix row.
Use the tunnel-reachable harness IPv4 address for direct `wgnx:tun` and routed BSD MITM rows.
Keep `Echo replies=true`, one concurrent flow, a fixed payload seed, and a receive deadline that comfortably exceeds the observed Wi-Fi round-trip time.
Select `Tunnel` data path for a direct WGNX row with `tunnel_udp.enabled=true` and `bsd_system_udp.enabled=false`.
Select `bsd:s` data path for a routed MITM row with `tunnel_udp.enabled=false` and `bsd_system_udp.enabled=true`.
For every routed row, activate the peer, enable the MITM, and confirm that its policy covers the configured destination before starting the toolbox.

| ID  | Path and peer MTU                                            | Toolbox settings                                                                                               | Expected result                                                                                                                                                          |
|-----|--------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 150 | Direct WGNX, ordinary configured MTU                         | 1200 bytes, 32 datagrams, 5 ms pacing, echo                                                                    | 32 accepted and echoed datagrams with no timeout, duplicate, malformed, or unexpected harness record.                                                                    |
| 151 | BSD MITM to WGNX, ordinary configured MTU                    | 1200 bytes, 32 datagrams, 5 ms pacing, echo                                                                    | The same 32 round trips, a non-any WireGuard virtual `GetSockName` endpoint, and a matching MITM `connect tunneled transport=udp` record.                               |
| 152 | Direct WGNX, both peers at 1280-byte effective inner MTU     | 1472 bytes, 16 datagrams, 5 ms pacing, echo                                                                    | Every datagram completes after two-fragment outbound and inbound traversal.                                                                                              |
| 153 | BSD MITM to WGNX, both peers at 576-byte effective inner MTU | 1472 bytes, 8 datagrams, 10 ms pacing, echo                                                                    | Every datagram completes after three-fragment outbound and inbound traversal while BSD still reports one datagram per send and receive.                                  |
| 154 | BSD MITM to WGNX, ordinary configured MTU                    | Terminal-closure mode, 1200 bytes, one datagram, one flow, echo                                                | After one echo, deactivate the peer or shut down WGNX and observe `POLLHUP` plus post-closure `ECONNABORTED`, then restart the components and rerun ID 151 successfully. |
| 155 | BSD MITM to WGNX, ordinary configured MTU                    | The smallest previously known zero-pacing burst that triggers pressure, echo, `Require writable recovery=true` | At least one requester `EAGAIN`, a later `POLLOUT`, and successful retry of the same datagram without duplicate harness records.                                         |

For IDs 152 and 153, change both peer configurations to the stated effective inner MTU, reconnect the tunnel, and confirm a fresh handshake before launching the workload.
A 1472-byte UDP payload produces a 1500-byte IPv4 packet, which requires two fragments at 1280 bytes and three at 576 bytes.
Configuring only the Switch proves outbound fragmentation but cannot prove lwIP inbound reassembly, so both peers must use the reduced MTU for those rows.
Restore the ordinary peer MTU before IDs 154 and 155.
Run the terminal-closure action only after the requester reports that it is waiting for the expected closure.
If the current platform cannot reproduce pressure at the formerly observed burst, record the largest attempted burst and its clean accounting as inconclusive for ID 155 rather than calling writable recovery successful.

After each row, archive the requester, harness, MITM, and WGNX logs without appending another run to them.
After IDs 152 and 153, perform an orderly WGNX shutdown after collecting the flow summaries so the `lwip adapter reset summary` records nonzero reassembly activity and no unexpected input, callback, or pbuf rejection.
Run `python3 tools/summarize_reports.py --check <toolbox.log> <harness.log> <mitm.log> <wgnx.log>` from `nx-reversing.git` for every routed BSD MITM row.
Require exact requester, harness-unique, and harness-echoed counts, with zero duplicate, reordered, malformed, and unexpected records for every successful echo row.
Require the MITM local-admission invariants to pass, and do not equate requester-visible retries with later WGNX `QueueFull` events.
Treat any unexplained timeout, loss, stale completion, reassembly rejection, pbuf rejection, or accounting mismatch as a regression.
Record the requester average echo latency for IDs 150 through 153 as a comparison point only, not a pass or fail performance threshold.
Defer sustained throughput, large-volume transfer, path-transition, explicit missing or reordered fragment injection, and full latency characterization to the broader Item 15 campaign after this regression matrix passes.

## Scope Boundary After Completion

The resulting adapter is the common WireGuard-owned Layer 3 boundary for later transports, but Task 6 should not add speculative TCP abstractions.
Task 7 can add TCP PCBs, stream buffering, and stream-specific IPC only after this UDP replacement proves the adapter ownership, timeout, backpressure, and packet-plane contracts on device.
