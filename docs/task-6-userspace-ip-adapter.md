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

| Current source | Responsibility to preserve | Task 6 change |
| --- | --- | --- |
| `common/include/wgnx/tunnel_protocol.hpp` | Current API version 3 records, statuses, capabilities, flow handles, batches, completions, and fixed storage maxima | Change the contract when that produces a cleaner lwIP boundary, increment `TunApiVersion` for incompatible changes, and advertise a larger measured datagram maximum only after the fragment path passes its gates. |
| `wg-sysmodule/src/tunnel_service.cpp` | CMIF buffer validation and single or batched UDP commands | Submit one adapter operation per CMIF batch and retain the current ordered per-descriptor dispositions. |
| `wg-sysmodule/src/runtime/tunnel_flow_plane.*` | Clients, routes, virtual tuples, generations, tombstones, completion reservation, inbound slabs, counters, and writable state | Retain these owners, but remove IPv4 and UDP construction, parsing, checksums, packet identifiers, and outbound packet slabs once lwIP is authoritative. |
| `wg-sysmodule/src/runtime/daemon_runtime.cpp` | State-lock boundary and composition | Split flow operations into a locked validation or reservation phase, a post-lock adapter phase, and a generation-checked locked commit. |
| `wg-sysmodule/src/runtime/runtime_effect_executor.*` | Decrypted packet publication after peer authentication | Copy authorized plaintext into bounded adapter work, then return before lwIP input, callbacks, or pbuf lifetime begins. |
| `wg-sysmodule/src/runtime/horizon_dispatcher.*` | Existing ordered `wgnx-submit` work lane | Add one adapter work item to this lane and do not create another thread. |
| `wg-sysmodule/src/runtime/packet_data_plane.*` and `runtime/peer/*` | Complete inner-IP validation and bounded peer staging | Add an all-or-none internal packet-batch admission needed to stage every fragment of one UDP datagram atomically. |
| `wg-sysmodule/src/runtime/timer_scheduler.*` | Concrete timer expiry and ordered timer work | Use one auxiliary timer only to enqueue timeout work onto `wgnx-submit`, where `sys_check_timeouts()` remains serialized with every other lwIP call. |
| `wg-sysmodule/src/wireguard/inner_packet.*` | Generic complete-IP validation and the experimental raw packet API | Keep this boundary independent of lwIP and do not expose lwIP types to the WireGuard protocol core. |

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

- [ ] **2. Vendor the pinned minimal lwIP source set with reproducible provenance.**

  Import lwIP 2.2.1 under `wg-sysmodule/src/ip/third_party/lwip/` from tag `STABLE-2_2_1_RELEASE` at commit `77dcd25a72509eb83f72b033d219b1d40cd8eb95`.
  Preserve upstream `COPYING` and record the BSD-3-Clause license, retrieval URL and date, source archive and imported-file SHA-256 values, selected source list, and refresh procedure in a neighboring `UPSTREAM.md`.
  Retain the complete upstream `src/include/` tree and initially compile `def.c`, `init.c`, `inet_chksum.c`, `ip.c`, `mem.c`, `memp.c`, `netif.c`, `pbuf.c`, `timeouts.c`, `udp.c`, `ipv4/ip4.c`, `ipv4/ip4_addr.c`, and `ipv4/ip4_frag.c`.
  Compile `stats.c` only while `LWIP_STATS=1`, and omit `sys.c` because it provides no implementation in the selected `NO_SYS=1` configuration.
  Keep first-party configuration, platform hooks, wrappers, and tests outside the import, and exclude only vendored files from project style and static-analysis rules.

- [ ] **3. Define the minimal `NO_SYS=1` configuration and explicit resource limits.**

  Add first-party `lwipopts.h`, `arch/cc.h`, and `sys_now()` adapters under `wg-sysmodule/src/ip/`, with an injectable host clock and Horizon monotonic-millisecond clock.
  Enable timers, IPv4, UDP, checksums, `IP_FRAG`, `IP_REASSEMBLY`, one netif, internal lwIP memory, and bounded statistics.
  Disable TCP, raw PCBs, ICMP, ARP, Ethernet framing, forwarding, IPv4 options, IGMP, DHCP, DNS, AutoIP, netconn, sockets, and IPv6.
  Set `IP_REASS_FREE_OLDEST=0` so pressure rejects new fragment work instead of silently evicting an older datagram.
  Put C-visible limits in one first-party budget header and expose the same constants to `wgnx/resource_budget.hpp` for compile-time checks.
  Begin measurements with at most 16 UDP PCBs, four concurrent reassemblies, eight retained reassembly pbufs, eight fragment-reference pbufs, a 24-entry 1,600-byte pbuf pool, and a 32 KiB heap, but treat every value as a prototype hypothesis rather than a final requirement.
  Require `PBUF_POOL_SIZE > 2 * IP_REASS_MAX_PBUFS` and accept a final value only after deterministic exhaustion tests and target footprint evidence.

- [ ] **4. Prove the isolated host adapter before composing it with daemon state.**

  Build a host-only adapter test around the production vendored source set, one netif, the real configuration, and a deterministic clock without platform sockets or WireGuard state.
  Prove one-time `lwip_init()`, deterministic adapter epoch reset, connected PCB creation and removal, unfragmented send and receive, fragmented send, in-order and out-of-order reassembly, expiry, and bounded allocation failure.
  Make the netif output callback collect complete IPv4 packets and the UDP callback collect copied datagrams so the prototype establishes ownership without introducing daemon callbacks.

- [ ] **5. Add one bounded serialized adapter owner on the existing submission lane.**

  Introduce `UserspaceIpAdapter` as the sole owner of lwIP initialization, the IPv4 netif, UDP PCBs, pbuf activity, fragment state, result collectors, counters, and operation slots.
  Do not expose `netif`, `udp_pcb`, `pbuf`, or lwIP error types outside this boundary.
  Extend `HorizonDispatcher` with one adapter work item on the existing ordered `wgnx-submit` lane and increase only that lane's bounded capacity when measurements require it.
  Do not add a thread or global lwIP mutex because ordered work execution is the single lwIP owner.
  Use owned generation-tagged operation slots and a reserved or coalesced lifecycle-control path so data pressure cannot suppress close or reset work.
  A CMIF command may wait for accepted adapter work only after releasing `DaemonRuntime::m_state_mutex`, and shutdown must complete every accepted waiter exactly once.
  Process one `SendUdpDatagramBatch` as one adapter operation while preserving the current admitted-prefix and queue-full-suffix ordering.
  Restrict lwIP callbacks to copying into adapter-owned collectors without calling daemon state, packet-plane, peer, logging, CMIF, or platform-I/O code.

- [ ] **6. Integrate flow reservation, PCB lifetime, closure, and tuple quarantine.**

  Keep client and flow slots, flow handles, policy generations, route selection, virtual ports, tuple tombstones, counters, and completion storage in `TunnelFlowPlane`.
  Represent each PCB outside the adapter only with a stable token containing the flow slot and allocation generation.
  Open a flow by reserving and validating under the daemon mutex, creating and binding the PCB post-lock, then committing only if client, flow, peer activation, and policy identities remain current.
  Bind the PCB to the captured tunnel address and virtual source port, connect it to the requested remote endpoint, bind it to the one netif, and use the stable token as the receive callback argument.
  Map PCB exhaustion to `FlowQuotaExhausted`, preserve existing typed argument and route failures, and immediately remove a PCB whose reservation becomes stale before commit.
  Remove a closed flow's PCB with one post-lock operation and remove a destroyed client's PCBs with one bounded close batch.
  Preserve the 60-second reverse-tuple quarantine and prove it exceeds lwIP's default maximum fragment-reassembly lifetime so delayed fragments cannot target a replacement flow.
  Do not try to purge one flow through `ip_reass_tmr()` because it advances every global reassembly timer and cannot selectively remove a tuple.

- [ ] **7. Replace outbound UDP and IPv4 construction with lwIP at the effective inner MTU.**

  Allocate a `PBUF_TRANSPORT` payload for each accepted descriptor, copy the whole UDP datagram once, and call `udp_send()` on its connected PCB.
  Set the netif MTU from the active effective inner MTU and let lwIP own IPv4 and UDP headers, checksums, packet identifiers, and fragmentation.
  Make the netif output callback copy each emitted complete IPv4 packet into one bounded per-operation collector and return `ERR_BUF` before exceeding its packet or byte capacity.
  Do not submit from the callback because a later fragment failure would otherwise expose only part of one BSD datagram.
  Keep the first payload backing-store ceiling at 1,472 bytes, which requires no more than three IPv4 fragments at the supported 576-byte minimum MTU.
  Keep advertising the current MTU-limited maximum until fragmentation passes every gate, then advertise the measured 1,472-byte maximum and return `DatagramTooLarge` above it.

- [ ] **8. Add atomic fragment-batch admission and preserve writable backpressure.**

  Add one all-or-none internal packet-batch admission that validates every collected packet and preflights free peer staging slots under the existing state lock.
  Reuse the current `InnerPacketStagedEvent` path for admitted fragments while producing no more than one outbound-processing effect for the batch.
  Admit no fragment when peer identity is stale or any fragment cannot fit, and map lwIP allocation, collector, operation-slot, or peer-staging pressure to the existing `QueueFull` disposition.
  Record the fragment-slot requirement of a rejected datagram and emit its coalesced `Writable` completion only when the peer queue can admit the entire retry atomically.
  Preserve current descriptor ordering and do not convert recoverable data pressure into a CMIF transport failure.

- [ ] **9. Fence decrypted-packet admission before any packet enters lwIP.**

  Preserve peer `AllowedIPs` source authorization before copying decrypted plaintext into bounded adapter work.
  Tag each input with peer identity, activation generation, policy generation, and adapter epoch while the daemon state is locked.
  Revalidate those identities immediately before `netif->input`, not only when publishing the result, so a stale queued fragment can never join new-generation reassembly state.
  Drop stale work with an explicit aggregate disposition and do not allocate a pbuf or mutate lwIP state for it.
  Allocate and populate the raw-input pbuf only on the serialized adapter owner, then transfer ownership according to lwIP's `netif->input` contract.

- [ ] **10. Replace inbound UDP parsing while preserving the existing consumer order.**

  Preserve the current decrypted receive order of `AllowedIPs` authorization, debug-probe handling, tunnel UDP delivery, and fallback to the generic `PacketDataPlane` consumer.
  Let lwIP retain valid IPv4 fragments until reassembly, and let a connected UDP PCB claim only a datagram matching its current local and remote tuple.
  In the UDP callback, copy chained payload data with `pbuf_copy_partial()` into the existing bounded inbound slab and record only the adapter token, remote endpoint, payload size, and a closed callback outcome.
  After lwIP returns and releases its pbufs, commit under the daemon mutex only after revalidating flow allocation, client generation, peer activation, policy generation, adapter epoch, tuple, per-flow quota, and completion reservation.
  Publish exactly one `InboundDatagram` completion for a valid reassembly and never retain a callback pointer or pbuf reference in project state.
  Pass complete valid packets that are not claimed as tunnel UDP, including unmatched UDP, to the existing raw packet consumer rather than dropping them or misrepresenting them as a flow delivery.
  Preserve zero-checksum IPv4 UDP acceptance and give invalid checksums, malformed lengths, unsupported options, invalid fragments, oversized payloads, unknown tuples, stale state, and completion pressure deterministic bounded dispositions.

- [ ] **11. Integrate timeout scheduling, adapter epochs, and lifecycle resets.**

  Implement `sys_now()` with the same wrap-safe monotonic millisecond semantics on host and target and advance the host clock explicitly in tests.
  Use `sys_timeouts_sleeptime()` to arm one auxiliary Horizon timer whose callback only queues timeout work onto `wgnx-submit`.
  Run `sys_check_timeouts()` on the serialized owner and rearm from the next reported deadline without holding the daemon mutex or timer-manager lock.
  Close a flow by removing its PCB and retaining its tuple quarantine without globally advancing reassembly timers.
  Increment the adapter epoch and reset all PCB and fragment state on policy invalidation, peer restart, activation teardown, and sysmodule shutdown.
  Perform global fragment expiry or reset only at those adapter-epoch boundaries because upstream exposes no safe selective reassembly purge API.
  Record collateral fragment drops during an epoch reset instead of patching upstream reassembly internals.

- [ ] **12. Add bounded pressure, reassembly, callback, and lifecycle accounting.**

  Keep `LWIP_STATS=1` when its target cost is acceptable and report project-owned aggregate counters when an upstream counter does not express the required disposition.
  Cover pbuf and heap use, PCB use, operation slots, collector use, fragment transmit and receive, fragment drops, memory errors, reassembly success and failure, timeouts, resets, stale generations, callback delivery, peer staging, and completion pressure.
  Record current and high-water values plus the first explicit rejection reason so pressure can be reconciled across requester, MITM, flow plane, adapter, packet plane, peer, and WireGuard transport.
  Keep per-packet filesystem logging disabled and flush summaries outside the daemon state mutex at existing diagnostic boundaries.

- [ ] **13. Extend local regression, sanitizer, fuzz, static, stack, and resource gates.**

  Update protocol ABI tests to the selected Task 6 version and retain route, client, handle, tombstone, completion, writable, leak-protection, packet-plane, protocol, recovery, timer, and lifecycle tests against production code.
  Compare lwIP-emitted packets by endpoints, lengths, checksums, MTU, fragment offsets, more-fragments flags, reconstructed payload, and disposition rather than incidental packet identifiers.
  Add deterministic cases for MTUs 1,420, 1,280, and 576, two- and three-fragment output, in-order and out-of-order input, duplicates, overlaps, missing fragments, expiry, malformed packets, every bounded resource exhaustion, callback pressure, stale pre-input work, and atomic peer-queue rejection.
  Close a flow, change policy, restart the peer, and tear down activation with partial reassembly and queued input, then prove no delayed fragment reaches a replacement flow or new adapter epoch.
  Extend the existing inner-IPv4 fuzz target or add one adapter-input fuzz target that resets retained state between cases and executes the production wrapper.
  Run `test`, `test-sanitize`, `test-warnings`, supported `test-tsan`, `fuzz-run`, `format-check`, `static-check`, `tidy-check`, the target build, stack checks, and the resource report before device deployment.
  Vendor files may be excluded from style tools, but every first-party wrapper, ownership transition, budget, and disposition mapping remains in the aggregate gate.

- [ ] **14. Cut over once, remove the handmade codec, and synchronize architecture documentation.**

  Delete `BuildUdpPacket`, `ParseIpv4Endpoint`, local internet and UDP checksum helpers, `m_next_ipv4_identification`, and obsolete outbound packet storage after every production send and receive uses lwIP.
  Do not retain a runtime switch or fallback to the handmade path because two authoritative packet implementations would duplicate correctness and test ownership.
  Re-run the local aggregate gate after deletion so no test or target-only path still depends on the removed codec.
  Update `docs/runtime-architecture.md`, `docs/runtime-resource-budgets.md`, `docs/packet-api.md`, `TASK_4_TODO.md`, and `HORIZON_INTEGRATION_PLAN.md` with the measured adapter ownership, capacities, lifecycle, fallback order, and diagnostics.

- [ ] **15. Run the complete on-device functional, lifecycle, fragmentation, pressure, latency, and throughput matrix.**

  Repeat the Task 4 direct-WGNX and full BSD MITM UDP scenarios with established unfragmented payloads, then with a 1,472-byte payload and effective MTUs that force two and three fragments.
  Exercise in-order and intentionally reordered fragments where the peer harness permits, missing-fragment expiry, queue pressure and writable recovery, terminal closure, policy change, peer restart, Wi-Fi path transition, clean module shutdown and restart, multiple flows, sustained throughput, and echo latency.
  Disable packet logging and reconcile requester, harness, MITM, flow-plane, adapter, pbuf, fragment, completion, peer-staging, and WireGuard counters.
  Archive the first explicit pressure disposition and investigate every unexplained loss, timeout, stale delivery, or counter mismatch.
  Task 6 is complete only when device runs preserve BSD datagram atomicity and Task 4 lifecycle behavior, all local gates pass, the handmade codec is absent, and the final resource report records the bounded lwIP cost.

## Scope Boundary After Completion

The resulting adapter is the common WireGuard-owned Layer 3 boundary for later transports, but Task 6 should not add speculative TCP abstractions.
Task 7 can add TCP PCBs, stream buffering, and stream-specific IPC only after this UDP replacement proves the adapter ownership, timeout, backpressure, and packet-plane contracts on device.
