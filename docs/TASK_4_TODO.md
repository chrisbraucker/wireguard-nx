# Task 4 Follow-Up TODO

This document records review findings and brief implementation notes discovered while Task 4 on-device acceptance and benchmarking are in progress.

The current Task 4 acceptance sequence and definition of done remain authoritative in `HORIZON_INTEGRATION_PLAN.md`.

Task 6 now owns tunnel-side IPv4 and UDP through lwIP.
Its remaining device acceptance is documented separately in `docs/task-6-userspace-ip-adapter.md` item 15.

## Current Acceptance Work

- [x] Complete every Task 4 on-device success and expected-error scenario.
- [x] Reconcile requester, remote-harness, MITM, and WireGuard counters for all four workload modes.
- [ ] Record throughput, latency, queue pressure, the first explicit saturation point, and its reported disposition.
- [x] Confirm lifecycle restart leaves a clean final full BSD MITM echo.
- [x] Preserve direct-WGNX and requester-only passive MITM tests as regression controls.

## 2026-08-01 On-Device Acceptance Record

The archived evidence is under `workspace/task_4_reports/`.

The four-mode comparison completed with 32 1200-byte datagrams in every mode.
Direct WGNX workload 100 and full BSD MITM workload 200 each used source `10.13.14.2`.
Native BSD workload 300 and passive MITM workload 400 each used source `192.168.203.27`.
The requester, harness, MITM, and WireGuard summaries agree on 32 accepted and echoed datagrams for the two tunneled modes, with no duplicates or reordering in the four-mode harness summary.

The no-reply timeout, post-route `SO_REUSEADDR` rejection, writable recovery, peer-deactivation terminal closure, and WGNX-service-loss terminal closure scenarios all reported their documented requester outcomes.
The terminal-closure rerun verified `POLLHUP`, post-closure `ECONNABORTED`, clean service invalidation after the expected drain CMIF failure, and a later fresh echo after WGNX restart.
The lifecycle regression completed a four-flow workload with eight echoed datagrams per flow, orderly requester and module shutdown, restart, and a final 32-datagram full BSD MITM echo without stale flow state, loss, duplication, or reordering.
No fatal-report artifact was archived with these evidence sets.

The writable-recovery behavior and its accounting boundary are reconciled.
For workload 802, the requester reports 508 queue-full retries while the MITM and WireGuard summaries each report 509 downstream queue-full events.
The extra downstream event is expected because MITM may first accept a BSD send into its local FIFO, then receive a later WGNX `QueueFull` while submitting that already accepted payload, retain it, and resubmit it after `Writable` without returning another BSD `EAGAIN`.
Per-flow MITM summaries now expose `adapter_queued`, `adapter_queue_full`, and `too_large` alongside downstream acceptance, queue-full, pending, and discarded counters.
The independent local-admission invariants are `sends = adapter_queued + adapter_queue_full + too_large` and `adapter_queued = accepted + discarded + queued`.
WireGuard `send_queue_full` remains a downstream pressure-event counter, rather than a requester-visible rejection partition, so it must not be forced to equal requester retry count.
`nx-reversing.git/tools/summarize_reports.py --check` validates the available per-flow invariants for newly captured summaries.
Keep the performance and feasibility gate open for throughput, latency, and the first measured saturation point.

Implementation note: the requester now emits aggregate local submission intervals, echoed bytes, queue-pressure counters, and bounded echo RTT histogram summaries.
The controlled harness emits matching per-flow and per-workload local receive intervals with byte, unique, duplicate, reorder, and source accounting.
The report helper renders requester submission rate and harness receiver goodput as separate local-clock values.
This instrumentation supports the remaining performance measurement without claiming a cross-host one-way timing value.

Implementation note: requester Settings now initializes and resets the expected BSD:S outcome selector from the loaded enum value instead of always displaying the normal-workload choice.
This makes every stored requester setting visible at first display, including a persisted no-reply or terminal-closure mode.

## Correctness Before lwIP

### AllowedIPs authorization

- [x] Validate the source address of every authenticated decrypted inner packet against the peer's AllowedIPs before publishing it to any consumer.
- [x] Apply destination AllowedIPs selection to ordinary outbound raw packets, or document the diagnostic raw-packet API as an explicit privileged bypass.

Implementation note: place the inbound check once after authenticated decryption and before the debug probe, tunnel flow plane, or packet channel can observe the packet.

Implementation note: follow the wireguard-go receive contract, which drops an authenticated packet when the source lookup does not resolve to the authenticating peer.

### Policy generation

- [x] Fix `TunnelFlowPlane::RefreshPolicy` so each refresh advances `m_policy_generation` instead of assigning the old allocated value back over the increment.
- [x] Add a deterministic test that refreshes policy more than once and asserts that the generation changes.

Implementation note: keep allocation state separate from the published generation so stale-policy detection cannot silently collapse to one permanent value.

### UDP receive truncation

- [x] Make a short BSD receive buffer copy the fitting prefix, consume the whole queued datagram, and discard the remainder.
- [x] Add focused coverage proving that the truncated datagram cannot wedge every later receive.
- [ ] Define `MSG_TRUNC` behavior separately if nonzero receive flags are added later.

Implementation note: zero-flags UDP receive must preserve datagram atomicity even before broader flag support exists.

### Completion response validation

- [x] Reject a returned completion count larger than the local completion array.
- [x] Validate payload offset arithmetic and the aggregate IPC payload range without integer overflow.
- [x] Reject a completion payload larger than one `InboundDatagram::payload` before allocating or copying it.
- [x] Add malformed-response tests for count, offset, range, and per-datagram capacity failures.

Implementation note: treat the private service boundary as untrusted even though both processes are maintained in this repository.

### WireGuard key freshness

- [x] Run the peer-owned key-freshness decision after every authenticated transport send, including keepalives.
- [x] Run the same decision after every accepted authenticated transport receive.
- [x] Preserve wireguard-go's deduplication behavior so last-minute traffic cannot create repeated handshake attempts.

Implementation note: use one shared peer policy decision rather than adding checks independently to individual callers.

## Additional Protocol Corrections

### Flow diagnostics

- [x] Populate `GetFlowState.advertised_local` from the tunnel source address and virtual source port.
- [x] Add a host assertion for the advertised local endpoint.

Implementation note: remove the field only through a deliberate private API revision if it is no longer part of the diagnostic contract.

### IPv4 UDP checksum semantics

- [x] Accept a zero inbound UDP checksum for IPv4.
- [x] Continue generating and validating nonzero outbound UDP checksums.
- [x] Add one accepted-zero and one rejected-invalid-nonzero checksum case.

### WireGuard padding and MTU

- [x] Cap transport padding at the active effective inner MTU as wireguard-go does.
- [x] Cover 1419-byte, 1420-byte, and configured-MTU boundaries.
- [ ] Include an outer-IPv6 case in the eventual device MTU matrix.

Implementation note: pass the effective MTU to the common padding calculation instead of applying per-caller corrections.

### Poll error reporting

- [x] Propagate `TunnelPollResult.result` through `BsdMitmService::Poll` instead of reporting every worker failure as a successful empty poll.
- [x] Map queue rejection and transport failure to a documented BSD errno or terminal poll event.
- [x] Add focused tests distinguishing timeout, readiness, and worker failure.

Implementation note: timeout returns `0` with errno zero, readiness returns the ready count with errno zero, terminal closure returns `POLLHUP`, worker ingress or pending-poll capacity returns `-1/EAGAIN`, and worker or CMIF failure returns `-1/EIO`.
Synthetic BSD:S errno values use named Linux-numbered CMIF wire values, so libnx converts them to the requester's newlib errno values correctly.

Implementation note: the first terminal-closure device run exposed the ABI mismatch as requester `EHOSTUNREACH` instead of `ECONNABORTED`.
The corrected Linux-numbered CMIF values passed both peer-deactivation and WGNX-service-shutdown terminal-closure reruns.

Implementation note: V1 intentionally does not expose `POLLERR` because it has no defined per-flow asynchronous error state.

### Cookie and rate-limit parity

- [x] Generate responder cookies, require MAC2 while under load, send cookie replies to the received endpoint, and rate-limit valid cookie-authenticated handshakes.

Implementation note: cookie construction, MAC1 and MAC2 validation, 120-second secret rotation, and the per-source `20/s` burst-`5` limiter follow wireguard-go.

Implementation note: the current serialized receive runtime enters the upstream one-second sticky under-load state after a global valid-MAC1 arrival bucket exceeds the same `20/s` burst-`5` threshold.

Implementation note: this is a target-specific substitute for wireguard-go's handshake-queue-depth trigger and remains isolated behind responder admission until a measured handshake queue is warranted.

## Verification and Test Coverage

- [x] Fix the three redundant moves reported by clang-tidy in `wg-sysmodule/test/host/scripted_platform.cpp`.
- [x] Fix the three `size_t` to signed time-type narrowing conversions reported in `wg-sysmodule/test/host/tunnel_flow_plane_tests.cpp`.
- [x] Include `tidy-check` in the intended aggregate verification gate, or document clearly why it remains separate.
- [x] Add host coverage for MITM completion validation, receive truncation, errno translation, and route-state transitions.

Implementation note: the WireGuard normal, ASan/UBSan, warning, and tidy suites passed 50 deterministic cases during this review.

Implementation note: `mitm-sysmodule` and `manager` now run `tidy-check` from `verify` because they pass it cleanly.

Implementation note: `wg-sysmodule` now runs `tidy-check` from `verify`, while `overlay` remains separate because clang-tidy cannot parse its unmodified Tesla and Ultrahand dependency headers.

Implementation note: completion validation, datagram truncation, readiness, submission state, errno translation, and route transitions are now shared production helpers with deterministic host coverage.

Implementation note: the host suite still does not instantiate Horizon CMIF objects or worker threads, which remain target integration concerns covered by the Task 4 device matrix.

## Leanups

- [ ] Remove the tunnel worker's dedicated stop event if the existing wake event and stop flag fully cover stop interruption.
- [ ] Remove `BsdSocketRouteState::Closed` because the state is assigned immediately before the socket record is reset.
- [ ] Remove `visible_local_valid` if the tunneled-state transition continues to guarantee that the visible local endpoint is valid.
- [ ] Confirm CMIF object serialization before removing the apparently unobservable `OpeningTunnel` state.
- [ ] Remove unused `FlowState::Suspended` and `FlowState::Closing` values in the next private API revision unless a near-term producer is identified.
- [ ] Give the root capability command and child capability command one consistent name and meaning in the next private API revision.

Implementation note: do not split the two large MITM translation files merely because of their size.

Implementation note: preserve `PeerRuntime`, iterative completion draining, the effect executor, and timer ownership because their separation enforces demonstrated stack and lock-safety requirements.

Implementation note: the immediately removable complexity is small at roughly 25 lines with no dependency reduction.

## UDP Fragmentation and lwIP Ownership

The selected design keeps the userspace IP stack in the WireGuard sysmodule behind a boundary that remains separate from the WireGuard cryptographic protocol core.

The MITM owns BSD socket and whole-datagram semantics while the WireGuard IP adapter owns Layer 3 construction, validation, fragmentation, reassembly, and transport demultiplexing.

- [x] Assign the userspace IP stack and Layer 3 ownership to the WireGuard sysmodule.
- [x] Record the selected ownership model in `HORIZON_INTEGRATION_PLAN.md`, `HORIZON_INTEGRATION_SPEC.md`, and workspace guidance.
- [x] Do not retain both the current manual UDP/IP implementation and an lwIP implementation after the migration is complete.

The intended minimal boundary is:

```text
BSD MITM
  owns socket semantics and one whole UDP datagram
        |
        v
private flow IPC
  owns handles, generations, ordering, and bounded transfer
        |
        v
serialized IP adapter backed by lwIP
  owns UDP PCB state, IPv4 construction, fragmentation, and reassembly
        |
        v
WireGuard packet boundary
  owns authenticated opaque inner-IP packet transport
```

## Host-Only lwIP Fit Prototype

- [x] Initialize the pinned stable lwIP source set and record its provenance.
- [x] Record the revision, BSD license, integrity hash, and refresh procedure beside the import.
- [x] Build and test the host-only NO_SYS adapter before target deployment.
- [x] Compile only the IPv4, pbuf, timeout, netif, UDP, checksum, fragmentation, and reassembly pieces required for the UDP path.
- [x] Exclude TCP, DNS, DHCP, netconn, sockets, and application-facing lwIP APIs from this slice.
- [x] Replace the manual UDP packet builder, IPv4 and UDP parser, and checksum helpers behind the existing flow API.

Implementation note: use `wg-nx` for its minimal Switch build and NO_SYS configuration ideas.

Implementation note: use `netbird-switch` for PCB lifetime, one-time initialization, static-pool, shutdown-ordering, and do-not-block-under-lock lessons.

Implementation note: do not copy their hardcoded MTU, global mutable ownership, relay architecture, or application-local socket contract.

## lwIP Runtime Ownership

- [x] Serialize every lwIP call through one existing post-lock work owner.
- [x] Do not call lwIP, run callbacks, allocate pbufs, or process lwIP timeouts while holding the daemon state mutex.
- [x] Avoid a new thread and global lwIP mutex by using the existing serialized work boundary.
- [x] Keep flow handles, policy generations, tuple quarantine, queue ordering, and completion slabs project-owned.
- [x] Invalidate fragment and PCB state across flow close, policy refresh, peer restart, and activation teardown.

## Fragmentation Acceptance Cases

- [x] Fragment outbound IPv4 UDP datagrams at the effective inner MTU with valid IP and UDP checksums.
- [x] Reassemble valid inbound fragments into exactly one UDP datagram.
- [x] Cover out-of-order, duplicate, overlapping, missing, expired, malformed, and resource-exhausted fragments in host tests and fuzzing.
- [x] Produce either one delivery or one bounded observable drop for every reassembly attempt.
- [x] Verify stale reassembly cannot cross flow closure, policy-generation change, peer restart, or activation teardown.
- [x] Measure pbuf, fragment, timer, stack, completion, and total memory bounds under host exhaustion.
- [x] Add sanitizer coverage and fuzz the inner IPv4 input boundary.
- [ ] Repeat target throughput, latency, path-transition, and lifecycle benchmarks after replacement of the manual adapter.

## Datagram Size Contract

- [ ] Measure a bounded first-release UDP datagram maximum from the target memory and IPC budgets.
- [ ] Return `EMSGSIZE` above that explicit maximum until larger transfer storage is justified.
- [ ] Preserve BSD UDP send atomicity for every size claimed as supported.
- [ ] Avoid expanding every FIFO slot to the 65,507-byte IPv4 UDP maximum without measured need.

Implementation note: the first fragmentation milestone need not promise the full theoretical IPv4 UDP datagram size.

## Recommended Order

1. Complete and reconcile the current Task 4 device acceptance work.
2. Fix the high-priority correctness findings and verification-gate discrepancy.
3. Add focused host coverage for the MITM production semantics.
4. Preserve the documented WireGuard-owned Layer 3 boundary during implementation.
5. Run the minimal host-only lwIP UDP fragmentation and reassembly prototype.
6. Replace the manual UDP/IP adapter behind the existing flow contract.
7. Repeat host, target, resource, and path-transition validation.
8. Consider TCP only after the UDP adapter is stable and its bounds are demonstrated.

Implementation note: Task 6 item 14 removed the legacy flow-plane IPv4 and UDP codec, so lwIP is now the only tunnel-side IP and UDP implementation.
The remaining Task 6 device work is the focused fragmentation, pressure, lifecycle, latency, and throughput matrix in item 15.
