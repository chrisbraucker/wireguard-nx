# Task 4 Follow-Up TODO

This document records review findings and brief implementation notes discovered while Task 4 on-device acceptance and benchmarking are in progress.

The current Task 4 acceptance sequence and definition of done remain authoritative in `HORIZON_INTEGRATION_PLAN.md`.

Do not begin target-side lwIP integration until the high-priority correctness items below are resolved and covered by deterministic host tests.

## Current Acceptance Work

- [ ] Complete every Task 4 on-device success and expected-error scenario.
- [ ] Reconcile requester, remote-harness, MITM, and WireGuard counters for all four workload modes.
- [ ] Record throughput, latency, queue pressure, the first explicit saturation point, and its reported disposition.
- [ ] Confirm lifecycle restart leaves a clean final full BSD MITM echo.
- [ ] Preserve direct-WGNX and requester-only passive MITM tests as regression controls.

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

- [ ] Run the peer-owned key-freshness decision after every authenticated transport send, including keepalives.
- [ ] Run the same decision after every accepted authenticated transport receive.
- [ ] Preserve wireguard-go's deduplication behavior so last-minute traffic cannot create repeated handshake attempts.

Implementation note: use one shared peer policy decision rather than adding checks independently to individual callers.

## Additional Protocol Corrections

### Flow diagnostics

- [ ] Populate `GetFlowState.advertised_local` from the tunnel source address and virtual source port.
- [ ] Add a host assertion for the advertised local endpoint.

Implementation note: remove the field only through a deliberate private API revision if it is no longer part of the diagnostic contract.

### IPv4 UDP checksum semantics

- [ ] Accept a zero inbound UDP checksum for IPv4.
- [ ] Continue generating and validating nonzero outbound UDP checksums.
- [ ] Add one accepted-zero and one rejected-invalid-nonzero checksum case.

### WireGuard padding and MTU

- [ ] Cap transport padding at the active effective inner MTU as wireguard-go does.
- [ ] Cover 1419-byte, 1420-byte, and configured-MTU boundaries.
- [ ] Include an outer-IPv6 case in the eventual device MTU matrix.

Implementation note: pass the effective MTU to the common padding calculation instead of applying per-caller corrections.

### Poll error reporting

- [ ] Propagate `TunnelPollResult.result` through `BsdMitmService::Poll` instead of reporting every worker failure as a successful empty poll.
- [ ] Map queue rejection and transport failure to a documented BSD errno or terminal poll event.
- [ ] Add focused tests distinguishing timeout, readiness, and worker failure.

### Cookie and rate-limit parity

- [ ] Retain responder cookie generation, under-load MAC2 validation, cookie replies, and handshake rate limiting as an explicit WireGuard conformance item.

Implementation note: this known hardening gap does not block the initial UDP fragmentation slice, but it blocks a full hostile-network conformance claim.

## Verification and Test Coverage

- [ ] Fix the three redundant moves reported by clang-tidy in `wg-sysmodule/test/host/scripted_platform.cpp`.
- [ ] Fix the three `size_t` to signed time-type narrowing conversions reported in `wg-sysmodule/test/host/tunnel_flow_plane_tests.cpp`.
- [ ] Include `tidy-check` in the intended aggregate verification gate, or document clearly why it remains separate.
- [ ] Add host coverage for MITM completion validation, receive truncation, errno translation, and route-state transitions.

Implementation note: the WireGuard normal, ASan/UBSan, and warning suites passed 48 deterministic cases during this review, while `tidy-check` failed on the six test findings above.

Implementation note: the MITM normal, sanitizer, static-analysis, and tidy targets passed, but the host suite does not compile or exercise the production BSD service and tunnel worker implementations.

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
- [ ] Do not retain both the current manual UDP/IP implementation and an lwIP implementation after the migration is complete.

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

- [ ] Initialize or retrieve the exact pinned lwIP source used by the local `wg-nx` reference.
- [ ] Record the revision, BSD license, integrity hash, and refresh procedure before importing source.
- [ ] Build a host-only NO_SYS prototype before integrating lwIP into the target runtime.
- [ ] Compile only the IPv4, pbuf, timeout, netif, UDP, checksum, fragmentation, and reassembly pieces required for the UDP path.
- [ ] Exclude TCP, DNS, DHCP, netconn, sockets, and application-facing lwIP APIs from this slice.
- [ ] Replace the manual UDP packet builder, IPv4 and UDP parser, and checksum helpers behind the existing flow API.

Implementation note: use `wg-nx` for its minimal Switch build and NO_SYS configuration ideas.

Implementation note: use `netbird-switch` for PCB lifetime, one-time initialization, static-pool, shutdown-ordering, and do-not-block-under-lock lessons.

Implementation note: do not copy their hardcoded MTU, global mutable ownership, relay architecture, or application-local socket contract.

## lwIP Runtime Ownership

- [ ] Serialize every lwIP call through one existing post-lock work owner.
- [ ] Do not call lwIP, run callbacks, allocate pbufs, or process lwIP timeouts while holding the daemon state mutex.
- [ ] Avoid adding a new thread or a global lwIP mutex unless measurements prove the existing serialized work boundary insufficient.
- [ ] Keep flow handles, policy generations, tuple quarantine, queue ordering, and completion slabs project-owned.
- [ ] Invalidate fragment and PCB state across flow close, policy refresh, peer restart, and activation teardown.

## Fragmentation Acceptance Cases

- [ ] Fragment outbound IPv4 UDP datagrams at the effective inner MTU with valid IP and UDP checksums.
- [ ] Reassemble valid inbound fragments into exactly one UDP datagram.
- [ ] Cover out-of-order, duplicate, overlapping, missing, expired, malformed, and resource-exhausted fragments.
- [ ] Produce either one delivery or one bounded observable drop for every reassembly attempt.
- [ ] Verify stale reassembly cannot cross flow closure, policy-generation change, peer restart, or activation teardown.
- [ ] Measure pbuf, fragment, timer, stack, completion, and total memory bounds under exhaustion.
- [ ] Add sanitizer coverage and fuzz the inner IPv4 input boundary.
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
