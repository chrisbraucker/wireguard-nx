# Runtime Architecture

The sysmodule runtime is split by ownership rather than by call direction.
The IPC and WireGuard wire contracts remain unchanged; the separation is internal.

## Components

- `ipc_service.cpp` adapts CMIF buffers and process IDs to typed runtime operations and owns service registration.
  It does not own peer state, sockets, queues, or lifecycle policy.
- `runtime/daemon_runtime.cpp` composes one `DaemonRuntime` instance.
  It owns the single state mutex, routes external commands, aggregates status, and wires platform callbacks to their concrete execution components.
  Configuration loading and autostart filesystem persistence are serialized independently of the state mutex.
  The latter captures a bounded, generation-tagged request, persists outside the state lock, and commits only if it remains current after the write succeeds.
  CMIF-facing free functions are narrow adapters to that instance; no peer, packet, timer, probe, or pending-request state exists in independent daemon globals.
- `runtime/runtime_effect_executor.*` owns the iterative runtime-effect visitor and Horizon completion bridges.
  It performs endpoint resolution, UDP bind, send, and close operations; arms and cancels concrete timers; queues receive and outbound-submission work; publishes decrypted packets; and commits resolver, timer, debug-probe, and NIFM observation completions.
  It executes peer decisions and reports generation-tagged facts through `RuntimeCoordinator`; it does not choose peer lifecycle or recovery policy.
  It validates in-memory state under the daemon mutex, then releases it before every concrete timer, workqueue, socket, or nested-effect operation.
- `runtime/encrypted_receive_pump.*` owns encrypted UDP receive scheduling, the bounded manual-rebind request, one 4 KiB process-lifetime datagram scratch buffer, and one bounded completion batch.
  It snapshots receive identity under the shared mutex, performs blocking receive without that mutex, and publishes authenticated datagrams or factual receive failures only after generation revalidation.
- `runtime/peer/peer_runtime.hpp` defines the fixed-capacity `PeerRegistry`.
  The registry owns slot configuration, clearing, selection, event routing, and bounded bulk packet retirement without exposing mutable slots.
  Each `PeerRuntime` slot is the structural owner of one peer's configuration, derived secrets, lifecycle and metrics state, UDP binding, protocol device, and peer controller.
  Lifecycle state is private; activation generations, transitions, metrics, errors, status projection, activation, and inbound and outbound protocol policy are peer-owned.
  Each peer owns one bounded pending encrypted datagram and one bounded generation-tagged plaintext slot, so events and effects never carry owned packet buffers.
- `runtime/runtime_coordinator.*` is the runtime-facing mediator for peer transitions.
  It uses only `PeerRegistry`'s closed collection API and has no direct mutable access to peer slots.
  Peer configuration, derived secrets, binding, protocol device, controller, generations, and lifecycle are private.
  Runtime adapters receive immutable lifecycle, binding, packet, timer, or protocol snapshots scoped to one operation; they cannot obtain a mutable peer.
- `runtime/runtime_events.hpp` defines the closed event/effect vocabulary and bounded effect storage. `runtime/runtime_coordinator.*` resolves event peer identity and dispatches into `PeerRuntime`.
  Activation, endpoint and bind completion, outbound packet staging, send completion, encrypted datagram receipt, protocol timer expiry, transport rebind, transport failure, deactivation, and decrypted-packet publication use this path.
  UDP transport failures cross this boundary as socket- and generation-tagged facts.
  The peer decides whether an error is nonterminal, whether send failure suspends transport, which timers must be canceled, and whether successful rebinding resumes with a keepalive or a handshake.
  Rebind opens are tagged by purpose and generation: failed opens preserve the old socket, stale completions close only their candidate, and successful completion atomically adopts the replacement before recovery effects are emitted.
- `runtime/domain_types.hpp` defines compiler-distinct peer, activation, socket, datagram, packet-generation, packet, and process identities.
  Runtime components retain these types internally and convert to fixed-width CMIF, platform, WireGuard-record, timer, status, and diagnostic values only at those boundaries.
- `runtime/endpoint_resolver.*` owns the bounded pending endpoint-resolution request.
  Resolution runs on its Horizon work queue and returns a typed, activation-tagged completion instead of mutating daemon-owned request state.
- `runtime/horizon_dispatcher.*` owns Atmosphere ordered work queues only.
  It executes work supplied by runtime components and contains no timer or peer policy.
  Each lane has an explicit pending capacity and exposes high-water, coalescing, rerun, rejection, and completion statistics.
- `runtime/userspace_ip_adapter_owner.*` owns lwIP initialization, one IPv4 netif, UDP PCBs, pbuf lifetime, and bounded adapter operations.
  It runs only through a dedicated work item on the existing ordered `wgnx-submit` lane.
  Flow state reserves a stable handle under the daemon mutex, the owner opens or closes the matching PCB outside that mutex, and `TunnelFlowPlane` commits an open only after the captured client, peer, and policy identities remain current.
  A send copies one payload into the owner slot, lets lwIP construct and fragment IPv4 output, and exposes that complete bounded collector only after `udp_send()` returns.
  The daemon then atomically stages the complete packet batch through the peer-owned WireGuard queue before it executes resulting effects.
- `runtime/timer_scheduler.*` owns concrete Horizon protocol and auxiliary timers. `runtime/timer_schedule.*` tracks bounded physical arm and queued delivery state independently of Horizon.
  Expirations retain their complete token until delivered through the coordinator; the scheduler contains no peer policy.
  Arm and cancellation effects likewise retain the token allocated under the runtime lock, preventing delayed platform work from changing a newer physical schedule.
- `runtime/udp_binding.*` owns in-memory resolved-endpoint, socket-generation, and suspension state.
  It does not perform platform I/O or implicit destruction-time closure: every socket is explicitly released into a close effect before it crosses the state-lock boundary.
- `runtime/packet_transport.hpp` defines the protocol-neutral complete-IP packet boundary.
  It does not expose CMIF types or contained IP protocols.
- `runtime/packet_data_plane.*` owns IPv4/IPv6 envelope validation, active-peer routing, packet IDs, consumer transfer, outbound submission, decrypted packet delivery, receive staleness, and queue disposition.
  The public API v4 adapter intentionally retains its IPv4-only contract.
- `runtime/packet_channel.hpp` implements `PacketTransport` for the development CMIF packet API.
  Its explicit IPv4-only capability preserves the API v4 receive contract while future transports can accept IPv6.
  PID ownership and the bounded receive queue end at this adapter; PID identity does not enter peer events or WireGuard packet records.
  Peer-owned outbound staging remains in the protocol peer.
- `runtime/debug_probe_runner.*` owns synthetic probe commands, status, packet construction, reply classification, and timeout state.
  It submits through the internal-producer side of `PacketDataPlane`, preserving the CMIF packet consumer while using the same peer staging and effect path.
- `platform/horizon/network_path_service.*` owns one activation-scoped `nifm:s` request, configures it with the observed system requirement preset, waits for request-state events on a dedicated bounded worker, and publishes typed raw state observations only.
  It neither owns nor associates a UDP descriptor; `PeerRuntime` owns the resulting local-path policy and the transport runtime owns socket lifecycle.
  Request creation does no synchronous formatted logging because it executes on the deep CMIF activation stack.
- `runtime/peer_configuration.*` loads a configuration snapshot, derives move-only private and preshared key material before peer assignment, resolves the autostart selection, and scrubs encoded secret fields.
- `runtime/udp_binding.hpp` also defines the bounded single-item `UdpRebindQueue`, which owns manual path-transition requests until the receive pump can safely replace the socket.
- `wireguard/peer_controller.*` owns platform-independent staged-send, handshake retry, initiator/responder session derivation, responder-session confirmation, and timer-token transitions.
  Each `PeerRuntime` owns one controller; production and deterministic host tests invoke the same paths.

Inbound endpoint roaming occurs only after handshake or transport authentication.
A responder-derived keypair enters the `next` slot and does not replace the current session until its first authenticated transport packet; that promotion moves the old current keypair to `previous`.
Invalid MACs, non-increasing initiation timestamps, initiations inside the upstream 20 ms flood interval, transport replays, and unknown receiver indices do not update endpoint or authenticated byte counters.

## Concurrency Rule

The daemon keeps one state mutex.
Blocking endpoint resolution, UDP socket opening and sends, and UDP receive use the established three-step pattern:

1. snapshot peer, activation, socket generation, and socket under the mutex;
2. release the mutex for blocking platform I/O;
3. reacquire it and commit only if every generation and identity still match.

`UdpBinding::Matches` centralizes the socket half of this validation.
Timer work is similarly guarded by peer, activation, retry-sequence, and arm-generation tokens before a controller transition is applied.

Event handlers mutate memory and return effects only.
Command and completion paths release the state mutex before handing a batch to `RuntimeEffectExecutor`, which revalidates peer and activation identity before scheduling work.
Stale effects are discarded.

Effect execution is iterative.
The platform-neutral `DrainEffectBatches` primitive owns the loop used by `RuntimeEffectExecutor`, so completion events may produce another bounded batch without recursively retaining prior batches on a Horizon worker stack.
Blocking UDP bind and send handlers are non-inlined stack boundaries so their I/O snapshots cannot be coalesced into the executor frame.

Userspace-IP flow operations use the same snapshot, release, and revalidate rule.
The operation slot is bounded, while a coalesced lifecycle-control path remains reserved for configuration and reset work.
lwIP callbacks only copy into owner-owned collectors and never call daemon, packet-plane, peer, CMIF, logging, or platform-I/O code.

`EncryptedReceivePump` owns one process-lifetime 4 KiB datagram scratch buffer and one 2,184-byte effect batch.
Its ordered work item places only a small `packet_buffer` view on the worker stack.
Work for the same receive item cannot execute concurrently, so this storage is exclusive without requiring one allocation per peer.
Received bytes are consumed synchronously before the next socket read and are never retained through the scratch view.
The non-inlined commit boundary returns before the member batch enters effect execution, so its frame cannot accumulate with UDP send effects.

The UDP platform boundary returns a `[[nodiscard]]` closed receive result.
`Datagram`, `Retry`, and `Failure` are separate outcomes; byte count is therefore not used as an error channel, and a zero-length UDP datagram remains a datagram.
The Horizon adapter normalizes explicit would-block, timeout, and interruption conditions as retryable while preserving the native result and errno value for diagnostics.
Horizon BSD has also been observed to return negative `RecvFrom` results while reporting no native error.
This separately tagged anomaly is a bounded, 25 ms-paced local retry on the dedicated receive worker.
It neither publishes a transport failure nor changes peer or binding state: NIFM observation owns future path/lifecycle policy.
Other unclassified negative results are terminal.
The receive pump publishes a generation-tagged transport failure only for a terminal outcome, preserving peer recovery policy outside the platform adapter.

Every peer event declares its maximum effect count.
The coordinator checks the actual count against that event budget, and all budgets fit the fixed eight-effect batch.
Peer policy uses invariant `Add`/`Append` operations, which terminate if the declared bound is violated; capacity-sensitive callers use the `[[nodiscard]]` `TryAdd`/`TryAppend` operations and handle the closed capacity result.

Packet views carried by peer events are explicitly synchronous borrows.
A `SynchronousPacketView` cannot be retained in a runtime effect, and any packet that survives event dispatch is copied into existing bounded peer or data-plane storage with its generation or packet identity before dispatch returns.
Asynchronous queues therefore own packet bytes rather than retaining caller memory.

The single mutex is intentionally retained through the first post-refactor on-device regression.
Narrower locks can be considered later from measured contention, without weakening generation-checked commits.

`TimerFacts` records only sampled platform facts: a monotonic timer origin and raw entropy.
It never contains a policy decision.
`PeerRuntime` reduces that entropy using WireGuard's retry-jitter bounds, combines it with peer configuration and protocol limits, and emits absolute timer effects; daemon, receive, and executor adapters do not derive deadlines.

Diagnostics use a bounded in-memory producer queue. `logger::Log` only formats and records a line, so protocol and state-owner paths can preserve diagnostic facts while holding the daemon mutex. `logger::Flush` performs debug and SD-card I/O only from post-lock IPC and worker boundaries.

## Test Boundary

The host suite links the production `PeerRegistry`, `PeerRuntime`, `RuntimeCoordinator`, `EndpointResolver`, `UdpBinding`, `PeerController`, `TimerCoordinator`, `TimerSchedule`, `PacketDataPlane`, `PacketChannel`, `DebugProbeRunner`, typed NIFM path classification, `UdpRebindQueue`, and the production `DrainEffectBatches` primitive.
Its deterministic cases characterize UDP receive and work-admission outcomes, selection, activation, lifecycle transitions, status projection, stale event rejection, timer arming/replacement/cancellation, queued stale delivery, bounded effects, generation matching, per-peer ownership, packet IDs, PID consumer transfer, IPv4/IPv6 envelope handling, packet queue overflow and staleness, closed endpoint/rebind/probe admission, typed packet rejection, and the outbound send lifecycle.
Compile-time checks reject cross-domain identity comparisons and verify every event effect budget.
Its production-runtime recovery workflow drives:

`stage -> 20 fresh unanswered sends -> exhaust/drop -> stage later packet -> fresh handshake -> derive session -> release packet`

The same runtime test then drives peer-originated rotation:

`authenticated initiation -> preserve current/install next -> send response -> authenticated transport -> promote next/preserve previous -> publish plaintext`

It also verifies initiation admission, malformed input, transport replay, unknown receiver indices, unauthenticated endpoint-roaming rejection, and the composition failure path: cancelled resolver work and stale completion during shutdown, resolution and UDP-open failure, deactivation with pending rebind and timer work, and a multi-batch nonrecursive effect drain.

Horizon work-queue execution, synchronous platform timer cancellation, BSD socket lifetime, and real callback races remain on-device validation responsibilities.

Fixed storage, queue pressure, lock order, lock-required methods, and worker execution contexts are specified in [Runtime Resource And Concurrency Budgets](runtime-resource-budgets.md).

## Stack Budget

The sysmodule main thread has a 16 KiB stack. `wg_device` and `wg_peer` include bounded packet storage and are therefore themselves roughly 16 KiB objects.
Their reset and initialization paths reconstruct existing storage in place; they must never use aggregate assignment that materializes a full temporary.
Target C++ builds enforce an 8 KiB maximum frame as a compile-time regression guard.
This limit is necessary but does not detect cumulative nested frames: a Chunk 4 activation regression retained resolver, effect-batch, bind-completion, and send-snapshot frames through recursive effect execution and overflowed the 16 KiB resolver stack.
The executor is now iterative, with target frames of 3,184 bytes for resolver work, 32 bytes for executor entry, 4,464 bytes for the shared effect drain, 2,560 bytes for bind opening, and 4,064 bytes for datagram send.
Host ASan/UBSan coverage verifies object lifetime and bounded effect chaining, while generated target code verifies each constrained frame.

Chunk 14 enables compiler stack-usage output and checks the known cumulative paths with `tools/check_stack_usage.py`.
The resolver -> activation -> handshake -> logging path is currently the tightest at 13,840 bytes, leaving 2,544 bytes on its 16 KiB worker stack.
Receive commit, generated send, and failure-publication chains retain 8,704, 6,736, and 6,048 bytes respectively.

An on-device fatal after Chunk 5 exposed another cumulative-stack case on the receive worker: its 4 KiB local datagram buffer remained live while inbound processing generated and executed a pending datagram send.
The resulting call chain exhausted the 16 KiB worker stack in `udp_send`, even though every individual frame passed the 8 KiB compiler guard.
The receive bytes now live in the ordered worker's persistent scratch storage, reducing the receive frame from 6,816 bytes to 160 bytes without increasing any thread stack or changing packet capacity.
Including the 2,608-byte inbound commit, 4,560-byte effect executor, 4,048-byte datagram-send effect, and 160-byte UDP adapter frames, the measured target path now consumes about 11.6 KiB before small workqueue frames instead of exceeding the 16 KiB worker stack.

Chunk 6's first shape retained the inbound commit's effect batch while entering effect execution and reached roughly 13 KiB before workqueue frames.
Receive effects now use the ordered worker's persistent batch and cross a non-inlined commit boundary that returns before execution.

The first Chunk 6 device run exposed a separate activation-path regression.
The compiler had inlined the plaintext-publication effect's validation and logging locals into the shared variant visitor, increasing every executor frame from 4,560 to 6,144 bytes.
The initial outbound handshake then overflowed the resolver worker during formatted logging before any inbound packet was handled.
Plaintext publication now crosses a dedicated 192-byte non-inlined adapter.
Target frames are again 3,168 bytes for resolver work, 4,560 bytes for effect iteration, 2,544 bytes for bind opening, and 4,064 bytes for datagram send.
This restores the proven pre-Chunk-6 activation shape while keeping the publication path generation-checked under the daemon mutex.

Chunk 12 preserves those boundaries after extracting concrete execution.
Generated target code measures 3,168 bytes for endpoint completion, 4,448 bytes for effect iteration, 2,560 bytes for bind opening, 4,064 bytes for datagram send, 2,752 bytes for receive commit, and 144 bytes for the receive loop.
Receive commit still returns before effect execution, and iterative completion draining still prevents prior effect batches from accumulating recursively.

The typed UDP receive result grows the receive loop to 208 bytes while retaining the 192-byte UDP adapter frame.
Terminal receive completion uses a 4,752-byte frame only after the adapter has returned, keeping the receive failure path inside the existing 16 KiB worker budget.

The first Chunk 13 device activation exposed a compiler-materialized `EffectBatch` in `RuntimeCoordinator::Dispatch`.
A coordinator-local batch used only to validate the event effect budget added 2,240 bytes to the resolver -> executor -> bind completion -> peer handshake chain and overflowed during handshake-transition logging.
The invariant check now runs after timer-effect finalization in `PeerRuntime::Handle`, where the returned batch already exists, and coordinator dispatch directly returns the peer result.
Target frames are 16 bytes for coordinator dispatch and 80 bytes for the peer handler, removing 2,224 bytes from the failed chain without changing event budgets or storage capacity.
The corrected path subsequently sustained a real-peer connection for more than 15 minutes and completed several requester round trips without instability.

The post-Chunk 14 corrective pass moves iterative effect handling into a platform-neutral 4,464-byte drain called through a 32-byte executor entry; bind opening is 2,560 bytes.
The resource gate measures the complete resolver chain at 13,840 bytes.
This remains above the required 1 KiB margin and leaves 2,544 bytes for ABI and platform overhead.
Any new activation or common effect-path local storage must therefore be checked against this chain before it is accepted.

NIFM-driven activation also crosses a dedicated serialized transmit worker before issuing the initial encrypted datagram.
The resolver returns after it opens the UDP bind and queues the peer-owned datagram; the transmit worker owns one pending send effect and a persistent completion batch.
This removes the resolver -> bind -> send-completion stack chain that exceeded the 16 KiB worker stack on device.
Initial receive polling is queued only after the handshake initiation completion, preserving send-before-receive ordering without relying on cross-worker timing.
