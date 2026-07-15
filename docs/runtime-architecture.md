# Runtime Architecture

The sysmodule runtime is split by ownership rather than by call direction. The
IPC and WireGuard wire contracts remain unchanged; the separation is internal.

## Components

- `ipc_service.cpp` adapts CMIF buffers and process IDs to typed runtime
  operations and owns service registration. It does not own peer state,
  sockets, queues, or lifecycle policy.
- `runtime/daemon_runtime.cpp` owns the single state mutex and the transitional
  procedural orchestration. It accesses peer state through `PeerRegistry`
  rather than index-correlated arrays.
- `runtime/peer_runtime.hpp` defines the fixed-capacity `PeerRegistry`. Each
  `PeerRuntime` slot is the structural owner of one peer's configuration,
  derived secrets, lifecycle and metrics state, UDP binding, protocol device,
  and peer controller. Lifecycle state is private; activation generations,
  transitions, metrics, errors, and status projection are peer-owned.
- `runtime/runtime_events.hpp` defines the closed event/effect vocabulary and
  bounded effect storage. `runtime/runtime_coordinator.*` resolves event peer
  identity and dispatches into `PeerRuntime`. Session establishment is the
  first production event path; remaining daemon procedures are migration
  adapters for later chunks.
- `runtime/horizon_dispatcher.*` owns Atmosphere work queues and concrete timer
  objects. It captures timer tokens and delivers typed callbacks; it does not
  decide protocol transitions.
- `runtime/udp_binding.*` is the move-only owner of one resolved endpoint and
  UDP socket lifetime. It also owns socket generation and suspension state.
- `runtime/packet_channel.hpp` owns development packet-API PID identity,
  receive queueing, and packet IDs. Peer-owned outbound staging remains in the
  protocol peer.
- `wireguard/peer_controller.*` owns platform-independent staged-send,
  handshake retry, and timer-token transitions. Each `PeerRuntime` owns one
  controller; production and deterministic host tests invoke the same
  operations.

## Concurrency Rule

The daemon keeps one state mutex during this refactor. Blocking endpoint
resolution and UDP receive continue to use the established three-step pattern:

1. snapshot peer, activation, socket generation, and socket under the mutex;
2. release the mutex for blocking platform I/O;
3. reacquire it and commit only if every generation and identity still match.

`UdpBinding::Matches` centralizes the socket half of this validation. Timer work
is similarly guarded by peer, activation, retry-sequence, and arm-generation
tokens before a controller transition is applied.

Event handlers mutate memory and return effects only. The daemon releases the
state mutex before executing an effect, then revalidates its peer and activation
identity before scheduling work. Stale effects are discarded.

The single mutex is intentionally retained until on-device regression testing
confirms this ownership refactor. Narrower locks can be considered later from
measured contention, without weakening generation-checked commits.

## Test Boundary

The host suite links the production `PeerRegistry`, `PeerRuntime`,
`RuntimeCoordinator`, `UdpBinding`, `PeerController`, `TimerCoordinator`, and
`PacketChannel`. It characterizes selection, lifecycle transitions, status
projection, stale event rejection, bounded effects, generation matching, and
per-peer ownership. Its recovery workflow drives:

`stage -> 20 fresh unanswered sends -> exhaust/drop -> stage later packet ->
fresh handshake -> derive session -> release packet`

Horizon work-queue scheduling, synchronous timer cancellation, BSD socket
lifetime, and real callback races remain on-device validation responsibilities.

## Stack Budget

The sysmodule main thread has a 16 KiB stack. `wg_device` and `wg_peer` include
bounded packet storage and are therefore themselves roughly 16 KiB objects.
Their reset and initialization paths reconstruct existing storage in place;
they must never use aggregate assignment that materializes a full temporary.
Target C++ builds enforce an 8 KiB maximum frame as a compile-time regression
guard. Host ASan/UBSan coverage verifies the destroy-and-reconstruct object
lifetime, while the generated target code verifies the constrained stack shape.
