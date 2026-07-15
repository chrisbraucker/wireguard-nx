# Runtime Architecture

The sysmodule runtime is split by ownership rather than by call direction. The
IPC and WireGuard wire contracts remain unchanged; the separation is internal.

## Components

- `ipc_service.cpp` adapts CMIF buffers and process IDs to typed runtime
  operations and owns service registration. It does not own peer state,
  sockets, queues, or lifecycle policy.
- `runtime/daemon_runtime.cpp` owns configured peers, activation generations,
  runtime metrics, protocol devices, and the single state mutex. It coordinates
  operations across the narrower components without exposing `DaemonState`.
- `runtime/horizon_dispatcher.*` owns Atmosphere work queues and concrete timer
  objects. It captures timer tokens and delivers typed callbacks; it does not
  decide protocol transitions.
- `runtime/udp_binding.*` is the move-only owner of one resolved endpoint and
  UDP socket lifetime. It also owns socket generation and suspension state.
- `runtime/packet_channel.hpp` owns development packet-API PID identity,
  receive queueing, and packet IDs. Peer-owned outbound staging remains in the
  protocol peer.
- `wireguard/peer_controller.*` owns platform-independent staged-send and
  handshake retry transitions. Production and deterministic host tests invoke
  the same operations.

## Concurrency Rule

The daemon keeps one state mutex during this refactor. Blocking endpoint
resolution and UDP receive continue to use the established three-step pattern:

1. snapshot peer, activation, socket generation, and socket under the mutex;
2. release the mutex for blocking platform I/O;
3. reacquire it and commit only if every generation and identity still match.

`UdpBinding::Matches` centralizes the socket half of this validation. Timer work
is similarly guarded by peer, activation, retry-sequence, and arm-generation
tokens before a controller transition is applied.

The single mutex is intentionally retained until on-device regression testing
confirms this ownership refactor. Narrower locks can be considered later from
measured contention, without weakening generation-checked commits.

## Test Boundary

The host suite links the production `PeerController`, `TimerCoordinator`, and
`PacketChannel`. Its recovery workflow drives:

`stage -> 20 fresh unanswered sends -> exhaust/drop -> stage later packet ->
fresh handshake -> derive session -> release packet`

Horizon work-queue scheduling, synchronous timer cancellation, BSD socket
lifetime, and real callback races remain on-device validation responsibilities.
