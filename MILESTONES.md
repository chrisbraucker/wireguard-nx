# WireGuard-NX Milestones

This document defines the recommended order of progress for bringing up
WireGuard functionality on Nintendo Switch homebrew. The goal is to create
useful intermediate checkpoints instead of waiting for full system-wide VPN
integration before validating anything.

## Principles

- Keep the control plane stable while the data plane evolves.
- Prove protocol correctness before solving full Horizon integration.
- Prefer vertical slices with observable outcomes over large speculative ports.
- Keep platform-specific code behind small adaptation boundaries.
- Treat the manager as diagnostics-first for now.
- Treat the overlay and sysmodule as the primary interactive path.

## Module Roles

### common

Shared definitions that are safe for libnx and Stratosphere consumers:

- config path constants
- config schema structs and parsing helpers
- IPC protocol structs and command IDs
- status/result enums
- platform-neutral WireGuard engine interfaces

### sysmodule

Primary implementation target:

- config loading and persistence
- peer/device runtime state
- WireGuard protocol engine
- UDP transport
- timers and work scheduling
- IPC control and status service
- logging and diagnostics

### overlay

Primary user interaction surface:

- peer selection
- start/stop toggle
- auto-start toggle
- connection state display
- handshake/tx/rx/status display

### manager

Read-only diagnostics and inspection tool for now:

- sysmodule presence
- peer list
- daemon status
- counters and error reporting

Later this can become a richer config editor, but it is not the current priority.

## Milestone 0: Control Plane Bring-Up

### Goal

Establish a stable sysmodule, IPC service, logger, and UI clients.

### Scope

- sysmodule boots reliably
- logging to SD works
- IPC service registers and serves requests
- manager can query daemon status and peers
- overlay can display peers and toggle dummy active/auto-start state

### Success Criteria

- [x] sysmodule starts from Atmosphere consistently
- [x] `/atmosphere/logs/wgnx-sysmodule.log` is written
- [x] manager reports sysmodule status and peer list
- [x] overlay shows peers and updates state live

### Status

This milestone is effectively complete.

## Milestone 1: Shared Config Model

### Goal

Replace hardcoded peer state with a shared config-backed source of truth.

### Scope

- define config schema in `common`
- define on-disk config location under `wgnx::ConfigPath`
- implement sysmodule config load at startup
- expose loaded peers through existing IPC API
- keep manager read-only
- keep overlay as the main mutating surface for active/autostart runtime state

### Recommended Deliverables

- `common/include/wgnx/config.hpp`
- config file format decision
- sysmodule config loader
- validation/error reporting for malformed configs

### Success Criteria

- replacing a config file on SD changes the peer list after restart
- manager and overlay reflect configured peers instead of dummy peers
- invalid config is reported in logs and does not crash the sysmodule

## Milestone 2: Runtime State Separation

### Goal

Separate static peer configuration from live connection state.

### Scope

- distinguish configured peer data from runtime counters
- define daemon states such as stopped, resolving, handshaking, established, error
- add richer status/error fields to the IPC-visible state
- keep active/autostart selection separate from transport status

### Recommended Deliverables

- internal runtime state model in sysmodule
- additional status enums/fields in shared IPC structs
- overlay display for connection state and last error

### Success Criteria

- overlay can show "configured but stopped" vs "active but connecting" vs "established" vs "error"
- runtime counters survive control operations correctly without corrupting config state

## Milestone 3: Platform Abstraction Layer

### Goal

Define the boundary that future WireGuard engine code will use on Horizon.

### Scope

- clock/time abstraction
- random bytes abstraction
- work/timer abstraction
- lock/mutex abstraction
- UDP transport abstraction
- packet buffer abstraction

### Rationale

Do this before porting meaningful WireGuard logic so Linux/BSD assumptions do not leak everywhere.

### Success Criteria

- the sysmodule contains a small, explicit platform interface for engine-facing code
- no direct libnx/Stratosphere networking calls are embedded inside future protocol logic

## Milestone 4: Protocol Core Skeleton

### Goal

Introduce a WireGuard engine shell without full cryptographic completion yet.

### Scope

- peer/device/session structures
- handshake state machine scaffolding
- packet type parsing and serialization
- timer hooks
- state transition logging

### Recommended Source Strategy

- use `wireguard-linux` as the primary protocol reference
- use `wireguard-freebsd` as the adaptation reference for BSD-like kernel/network behavior
- port selected logic, do not vendor the full kernel modules as dependencies

### Success Criteria

- sysmodule can build with protocol state objects and packet encoding helpers
- unit-style in-process tests or debug harness can parse and serialize WireGuard message types

## Milestone 5: Cryptographic Handshake

### Goal

Complete the WireGuard handshake flow for one peer.

### Scope

- static key handling
- ephemeral key generation
- handshake initiation
- handshake response processing
- session key derivation
- cookie/replay primitives as needed

### Success Criteria

- sysmodule can generate a valid handshake initiation
- sysmodule can complete a handshake with a known-good WireGuard peer/server
- success/failure is visible through logs and IPC state

## Milestone 6: UDP Transport

### Goal

Send and receive real WireGuard packets over the network without full tunnel integration.

### Scope

- initialize network services in sysmodule
- resolve endpoint and open UDP transport
- send handshake packets
- receive handshake/session packets
- maintain keepalive/retry/rekey timers

### Success Criteria

- sysmodule exchanges real WireGuard UDP packets with a remote peer
- overlay shows handshaking and established state
- rx/tx counters update over IPC

## Milestone 7: App-Owned Payload Transport

### Goal

Prove the engine works by sending encrypted application-owned data over the established session.

### Scope

- inject test payloads from within the sysmodule or a controlled test client
- encrypt and send through the WireGuard session
- receive and decrypt replies
- expose counters and last activity through IPC

### Rationale

This is the first milestone that proves practical WireGuard functionality without solving system-wide packet interception yet.

### Success Criteria

- given one configured peer, the sysmodule can:
  - complete a handshake
  - send encrypted test payload bytes
  - receive and decrypt response bytes
  - report success via IPC and logs

## Milestone 8: Persistent Runtime Operations

### Goal

Make start/stop/reconnect behavior robust enough for normal use during testing.

### Scope

- explicit connect/disconnect actions
- endpoint retry policy
- backoff/rekey behavior
- error recovery after network loss
- autostart behavior on sysmodule boot

### Success Criteria

- overlay can reliably start and stop a peer
- network interruptions do not permanently wedge the daemon
- autostart state behaves predictably after reboot

## Milestone 9: Packet Interface Strategy

### Goal

Choose and implement the first real packet path for non-test traffic.

### Options To Evaluate

- userspace packet injection path for homebrew-controlled apps
- socket-layer redirection for selected traffic
- deeper Horizon integration if feasible

### Scope

- define ingress/egress packet format
- attach decrypted/encrypted packet handling to the engine
- decide what "supported traffic" means for the first release

### Success Criteria

- non-test IP payloads can be carried through the engine in a controlled scenario
- limitations are clearly documented

## Milestone 10: Broader Horizon Integration

### Goal

Move from a validated transport engine toward console-wide usefulness.

### Scope

- routing strategy
- DNS behavior
- interaction with Nintendo services
- coexistence with normal networking
- handling suspend/resume and network state changes

### Success Criteria

- a clearly defined class of Switch traffic can use the tunnel end-to-end
- behavior is stable enough for real-world testing

## Recommended Immediate Order

1. Milestone 1: Shared Config Model
2. Milestone 2: Runtime State Separation
3. Milestone 3: Platform Abstraction Layer
4. Milestone 4: Protocol Core Skeleton
5. Milestone 5: Cryptographic Handshake
6. Milestone 6: UDP Transport
7. Milestone 7: App-Owned Payload Transport

This preserves momentum and gets you to a meaningful "WireGuard works on Switch for app-owned traffic" checkpoint before tackling the much harder OS-level tunnel problem.

## Non-Goals For The Near Term

- manager-based full config editor
- system-wide VPN semantics from day one
- direct reuse of Linux/BSD kernel source as a compiled dependency
- premature deep Horizon routing assumptions before protocol validation

## References To Use During Implementation

- `wireguard-linux` for protocol/reference truth
- `wireguard-freebsd` for BSD-like kernel/network adaptation ideas
- Atmosphere/libstratosphere for sysmodule/runtime/service patterns
- libnx and Switchbrew docs for Horizon networking and services
