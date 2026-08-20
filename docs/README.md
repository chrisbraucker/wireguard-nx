# WireGuard-NX Documentation

This documentation describes the implementation boundary between Horizon BSD clients, the MITM sysmodule, the private tunnel-flow IPC, the WireGuard-owned IP adapter, and the WireGuard protocol core.
The repository records stable design constraints, active implementation work, validation procedures, and retained decision history separately.

## Start Here

- [`architecture/system-overview.md`](architecture/system-overview.md) explains component ownership and the complete traffic path.
- [`architecture/bsd-mitm-traffic.md`](architecture/bsd-mitm-traffic.md) explains how the BSD MITM admits, forwards, redirects, and tears down supported sockets.
- [`contracts/tunnel-flow-ipc.md`](contracts/tunnel-flow-ipc.md) specifies the private `wgnx:tun` contract.
- [`work/horizon-integration-plan.md`](work/horizon-integration-plan.md) records the active integration direction and its acceptance intent.

## Directory Roles

`architecture/` contains current component and traffic-flow explanations.
`contracts/` contains versioned private interfaces and diagnostic API contracts.
`runtime/` contains WireGuard runtime, resource, key, timer, and recovery invariants.
`validation/` contains reproducible host and device validation guidance plus published aggregate measurements.
`work/` contains active implementation plans and focused task acceptance guides.
`history/` preserves completed roadmaps, refactor plans, and prior acceptance records that explain why the current design exists.

Private device evidence, credentials, per-device configuration, and raw reports are intentionally not referenced by a public filesystem path.
Public conclusions in this repository remain understandable without those records.
