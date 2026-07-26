# WireGuard-NX MITM Sysmodule

This is the separate Horizon-facing process reserved for the future narrow `bsd:s` UDP MITM.
It is intentionally resident but inert in this first split.
It registers only `wgm:ctl` and does not register an Atmosphere MITM server or observe application traffic.
It owns a dedicated `wgnx:tun` discovery worker so the future BSD interception path can remain fail-open when the WireGuard sysmodule is absent, restarting, incompatible, or otherwise unusable.

The module writes independent diagnostics to `sdmc:/wgnx/wgnx-mitm-sysmodule.log`.
It uses program ID `0x010000000000EAD3`.
The WireGuard sysmodule remains `0x010000000000EAD0`.
Both sysmodules statically build against the checked-out third-party Atmosphere-libs tree at `common/lib/Atmosphere-libs`.
They do not share a project-owned runtime library, mutable process state, or an implementation boundary other than the future private IPC contract.

`mitm_policy.hpp` owns the future `bsd:s` interception admission policy.
The WireGuard and MITM program IDs are unconditional exclusions even when a future tunnel policy covers `0.0.0.0/0`.
The known fragile system clients have individual disabled-by-default policy flags.
The `wgm:ctl` control service separately toggles the global future `bsd:s` policy and each identified system-client feature flag at runtime, but reports that no interception server is installed until the narrow passive registration work begins.

The discovery worker performs one startup probe for diagnostics.
Later attempts are requested only by intercepted traffic or a reported tunnel CMIF failure, never by the BSD dispatch path itself.
The dispatch path will only schedule worker work and pass the current request to upstream BSD while the tunnel client is unavailable.
Failures double from 250 ms to a four-second cap.
The worker validates the private tunnel API version and required UDP, routing-policy, and completion-event capabilities before publishing a ready state.
The worker is the sole owner of its root and child CMIF sessions.
Future BSD request handlers must not use those sessions directly.

Build and validate the skeleton with:

```sh
make -C mitm-sysmodule test
make -C mitm-sysmodule test-sanitize
make -C mitm-sysmodule
make -C mitm-sysmodule dist
```

Deploy it independently with `python3 tools/ftp_sync.py <host> <port> -i`.
The current module is safe to autoboot because it does not register an MITM target.
