# WireGuard-NX MITM Sysmodule

This is the separate Horizon-facing process implementing the first narrow `bsd:s` UDP MITM proof.
It registers `wgm:ctl` and one Atmosphere `bsd:s` MITM server.
The active interceptor admits every `bsd:s` service session from requester forwarder title ID `0x0515C00B3A04A000`.
SM requests this decision before the first CMIF command is available, so `RegisterClient` and `StartMonitoring` cannot safely select a session at admission time.
The expected `RegisterClient` session owns the descriptor table used by later socket operations.
Observed `StartMonitoring` side sessions are short-lived and use the generic forward path after admission.
`RegisterClient` is deliberately left on Atmosphere's generic forward path so its original PID descriptor is tagged and restored by Mesosphere, and its duplicated transfer-memory copy handle is closed after forwarding.
It owns one `wgnx:tun` flow worker that also performs bounded discovery so BSD dispatch remains fail-open when the WireGuard sysmodule is absent, restarting, incompatible, or otherwise unusable.

The module writes independent diagnostics to `sdmc:/wgnx/wgnx-mitm-sysmodule.log`.
It uses program ID `0x010000000000EAD3`.
The WireGuard sysmodule remains `0x010000000000EAD0`.
Both sysmodules statically build against the checked-out third-party Atmosphere-libs tree at `common/lib/Atmosphere-libs`.
They do not share a project-owned runtime library, mutable process state, or an implementation boundary other than the future private IPC contract.

`mitm_policy.hpp` owns the future `bsd:s` interception admission policy.
The WireGuard and MITM program IDs are unconditional exclusions even when a future tunnel policy covers `0.0.0.0/0`.
The known fragile system clients have individual disabled-by-default policy flags.
The `wgm:ctl` control service exposes the development policy controls and reports whether the `bsd:s` server registered.
Requester-only title admission is compile-time scoped while runtime policy toggles control whether future requester sessions are intercepted.

## Graceful shutdown

Control API v2 adds `Shutdown` as command ID 3 on `wgm:ctl`.
The command signals the main thread and returns before teardown starts.
The main thread joins both server loops, stops discovery, and closes every `wgnx:tun` handle on the flow worker.
The flow worker also interrupts an in-progress tunneled `poll()` so an unbounded caller timeout cannot prevent shutdown.
Controllers can issue this request through `wgnx/mitm_client.hpp` before terminating the sysmodule process.
The generated `toolbox.json` declares `wgm:ctl` and command 3 using the `ovl-sysmodules` shutdown contract, so its manager invokes this sequence before it considers forced termination.
After both loop threads have joined, the module deliberately retains the static control and BSD:S `ServerManager` instances until `ams::Main` returns.
It also retains the BSD MITM object heap because active service objects remain owned by that server manager.
This follows the WireGuard sysmodule's proven terminal-shutdown pattern because Horizon aborts while destroying `ServerManager` after `LoopProcess` has stopped.
After the BSD dispatch loop is joined, the module explicitly calls `UninstallMitm("bsd:s")` only when this process successfully installed that registration.
It then logs `HasMitm` so a stale registration is visible before process exit.
This is necessary because retaining the manager bypasses its normal destructor cleanup and SM does not reliably remove the retained `bsd:s` registration when the process exits.
The manager and heap retention remain an explicit Horizon-dependent workaround rather than a general C++ resource-management pattern, so no code may reuse retained state or attempt a second shutdown in the same process.
The module never declares a future MITM and therefore never calls `ClearFutureMitm` during shutdown.
Failed registration never triggers `UninstallMitm`, because an observed MITM could belong to another module.
The overlay probes `wgm:ctl` with Atmosphere's read-only `HasService` command rather than temporarily registering and unregistering the service name.

The local discovery controller performs one startup probe for diagnostics.
Later attempts are requested only by intercepted traffic or a reported tunnel CMIF failure, never by the BSD dispatch path itself.
The dispatch path will only schedule worker work and pass the current request to upstream BSD while the tunnel client is unavailable.
Failures double from 250 ms to a four-second cap.
The flow worker validates the private tunnel API version and required UDP, routing-policy, and completion-event capabilities before publishing a ready state.
The flow worker is the sole owner of every WGNX-related service-manager request, root session, and child client session.
The discovery controller owns only local backoff state and never opens a service or holds a CMIF handle.
BSD request handlers never use either worker session directly.

The implemented routed surface is connected IPv4 UDP through socket creation, connect, send, receive, receive-from, readable polling, endpoint queries, and close.
The original BSD descriptor is retained as the lifecycle and application-visible local-endpoint anchor.
After a WGNX flow opens, the MITM forwards the initial UDP `Connect` only to establish the native local IPv4 address and ephemeral port on that retained descriptor.
It captures the endpoint immediately and returns it from `GetSockName` while all payload traffic stays on `wgnx:tun`.
The WireGuard interface address and tunnel source port are never exposed through the BSD-facing socket.
Failure to establish or capture that endpoint closes the flow and leaves the socket terminal rather than permitting payload fallback to upstream BSD.
Every tracked descriptor has an explicit `Created`, `OpeningTunnel`, `Direct`, `Tunneled`, `Failed`, or `Closed` route state.
Only `Created` can choose a path, and neither a direct nor a tunneled socket migrates later because tunnel availability changes.
Uncovered or unavailable traffic continues through upstream BSD.
After a socket opens a WGNX flow, it remains tunneled until close and later tunnel failure returns a BSD error rather than switching back to direct BSD.
`SendTo` and mixed direct plus tunneled polls fail explicitly on a tunneled socket.
Tunneled `Send` copies payloads into a bounded MITM-owned FIFO and returns without waiting for a WGNX staging-slot retirement or outer UDP transmission.
The worker batches FIFO entries only for their owning WGNX child client, preserving per-socket UDP submission order.
WGNX `QueueFull` suppresses `POLLOUT` until its coalesced `Writable` completion arrives, while a full MITM adapter FIFO also returns `EAGAIN` without busy retrying.
Socket options and generalized process admission remain deferred work.

Build and validate the skeleton with:

```sh
make -C mitm-sysmodule test
make -C mitm-sysmodule test-sanitize
make -C mitm-sysmodule
make -C mitm-sysmodule dist
```

Deploy it independently with `python3 tools/ftp_sync.py <host> <port> -i`.
The current module is safe to autoboot because it only admits the requester forwarder title ID and passes the requester through while `wgnx:tun` is unavailable or does not cover the destination.
