# WireGuard-NX

A work-in-progress project to bring the WireGuard VPN to Atmosphère.

Current state: Userspace WireGuard implementation is able to send and receive IP packets inside the sysmodule.

Parts of this project were generated under supervision with AI, make of that what you want.


## Progress

WireGuard-NX has a real userspace WireGuard implementation for Atmosphère that establishes peer tunnels and exchanges encrypted inner IPv4 traffic on-device.
The project has deterministic host and sanitizer coverage, target resource gates, and real-peer validation across handshake and rekeying, recovery, lifecycle, direct flow IPC, and a narrowly scoped BSD MITM UDP path.
The MITM sysmodule retains Horizon BSD lifecycle and selects passthrough or the private WireGuard flow service with bounded queues and observable backpressure.
The WireGuard-owned lwIP adapter now provides IPv4, UDP, fragmentation, reassembly, and the bounded TCP foundation behind the private flow contract.
The remaining focused acceptance work is the Toolbox-only BSD TCP path against a real peer.


## Outline

The repository is split into these main source areas:

- `/common` for shared code
- `/docs` for documentation on usage and internals
- `/manager` for the manager applet started via nx-hbmenu or similar
- `/overlay` a tesla-based config menu for quick settings
- `/wg-sysmodule` for the sysmodule that does the actual tunnel work
- `/mitm-sysmodule` for the separate Horizon interception process
- `/tools` has convenience scripts for debugging and quickly installing binaries and pulling logs

Manager and overlay should communicate with the sysmodule via IPC.

The project provides a .devcontainer configuration for quick environment setup in supported editors such as VSCode.


## Development

Make sure that the submodule is initialized.

```bash
git submodule update --init --recursive
```

Run the deterministic protocol suite on the development host with:

```bash
make -C wg-sysmodule test
```

Build the target and report cumulative stack and image-footprint budgets with:

```bash
make -C wg-sysmodule resource-report

# Build and package the MITM sysmodule.
make -C mitm-sysmodule
make -C mitm-sysmodule dist
```

See [the documentation index](docs/README.md) for architecture, contracts, runtime invariants, validation, active work, and retained history.
See [Protocol Testing](docs/validation/protocol-testing.md) for the deterministic boundary, covered state transitions, and the final on-device interoperability gate.
See [Runtime Resource And Concurrency Budgets](docs/runtime/resource-budgets.md) for fixed capacities, queue pressure, lock order, and worker contexts.


### Devcontainers

The project ships devcontainer configuration based on the [`devkitPro`](https://devkitpro.org/) image with some tweaks to make development in VS Code more convenient.

The devcontainers configuration comes with two setup scripts to prepare host and container for the workflow.

- `/.devcontainer/initialize.sh` makes sure two volumes, `codex-data`, and `wg-nx-history`, exist to persist session history and agent configuration across devcontainer sessions.
  It is currently not possible to opt out of the creation of those volumes, but they do no harm if unused.
- `/.devcontainer/postStart.sh` maps those folders into the right locations in the container, so that history survives container rebuilds.
  If you create those volumes manually, they may need to have their permissions tweaked, as the `postStart.sh` script is executed without root permissions in the container and therefore cannot change permissions.


### Enabling nxlink in devcontainer

If using the devcontainer together with nxlink for on-device development, make sure to set the remote extension port forwarding policy to `allInterfaces` at [Remote Extension: Local Port Host](vscode://settings/remote.localPortHost).


## Primitive

The project outline is based in part on [switch-homebrew templates](https://github.com/switchbrew/switch-examples/tree/master/templates).


## License

This software is licensed under the terms of the GPLv2, with exemptions for specific projects noted below.

The project ships a vendored version of [monocypher](https://github.com/LoupVaillant/Monocypher), which is dual-licensed under CC-01 or BSD.

You can find a copy of the license in the [LICENSE file](LICENSE).

Exemptions:

- Nintendo is exempt from GPLv2 licensing and may (at its option) instead license any source code authored for the wireguard-nx project under the Zero-Clause BSD license.


## Resources

Network-related details may be relevant in [ldn-mitm](https://github.com/spacemeowx2/ldn_mitm).

ReSwitched SwIPC docs: https://reswitched.github.io/SwIPC/

Wireguard Linux kernel driver: https://git.zx2c4.com/wireguard-linux/tree/drivers/net/wireguard/

ftpd: https://github.com/mtheall/ftpd

Tesla-based helper to manage IP configuration for LANPlay and XLink Kai: https://github.com/matteofo/LANHelper-Tesla

ImGUI library: https://github.com/ocornut/imgui

Plutonium SDL2 GUI library: https://github.com/XorTroll/Plutonium


## Open questions

- The selected first transparent path uses the separate BSD MITM sysmodule to choose once between retained Horizon BSD handling and delegation through the private WireGuard flow service.
- The WireGuard sysmodule owns the userspace IP stack, Layer 3 packet processing, fragmentation, reassembly, and tunnel-facing transport state behind a boundary separate from the WireGuard protocol core.
- [BSD MITM traffic path](docs/architecture/bsd-mitm-traffic.md) records the observed service boundary, the route-selection rule, and the narrow Toolbox TCP translation.
- Native Horizon interface or routing integration remains a parallel reversing question rather than a dependency for the MITM path.
