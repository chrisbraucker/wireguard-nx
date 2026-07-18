# WireGuard-NX

A work-in-progress project to bring the WireGuard VPN to Atmosphère.

Current state: Userspace WireGuard implementation is able to send and receive IP packets inside the sysmodule.

Parts of this project were generated under supervision with AI, make of that what you want.


## Outline

The repo is split into four main source configurations:

- `/common` for shared code
- `/docs` for documentation on usage and internals
- `/manager` for the manager applet started via nx-hbmenu or similar
- `/overlay` a tesla-based config menu for quick settings
- `/sysmodule` for the sysmodule that does the actual work
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
make -C sysmodule test
```

Build the target and report cumulative stack and image-footprint budgets with:

```bash
make -C sysmodule resource-report
```

See [Protocol Testing](docs/protocol-testing.md) for the deterministic boundary,
covered state transitions, and the final on-device interoperability gate.
See [Runtime Resource And Concurrency Budgets](docs/runtime-resource-budgets.md)
for fixed capacities, queue pressure, lock order, and worker contexts.


### Devcontainers

The project ships devcontainer configuration based on the [`devkitPro`](https://devkitpro.org/) image with some tweaks to make development in VS Code more convenient.

The devcontainers configuration comes with two setup scripts to prepare host and container for the workflow.

- `/.devcontainer/initialize.sh` makes sure two volumes, `codex-data`, and `wg-nx-history`, exist to persist session history and agent configuration across devcontainer sessions. It is currently not possible to opt out of the creation of those volumes, but they do no harm if unused.
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

- Biggest question is how to get the OS to use the tunnel, e.g. via MITM, module replacement or even a custom kernel driver.
