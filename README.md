# Preliminary documentation

The repo is split into four main source configurations:

- `/common` for shared code
- `/manager` for the manager applet started via nx-hbmenu or similar
- `/overlay` a tesla-based config menu for quick settings
- `/sysmodule` for the sysmodule that does the actual work

Manager and overlay should communicate with the sysmodule via IPC.

The project provides a .devcontainer configuration for quick environment setup in supported editors such as VSCode.


## Enabling nxlink

If using the devcontainer together with nxlink for on-device development, make sure to set the remote extension port forwarding policy to `allInterfaces` at [Remote Extension: Local Port Host](vscode://settings/remote.localPortHost).


## Primitive

I grabbed the project outline in part from the [switch-homebrew templates](https://github.com/switchbrew/switch-examples/tree/master/templates) and the open source [sys-clk project](https://github.com/retronx-team/sys-clk/tree/develop), as I want to use the IPC, overlay controls and manager software for my project likewise.


## Resources

Other network-related stuff may be relevant in [ldn-mitm](https://github.com/spacemeowx2/ldn_mitm).

Wireguard Linux kernel driver: https://git.zx2c4.com/wireguard-linux/tree/drivers/net/wireguard/

ftpd: https://github.com/mtheall/ftpd

sys-ftpd (started at boot): https://github.com/jakibaki/sys-ftpd

libnx: https://github.com/switchbrew/libnx

Tesla overlay: https://gbatemp.net/threads/tesla-the-nintendo-switch-overlay-menu.557362/

Tesla-based helper to manage IP configuration for LANPlay and XLink Kai: https://github.com/matteofo/LANHelper-Tesla

ImGUI library: https://github.com/ocornut/imgui

Plutonium SDL2 GUI library: https://github.com/XorTroll/Plutonium

ReSwitched SwIPC docs: https://reswitched.github.io/SwIPC/


## Open questions

- Biggest question right now is if it is possible to implement a custom network device and driver and tweak routing on demand to enable VPN functionality.
- Another question is whether the wireguard runtime has a small-enough system footprint that it can stay running as a sysmodule all the time.
