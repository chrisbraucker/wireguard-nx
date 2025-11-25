# Preliminary documentation

Grabbed the project outline in part from the [switch-homebrew templates](https://github.com/switchbrew/switch-examples/tree/master/templates) and the open source [sys-clk project](https://github.com/retronx-team/sys-clk/tree/develop), as I want to use the IPC, overlay controls and manager software for my project likewise.

Other network-related stuff may be relevant in [ldn-mitm](https://github.com/spacemeowx2/ldn_mitm).

Wireguard Linux kernel driver: https://git.zx2c4.com/wireguard-linux/tree/drivers/net/wireguard/

ftpd: https://github.com/mtheall/ftpd

sys-ftpd (started at boot): https://github.com/jakibaki/sys-ftpd

libnx: https://github.com/switchbrew/libnx

Tesla overlay: https://gbatemp.net/threads/tesla-the-nintendo-switch-overlay-menu.557362/

## Questions

- Biggest question right now is if it is possible to implement a custom network device and driver and tweak routing on demand to enable VPN functionality.
- Another question is whether the wireguard runtime has a small-enough system footprint that it can stay running as a sysmodule all the time.
