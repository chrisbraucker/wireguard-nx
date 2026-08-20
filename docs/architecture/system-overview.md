# System Overview

WireGuard-NX makes a narrow set of Horizon BSD socket operations use an existing WireGuard tunnel without giving the BSD-facing process ownership of IP packets or WireGuard protocol state.
The implementation is deliberately split so Horizon service behavior, tunnel transport behavior, and cryptographic protocol behavior fail independently and have explicit ownership.

## Component Ownership

`mitm-sysmodule` owns Atmosphere `bsd:s` admission, retained BSD descriptors, visible BSD socket behavior, one-time route selection, and translation between supported BSD operations and private tunnel-flow IPC.
`wg-sysmodule` owns peer selection, WireGuard protocol state, encryption, outer UDP transport, virtual endpoint allocation, the userspace IP adapter, and complete inner IPv4 packets.
`manager` and `overlay` are control-plane clients and do not own traffic forwarding.
`nx-reversing.git/toolbox` and its public harness provide the controlled client and remote counterparty used by focused validation.

## Traffic Path

```text
Horizon BSD client
        |
        v
Atmosphere bsd:s MITM
        |
        +-- direct route --> retained Horizon BSD descriptor
        |
        `-- tunnel route --> bounded MITM worker
                                  |
                                  v
                            private wgnx:tun IPC
                                  |
                                  v
                    serialized WireGuard-owned IP adapter
                                  |
                                  v
                     complete inner IPv4 packet plane
                                  |
                                  v
                  WireGuard peer, encryption, and outer UDP
```

The MITM handles BSD operations and payload records rather than arbitrary IP packets.
The WireGuard sysmodule constructs, validates, fragments, reassembles, and demultiplexes inner IP traffic after it accepts a validated flow operation.
The WireGuard protocol core carries authenticated complete inner packets and does not know BSD descriptors, CMIF sessions, or lwIP types.

## Current Scope

The first transparent surface is configured-Toolbox-only connected IPv4 UDP and the documented connected IPv4 TCP subset.
Route selection occurs once at `connect()` and a selected descriptor never migrates between direct BSD and the tunnel.
Unsupported traffic continues through the retained BSD service only before a tunnel route is selected.
The detailed admission, operation, backpressure, and teardown contract is in [`bsd-mitm-traffic.md`](bsd-mitm-traffic.md).
