# lwIP Vendor Provenance

This directory contains the unmodified lwIP source required by the Task 6 IPv4 and UDP adapter.
Project configuration, platform hooks, wrappers, and tests remain outside this directory.

## Pinned Upstream

- Project: <https://github.com/lwip-tcpip/lwip>
- Release: `STABLE-2_2_1_RELEASE`
- Annotated tag: `009c2256469004009488b3385ba269461e8eb616`
- Resolved commit: `77dcd25a72509eb83f72b033d219b1d40cd8eb95`
- Retrieved: 2026-08-02
- License: BSD-3-Clause, included verbatim as `COPYING`
- Source archive: <https://github.com/lwip-tcpip/lwip/archive/refs/tags/STABLE-2_2_1_RELEASE.tar.gz>
- Source archive SHA-256: `ce0b7461c0ad9602c376f0bf07c5eb7253b48c7bf66f011c6bf3e2a96731c539`

`SHA256SUMS` contains a SHA-256 value for each of the 182 imported upstream files.
It can be verified with `sha256sum -c SHA256SUMS` from this directory.

## Imported Source Set

The complete upstream `src/include/` tree is retained for reproducible headers and future checked feature expansion.
The selected core source set is `def.c`, `init.c`, `inet_chksum.c`, `ip.c`, `mem.c`, `memp.c`, `netif.c`, `pbuf.c`, `stats.c`, `tcp.c`, `tcp_in.c`, `tcp_out.c`, `timeouts.c`, `udp.c`, `ipv4/ip4.c`, `ipv4/ip4_addr.c`, and `ipv4/ip4_frag.c`.
`sys.c` is deliberately absent because the production adapter uses `NO_SYS=1`.
The repository attributes exempt only this directory from trailing-whitespace checks because the unmodified upstream files contain historical whitespace that fails the project's first-party whitespace policy.

## Refresh Procedure

1. Clone the requested release under `workspace/repos/` and verify that the release tag resolves to the recorded commit.
2. Download the release archive and record its SHA-256 value here.
3. Replace `COPYING`, the complete `src/include/` tree, and only the selected core sources without local edits.
4. Regenerate `SHA256SUMS` with `find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS`.
5. Review the upstream diff and run the complete Task 6 host, target, and device gate before accepting the update.

Any vendor update changes packet processing and requires the same review as a WireGuard protocol change.
