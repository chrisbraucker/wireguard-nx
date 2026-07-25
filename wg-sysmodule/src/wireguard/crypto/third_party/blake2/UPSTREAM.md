# BLAKE2s Vendor Provenance

This directory contains the portable reference implementation of **BLAKE2s**
used by the WireGuard protocol. It is intentionally a narrow import: no BLAKE2b,
tree hashing, SIMD, test generator, or project build logic is included.

## Pinned Upstream

- Project: <https://github.com/BLAKE2/BLAKE2>
- Revision: `ed1974ea83433eba7b2d95c5dcd9ac33cb847913`
- Retrieved: 2026-07-24
- Algorithm variant: sequential BLAKE2s as specified by RFC 7693
- License selected: CC0 1.0 Universal, included verbatim as `COPYING`

Imported files and SHA-256 digests:

| File            | SHA-256                                                            |
|-----------------|--------------------------------------------------------------------|
| `blake2.h`      | `389bc87a83cdd9e25569a294d01a3347970d117237a66eee9df8edd6058736a4` |
| `blake2-impl.h` | `bc0ead7f3259a415325fa40ddebb1876f903d5062d888fc5994e8b2d9e616ec4` |
| `blake2s-ref.c` | `645fb0212db0d6e15a1568da210ac3f7123da1ab4330d4fc0e33312d742d569a` |
| `COPYING`       | `a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499` |

## Integration Boundary

Only `primitives.cpp` includes or calls the C API. `primitives.hpp` exposes the
move- and copy-disabled `Blake2sHasher` plus `std::span` input/output views.
The wrapper uses private, aligned opaque storage with compile-time size and
alignment checks against the pinned C state. It owns and clears that state after
finalization and on destruction; callers cannot access it or bypass lifecycle
checks.

The reference implementation is not modified. Project-specific validation,
state clearing, and C++ ownership behavior belong in the wrapper, never in
the vendored files.

## Refresh Procedure

1. Clone or update the upstream repository under the workspace-level external
   source directory: `workspace/repos/BLAKE2`.
2. Record the exact upstream commit, then copy only `ref/blake2.h`,
   `ref/blake2-impl.h`, `ref/blake2s-ref.c`, and upstream `COPYING` into this
   directory without edits.
3. Recalculate SHA-256 digests and update this file. Confirm the source header
   and copied license still permit the selected CC0 grant.
4. Review the upstream diff, the wrapper compatibility assumptions, and the
   target/host build rules. Do not adopt architecture-specific variants without
   a separate performance and portability review.
5. Run `make test`, `make test-sanitize`, `make test-warnings`, `make all`,
   `make check-stack`, and `make resource-report` from `wg-sysmodule/`. Compare
   BLAKE2s output against RFC 7693 and the official BLAKE2 KAT corpus, including
   keyed, unkeyed, incremental, and variable-digest cases.

Any vendor update is a cryptographic change: it requires a focused review and
the same host and on-device regression evidence as a protocol change.
