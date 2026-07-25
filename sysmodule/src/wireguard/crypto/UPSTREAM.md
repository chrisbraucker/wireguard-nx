# Cryptographic Backend Provenance

`primitives.cpp` is the only project-owned bridge from C++ protocol code to the low-level cryptographic implementations.
Its public interface uses spans and fixed-size arrays.
Raw pointers are confined to this translation unit when calling a backend.

## Monocypher

`monocypher.c` and `monocypher.h` are the vendored Monocypher source marked by upstream as revision `2c663c1` from <https://github.com/LoupVaillant/Monocypher>.
The upstream file headers state the dual BSD-2-Clause/CC0 licensing model; this project relies on the CC0 grant, consistent with the existing vendor headers.

The retained backend is intentional.
It supplies ChaCha20, Poly1305, ChaCha20-Poly1305, XChaCha20-Poly1305, and X25519, which are the narrow WireGuard primitive set used by this sysmodule.
`primitives.cpp` validates span-size contracts, clears transient AEAD contexts, and rejects all-zero X25519 shared secrets before protocol code can consume them.

Refresh procedure:

1. Obtain an upstream Monocypher release or pinned revision and review its changelog, API compatibility, and license headers.
2. Replace both source files as one audited update; do not edit their bodies locally.
3. Record the upstream revision and SHA-256 digests below.
4. Run `make verify`, `make fuzz-run`, and real-peer regression before merging.

Current integrity digests:

| File           | SHA-256                                                            |
|----------------|--------------------------------------------------------------------|
| `monocypher.c` | `dc1fe0a8132643c026b8463d073e8f816a2aba8ca872fc2c3e7bb2ef67808925` |
| `monocypher.h` | `5737d43e4054343ae650c0cf58ce690ee9f1f6a6ef4d4c8b25edefb380ab778e` |

## BLAKE2s

BLAKE2s uses the independent portable reference implementation documented in [`third_party/blake2/UPSTREAM.md`](third_party/blake2/UPSTREAM.md).
It is kept separate because it is a distinct upstream project and has its own refresh procedure and integrity manifest.
