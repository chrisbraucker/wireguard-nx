# WireGuard-NX Overlay

## Verification

Formatting and static-analysis checks remain enabled for first-party sources.
Clang-tidy is intentionally deferred because it must parse the included Tesla and Ultrahand headers, which currently produce target-specific Clang parser diagnostics outside this project's ownership.
Header filters cannot avoid those parser failures because dependency headers must be parsed before clang-tidy can analyze overlay translation units.
