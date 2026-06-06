#include "wireguard/debug_harness.hpp"

#include <cstdio>

int main() {
    const bool messages_ok = wgnx::wireguard::RunMessageSelfTest();
    const bool primitives_ok = wgnx::wireguard::RunPrimitiveSelfTest();
    const bool core_ok = wgnx::wireguard::RunCoreSelfTest();

    std::printf(
        "wireguard-host-tests: messages=%s primitives=%s core=%s\n",
        messages_ok ? "ok" : "fail",
        primitives_ok ? "ok" : "fail",
        core_ok ? "ok" : "fail");

    return (messages_ok && primitives_ok && core_ok) ? 0 : 1;
}
