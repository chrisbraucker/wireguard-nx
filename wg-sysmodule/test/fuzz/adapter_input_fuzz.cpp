#include "ip/lwip_platform.hpp"
#include "ip/userspace_ip_adapter.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace wgnx::sysmodule::ip;

    static UserspaceIpAdapter adapter{};
    constexpr std::array<std::uint8_t, 4> Local = {10, 13, 13, 8};
    constexpr UserspaceIpFlow Flow{
        .token = 1,
        .local = {.address = {10, 13, 13, 8}, .port = 49152, .reserved = 0},
        .remote = {.address = {10, 251, 0, 2}, .port = 29000, .reserved = 0},
    };

    adapter.Reset();
    SetLwipHostTimeForTests(static_cast<std::uint32_t>(size));
    if (adapter.Initialize(Local, 576) && adapter.OpenFlow(Flow) == UserspaceIpResult::Success) {
        static_cast<void>(adapter.Input(std::span<const std::uint8_t>(data, std::min(size, wgnx::MaxInnerIpv4PacketSize))));
        adapter.RunTimeouts();
    }
    adapter.Reset();
    return 0;
}
