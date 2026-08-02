#include "ip/lwip_platform.hpp"

#include "wgnx/platform/clock.hpp"

#include <lwip/arch.h>

namespace wgnx::sysmodule::ip {

namespace {

std::uint32_t g_host_time_ms{};

} // namespace

void SetLwipHostTimeForTests(std::uint32_t now_ms) {
    g_host_time_ms = now_ms;
}

} // namespace wgnx::sysmodule::ip

extern "C" u32_t sys_now() {
#if defined(__SWITCH__)
    return static_cast<u32_t>(wgnx::platform::ktime_get_coarse_boottime_ns() / 1'000'000);
#else
    return static_cast<u32_t>(wgnx::sysmodule::ip::g_host_time_ms);
#endif
}
