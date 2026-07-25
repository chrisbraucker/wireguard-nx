#pragma once

#include "wgnx/platform/clock.hpp"
#include "wgnx/platform/random.hpp"
#include "wgnx/platform/work.hpp"
#include "wireguard/timers.hpp"

#include <cstdint>

namespace wgnx::sysmodule::runtime {

// Platform adapters sample time and entropy once. Peer policy decides how to
// reduce entropy and use those facts when it creates protocol timer effects.
struct TimerFacts {
    wgnx::wireguard::TimerDeadline now{};
    std::uint32_t random_u32{0};
};

inline TimerFacts CaptureTimerFacts() {
    return {
        .now = wgnx::wireguard::TimerDeadlineFromJiffies(wgnx::platform::get_jiffies_64()),
        .random_u32 = wgnx::platform::get_random_u32(),
    };
}

} // namespace wgnx::sysmodule::runtime
