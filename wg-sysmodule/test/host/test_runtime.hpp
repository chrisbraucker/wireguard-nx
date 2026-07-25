#pragma once

#include "wgnx/platform/clock.hpp"

#include <cstdint>

namespace wgnx::test::runtime {

struct State {
    wgnx::platform::ktime_t monotonic_time_ns;
    wgnx::platform::timespec64 realtime;
    std::uint64_t random_state;
    std::uint64_t random_bytes_generated;
};

void Reset(const State& state);
void SetMonotonicTime(wgnx::platform::ktime_t time_ns);
void SetRealtime(const wgnx::platform::timespec64& time);
State GetState();

} // namespace wgnx::test::runtime
