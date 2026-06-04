#pragma once

#include <cstdint>

namespace wgnx::platform {

using ktime_t = std::int64_t;

constexpr inline ktime_t NSEC_PER_SEC = 1000000000LL;

struct timespec64 {
    std::int64_t tv_sec;
    std::int64_t tv_nsec;
};

ktime_t ktime_get_coarse_boottime_ns();
void ktime_get_real_ts64(timespec64 *ts);

} // namespace wgnx::platform
