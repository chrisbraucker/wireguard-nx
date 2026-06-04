#include "wgnx/platform/clock.hpp"

#include <switch/services/time.h>

#include <stratosphere.hpp>

namespace wgnx::platform {

namespace {

constinit bool g_time_initialized = false;
constinit bool g_time_available = false;
ams::os::Mutex g_time_mutex(false);

void SetFallbackMonotonicTime(timespec64 *ts) {
    const ktime_t ns = ktime_get_coarse_boottime_ns();
    ts->tv_sec = ns / NSEC_PER_SEC;
    ts->tv_nsec = ns % NSEC_PER_SEC;
}

bool EnsureTimeInitialized() {
    std::scoped_lock lock(g_time_mutex);
    if (!g_time_initialized) {
        g_time_available = R_SUCCEEDED(::timeInitialize());
        g_time_initialized = true;
    }

    return g_time_available;
}

} // namespace

ktime_t ktime_get_coarse_boottime_ns() {
    return ams::os::GetSystemTick().ToTimeSpan().GetNanoSeconds();
}

void ktime_get_real_ts64(timespec64 *ts) {
    if (ts == nullptr) {
        return;
    }

    /*
     * Deviation from Linux:
     * The preferred source is the Horizon user system clock. If that service is
     * unavailable in this sysmodule context, we fall back to monotonic boot
     * time. The implication is that ordering remains correct, but the fallback
     * is not a real wall clock for user-facing timestamps.
     */
    if (EnsureTimeInitialized()) {
        u64 posix_seconds = 0;
        if (R_SUCCEEDED(::timeGetCurrentTime(TimeType_UserSystemClock, std::addressof(posix_seconds)))) {
            ts->tv_sec = static_cast<std::int64_t>(posix_seconds);
            ts->tv_nsec = 0;
            return;
        }
    }

    SetFallbackMonotonicTime(ts);
}

} // namespace wgnx::platform
