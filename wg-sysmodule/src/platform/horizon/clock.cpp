#include "wgnx/platform/clock.hpp"

#include <stratosphere.hpp>

namespace wgnx::platform {

namespace {

constinit bool g_time_initialized = false;
ams::os::SdkMutex g_time_initialize_mutex;

void SetFallbackMonotonicTime(timespec64* ts) {
    const ktime_t ns = ktime_get_coarse_boottime_ns();
    ts->tv_sec = ns / NSEC_PER_SEC;
    ts->tv_nsec = ns % NSEC_PER_SEC;
}

bool EnsureTimeInitialized() {
    if (AMS_LIKELY(g_time_initialized)) {
        return true;
    }

    std::scoped_lock lk(g_time_initialize_mutex);
    if (AMS_UNLIKELY(!g_time_initialized)) {
        if (R_FAILED(ams::time::Initialize())) {
            return false;
        }
        g_time_initialized = true;
    }

    return true;
}

} // namespace

ktime_t ktime_get_coarse_boottime_ns() {
    return ams::os::GetSystemTick().ToTimeSpan().GetNanoSeconds();
}

void ktime_get_real_ts64(timespec64* ts) {
    if (ts == nullptr) {
        return;
    }

    /*
     * Deviation from Linux:
     * We use Atmosphere's time wrapper here instead of calling a raw libnx
     * time service API directly from this shim. The implication is that time
     * service mode selection and initialization stay aligned with the broader
     * Atmosphere runtime surface already used by the sysmodule.
     */
    if (EnsureTimeInitialized()) {
        ams::time::PosixTime current_time{};
        if (R_SUCCEEDED(ams::time::StandardUserSystemClock::GetCurrentTime(std::addressof(current_time))) && current_time.value > 0) {
            ts->tv_sec = static_cast<std::int64_t>(current_time.value);
            ts->tv_nsec = 0;
            return;
        }
    }

    SetFallbackMonotonicTime(ts);
}

} // namespace wgnx::platform
