#include "logger.hpp"

#include "wgnx/platform/clock.hpp"
#include "wgnx/platform/random.hpp"

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <random>

namespace {

std::atomic<wgnx::platform::ktime_t> g_fake_time_ns{1};

} // namespace

namespace ams::crypto {

void ClearMemory(void *mem, std::size_t size) {
    volatile auto *bytes = static_cast<volatile unsigned char *>(mem);
    while (size-- != 0) {
        *bytes++ = 0;
    }
}

bool IsSameBytes(const void *lhs, const void *rhs, std::size_t size) {
    const auto *a = static_cast<const unsigned char *>(lhs);
    const auto *b = static_cast<const unsigned char *>(rhs);
    unsigned char diff = 0;
    for (std::size_t i = 0; i < size; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

} // namespace ams::crypto

namespace wgnx::platform {

ktime_t ktime_get_coarse_boottime_ns() {
    return g_fake_time_ns.fetch_add(1'000'000, std::memory_order_relaxed);
}

void ktime_get_real_ts64(timespec64 *ts) {
    if (ts == nullptr) {
        return;
    }

    const ktime_t now = ktime_get_coarse_boottime_ns();
    ts->tv_sec = now / NSEC_PER_SEC;
    ts->tv_nsec = now % NSEC_PER_SEC;
}

void get_random_bytes(void *dst, std::size_t size) {
    static std::mt19937_64 rng{0x57474E5854455354ULL};
    auto *bytes = static_cast<unsigned char *>(dst);
    for (std::size_t i = 0; i < size; ++i) {
        bytes[i] = static_cast<unsigned char>(rng() & 0xffU);
    }
}

std::uint32_t get_random_u32() {
    std::uint32_t value = 0;
    get_random_bytes(&value, sizeof(value));
    return value;
}

std::uint32_t get_random_u32_below(std::uint32_t ceil) {
    if (ceil == 0) {
        return 0;
    }

    return get_random_u32() % ceil;
}

} // namespace wgnx::platform

namespace wgnx::sysmodule::logger {

void Initialize() {
}

void Log(const char *fmt, ...) {
    std::va_list args;
    va_start(args, fmt);
    std::vfprintf(stderr, fmt, args);
    std::fputc('\n', stderr);
    va_end(args);
}

} // namespace wgnx::sysmodule::logger
