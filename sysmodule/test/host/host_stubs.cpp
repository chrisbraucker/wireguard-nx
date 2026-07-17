#include "logger.hpp"

#include "wgnx/platform/clock.hpp"
#include "wgnx/platform/random.hpp"
#include "wgnx/platform/udp.hpp"

#include "test_runtime.hpp"

#include <atomic>
#include <cstring>

namespace {

std::atomic<wgnx::platform::ktime_t> g_monotonic_time_ns{1};
std::atomic<std::int64_t> g_realtime_seconds{0};
std::atomic<std::int64_t> g_realtime_nanoseconds{0};
std::atomic<std::uint64_t> g_random_state{0};
std::atomic<std::uint64_t> g_random_bytes_generated{0};

std::uint64_t NextRandom() {
    std::uint64_t value = g_random_state.fetch_add(0x9E3779B97F4A7C15ULL) +
                          0x9E3779B97F4A7C15ULL;
    value = (value ^ (value >> 30U)) * 0xBF58476D1CE4E5B9ULL;
    value = (value ^ (value >> 27U)) * 0x94D049BB133111EBULL;
    return value ^ (value >> 31U);
}

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
    return g_monotonic_time_ns.load(std::memory_order_relaxed);
}

void ktime_get_real_ts64(timespec64 *ts) {
    if (ts == nullptr) {
        return;
    }

    ts->tv_sec = g_realtime_seconds.load(std::memory_order_relaxed);
    ts->tv_nsec = g_realtime_nanoseconds.load(std::memory_order_relaxed);
}

void get_random_bytes(void *dst, std::size_t size) {
    auto *bytes = static_cast<unsigned char *>(dst);
    std::size_t offset = 0;
    while (offset < size) {
        std::uint64_t value = NextRandom();
        for (std::size_t i = 0; i < sizeof(value) && offset < size; ++i, ++offset) {
            bytes[offset] = static_cast<unsigned char>(value & 0xffU);
            value >>= 8U;
        }
    }
    g_random_bytes_generated.fetch_add(size, std::memory_order_relaxed);
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

socket_error udp_open(socket_handle *out_socket, address_family family) {
    if (out_socket == nullptr || family == address_family::unspecified) {
        return socket_error::invalid_endpoint;
    }
    *out_socket = 1;
    return socket_error::none;
}

void udp_close(socket_handle socket) {
    static_cast<void>(socket);
}

socket_error udp_send(
    socket_handle socket,
    const endpoint &destination,
    std::span<const std::uint8_t> data,
    std::size_t *out_sent) {
    if (socket == InvalidSocket || destination.family == address_family::unspecified ||
        out_sent == nullptr) {
        return socket_error::send_failed;
    }
    *out_sent = data.size();
    return socket_error::none;
}

udp_receive_result udp_receive(
    socket_handle socket,
    std::span<std::uint8_t> buffer) {
    static_cast<void>(buffer);
    if (socket == InvalidSocket) {
        return {
            .disposition = udp_receive_disposition::failure,
            .native_condition = udp_receive_native_condition::other,
            .error = socket_error::receive_failed,
        };
    }
    return classify_udp_receive_result(
        -1,
        udp_receive_native_condition::timed_out,
        0);
}

} // namespace wgnx::platform

namespace wgnx::test::runtime {

void Reset(const State &state) {
    g_monotonic_time_ns.store(state.monotonic_time_ns, std::memory_order_relaxed);
    g_realtime_seconds.store(state.realtime.tv_sec, std::memory_order_relaxed);
    g_realtime_nanoseconds.store(state.realtime.tv_nsec, std::memory_order_relaxed);
    g_random_state.store(state.random_state, std::memory_order_relaxed);
    g_random_bytes_generated.store(state.random_bytes_generated, std::memory_order_relaxed);
}

void SetMonotonicTime(wgnx::platform::ktime_t time_ns) {
    g_monotonic_time_ns.store(time_ns, std::memory_order_relaxed);
}

void SetRealtime(const wgnx::platform::timespec64 &time) {
    g_realtime_seconds.store(time.tv_sec, std::memory_order_relaxed);
    g_realtime_nanoseconds.store(time.tv_nsec, std::memory_order_relaxed);
}

State GetState() {
    return {
        .monotonic_time_ns = g_monotonic_time_ns.load(std::memory_order_relaxed),
        .realtime = {
            .tv_sec = g_realtime_seconds.load(std::memory_order_relaxed),
            .tv_nsec = g_realtime_nanoseconds.load(std::memory_order_relaxed),
        },
        .random_state = g_random_state.load(std::memory_order_relaxed),
        .random_bytes_generated = g_random_bytes_generated.load(std::memory_order_relaxed),
    };
}

} // namespace wgnx::test::runtime

namespace wgnx::sysmodule::logger {

void Initialize() {
}

void Log(const char *fmt, ...) {
    static_cast<void>(fmt);
}

} // namespace wgnx::sysmodule::logger
