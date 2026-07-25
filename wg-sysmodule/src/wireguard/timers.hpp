#pragma once

#include "wireguard/constants.hpp"

#include <chrono>
#include <cstdint>

namespace wgnx::wireguard {

enum class TimerHook : std::uint8_t {
    RetransmitHandshake = 0,
    SendKeepalive = 1,
    NewHandshake = 2,
    ZeroKeyMaterial = 3,
    PersistentKeepalive = 4,
};

struct TimerClock {
    using rep = std::chrono::milliseconds::rep;
    using period = std::chrono::milliseconds::period;
    using duration = std::chrono::milliseconds;
    using time_point = std::chrono::time_point<TimerClock, duration>;
    static constexpr bool is_steady = true;
};

using TimerDeadline = TimerClock::time_point;
using TimerDelay = TimerClock::duration;

constexpr TimerDeadline TimerDeadlineFromJiffies(std::uint64_t value) {
    return TimerDeadline{TimerDelay{static_cast<TimerDelay::rep>(value)}};
}

constexpr std::uint64_t TimerDeadlineToJiffies(TimerDeadline value) {
    return static_cast<std::uint64_t>(value.time_since_epoch().count());
}

struct wg_timer_hook_state {
    bool pending{false};
    TimerDeadline deadline{};
};

// Protocol timer intent is platform-independent; Horizon execution is adapted
// through generation-checked TimerToken values in the runtime coordinator.
struct wg_timers {
    wg_timer_hook_state retransmit_handshake{};
    wg_timer_hook_state send_keepalive{};
    wg_timer_hook_state new_handshake{};
    wg_timer_hook_state zero_key_material{};
    wg_timer_hook_state persistent_keepalive{};
    bool need_another_keepalive{false};
};

const char* GetTimerHookName(TimerHook hook);

void wg_timers_init(wg_timers* timers);
void wg_timers_schedule(wg_timers* timers, TimerHook hook, TimerDeadline deadline, const char* peer_name);
void wg_timers_cancel(wg_timers* timers, TimerHook hook, const char* peer_name);
void wg_timers_cancel_all(wg_timers* timers, const char* peer_name);
bool wg_timers_any_pending(const wg_timers& timers);
constexpr TimerDelay GetHandshakeRetryDelay(std::uint32_t jitter_ms) {
    return std::chrono::duration_cast<TimerDelay>(RekeyTimeout) + std::chrono::milliseconds{jitter_ms % RekeyTimeoutJitterMaxMs};
}

} // namespace wgnx::wireguard
