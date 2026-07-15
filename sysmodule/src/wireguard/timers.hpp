#pragma once

#include "wgnx/platform/work.hpp"

#include <chrono>
#include <cstdint>

namespace wgnx::wireguard {

enum class TimerHook : std::uint8_t {
    RetransmitHandshake = 0,
    SendKeepalive = 1,
    ZeroKeyMaterial = 2,
    Rekey = 3,
};

using TimerDeadline = std::chrono::milliseconds;

constexpr TimerDeadline TimerDeadlineFromJiffies(wgnx::platform::jiffies_t value) {
    return TimerDeadline{value};
}

constexpr wgnx::platform::jiffies_t TimerDeadlineToJiffies(TimerDeadline value) {
    return static_cast<wgnx::platform::jiffies_t>(value.count());
}

struct wg_timer_hook_state {
    bool pending{false};
    TimerDeadline deadline{};
};

/*
 * Deviation from Linux:
 * This milestone tracks protocol timer intent and scheduling requests without
 * yet executing real callback behavior. The implication is that later
 * milestones can wire real timer actions onto these hooks without changing the
 * owning object model, but timer expiry itself is not protocol-real yet.
 */
struct wg_timers {
    wg_timer_hook_state retransmit_handshake{};
    wg_timer_hook_state send_keepalive{};
    wg_timer_hook_state zero_key_material{};
    wg_timer_hook_state rekey{};
};

const char *GetTimerHookName(TimerHook hook);

void wg_timers_init(wg_timers *timers);
void wg_timers_schedule(
    wg_timers *timers,
    TimerHook hook,
    TimerDeadline deadline,
    const char *peer_name);
void wg_timers_cancel(wg_timers *timers, TimerHook hook, const char *peer_name);
void wg_timers_cancel_all(wg_timers *timers, const char *peer_name);
bool wg_timers_any_pending(const wg_timers &timers);

} // namespace wgnx::wireguard
