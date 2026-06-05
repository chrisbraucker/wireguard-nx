#include "wireguard/timers.hpp"

#include "logger.hpp"

namespace wgnx::wireguard {

namespace {

wg_timer_hook_state *GetHookState(wg_timers *timers, TimerHook hook) {
    if (timers == nullptr) {
        return nullptr;
    }

    switch (hook) {
        case TimerHook::RetransmitHandshake:
            return &timers->retransmit_handshake;
        case TimerHook::SendKeepalive:
            return &timers->send_keepalive;
        case TimerHook::ZeroKeyMaterial:
            return &timers->zero_key_material;
        case TimerHook::Rekey:
            return &timers->rekey;
    }

    return nullptr;
}

const wg_timer_hook_state *GetHookState(const wg_timers *timers, TimerHook hook) {
    return GetHookState(const_cast<wg_timers *>(timers), hook);
}

} // namespace

const char *GetTimerHookName(TimerHook hook) {
    switch (hook) {
        case TimerHook::RetransmitHandshake:
            return "retransmit_handshake";
        case TimerHook::SendKeepalive:
            return "send_keepalive";
        case TimerHook::ZeroKeyMaterial:
            return "zero_key_material";
        case TimerHook::Rekey:
            return "rekey";
    }

    return "unknown";
}

void wg_timers_init(wg_timers *timers) {
    if (timers == nullptr) {
        return;
    }

    *timers = {};
}

void wg_timers_schedule(
    wg_timers *timers,
    TimerHook hook,
    wgnx::platform::jiffies_t expires,
    const char *peer_name) {
    wg_timer_hook_state *state = GetHookState(timers, hook);
    if (state == nullptr) {
        return;
    }

    state->pending = true;
    state->expires = expires;
    wgnx::sysmodule::logger::Log(
        "WG timer peer='%s' schedule hook=%s expires=%llu",
        peer_name != nullptr ? peer_name : "<unnamed>",
        GetTimerHookName(hook),
        static_cast<unsigned long long>(expires));
}

void wg_timers_cancel(wg_timers *timers, TimerHook hook, const char *peer_name) {
    wg_timer_hook_state *state = GetHookState(timers, hook);
    if (state == nullptr) {
        return;
    }

    if (!state->pending) {
        return;
    }

    state->pending = false;
    state->expires = 0;
    wgnx::sysmodule::logger::Log(
        "WG timer peer='%s' cancel hook=%s",
        peer_name != nullptr ? peer_name : "<unnamed>",
        GetTimerHookName(hook));
}

void wg_timers_cancel_all(wg_timers *timers, const char *peer_name) {
    if (timers == nullptr) {
        return;
    }

    wg_timers_cancel(timers, TimerHook::RetransmitHandshake, peer_name);
    wg_timers_cancel(timers, TimerHook::SendKeepalive, peer_name);
    wg_timers_cancel(timers, TimerHook::ZeroKeyMaterial, peer_name);
    wg_timers_cancel(timers, TimerHook::Rekey, peer_name);
}

bool wg_timers_any_pending(const wg_timers &timers) {
    return GetHookState(&timers, TimerHook::RetransmitHandshake)->pending ||
           GetHookState(&timers, TimerHook::SendKeepalive)->pending ||
           GetHookState(&timers, TimerHook::ZeroKeyMaterial)->pending ||
           GetHookState(&timers, TimerHook::Rekey)->pending;
}

} // namespace wgnx::wireguard
