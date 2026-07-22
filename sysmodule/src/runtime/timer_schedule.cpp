#include "runtime/timer_schedule.hpp"

namespace wgnx::sysmodule::runtime {

std::size_t TimerSchedule::HookIndex(wgnx::wireguard::TimerHook hook) {
    switch (hook) {
        case wgnx::wireguard::TimerHook::RetransmitHandshake: return 0;
        case wgnx::wireguard::TimerHook::SendKeepalive: return 1;
        case wgnx::wireguard::TimerHook::NewHandshake: return 2;
        case wgnx::wireguard::TimerHook::ZeroKeyMaterial: return 3;
        case wgnx::wireguard::TimerHook::PersistentKeepalive: return 4;
    }
    return 0;
}

bool TimerSchedule::Arm(
    const wgnx::wireguard::TimerToken &token,
    wgnx::wireguard::TimerDeadline deadline) {
    if (!token.IsValid()) {
        return false;
    }

    Slot &slot = m_slots[HookIndex(token.hook)];
    slot.armed_token = token;
    slot.deadline = deadline;
    slot.armed = true;
    return true;
}

bool TimerSchedule::Cancel(const wgnx::wireguard::TimerToken &token) {
    if (!token.IsValid()) {
        return false;
    }
    Slot &slot = m_slots[HookIndex(token.hook)];
    if (!slot.armed || slot.armed_token != token) {
        return false;
    }
    Cancel(token.hook);
    return true;
}

void TimerSchedule::Cancel(wgnx::wireguard::TimerHook hook) {
    Slot &slot = m_slots[HookIndex(hook)];
    slot.armed_token = {};
    slot.deadline = {};
    slot.armed = false;
}

void TimerSchedule::CancelAll() {
    for (auto &slot : m_slots) {
        slot.armed_token = {};
        slot.deadline = {};
        slot.armed = false;
    }
}

bool TimerSchedule::CaptureExpiration(wgnx::wireguard::TimerHook hook) {
    Slot &slot = m_slots[HookIndex(hook)];
    if (!slot.armed) {
        return false;
    }

    slot.queued_token = slot.armed_token;
    slot.armed_token = {};
    slot.deadline = {};
    slot.armed = false;
    return true;
}

wgnx::wireguard::TimerToken TimerSchedule::TakeDelivery(
    wgnx::wireguard::TimerHook hook) {
    Slot &slot = m_slots[HookIndex(hook)];
    const auto token = slot.queued_token;
    slot.queued_token = {};
    return token;
}

bool TimerSchedule::IsArmed(wgnx::wireguard::TimerHook hook) const {
    return m_slots[HookIndex(hook)].armed;
}

wgnx::wireguard::TimerToken TimerSchedule::ArmedToken(
    wgnx::wireguard::TimerHook hook) const {
    return m_slots[HookIndex(hook)].armed_token;
}

wgnx::wireguard::TimerDeadline TimerSchedule::Deadline(
    wgnx::wireguard::TimerHook hook) const {
    return m_slots[HookIndex(hook)].deadline;
}

} // namespace wgnx::sysmodule::runtime
