#pragma once

#include "wireguard/timer_coordinator.hpp"

#include <array>
#include <cstddef>

namespace wgnx::sysmodule::runtime {

class TimerSchedule {
public:
    bool Arm(
        const wgnx::wireguard::TimerToken &token,
        wgnx::wireguard::TimerDeadline deadline);
    bool Cancel(const wgnx::wireguard::TimerToken &token);
    void Cancel(wgnx::wireguard::TimerHook hook);
    void CancelAll();

    bool CaptureExpiration(wgnx::wireguard::TimerHook hook);
    wgnx::wireguard::TimerToken TakeDelivery(wgnx::wireguard::TimerHook hook);

    bool IsArmed(wgnx::wireguard::TimerHook hook) const;
    wgnx::wireguard::TimerToken ArmedToken(wgnx::wireguard::TimerHook hook) const;
    wgnx::wireguard::TimerDeadline Deadline(wgnx::wireguard::TimerHook hook) const;

private:
    struct Slot {
        wgnx::wireguard::TimerToken armed_token{};
        wgnx::wireguard::TimerToken queued_token{};
        wgnx::wireguard::TimerDeadline deadline{};
        bool armed{false};
    };

    static constexpr std::size_t HookCount = 4;
    static std::size_t HookIndex(wgnx::wireguard::TimerHook hook);

    std::array<Slot, HookCount> m_slots{};
};

} // namespace wgnx::sysmodule::runtime
