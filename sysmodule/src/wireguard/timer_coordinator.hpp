#pragma once

#include "wireguard/timers.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace wgnx::wireguard {

struct TimerOwner {
    std::uint32_t peer_index{0};
    std::uint32_t activation_generation{0};
    std::uint32_t protocol_sequence{0};

    friend constexpr bool operator==(const TimerOwner &, const TimerOwner &) = default;
};

struct TimerToken {
    TimerHook hook{TimerHook::RetransmitHandshake};
    TimerOwner owner{};
    std::uint32_t generation{0};

    constexpr bool IsValid() const { return generation != 0; }
    friend constexpr bool operator==(const TimerToken &, const TimerToken &) = default;
};

class TimerCoordinator {
public:
    TimerToken Arm(TimerHook hook, TimerOwner owner);
    void Cancel(TimerHook hook);
    void CancelAll();
    bool IsCurrent(const TimerToken &token, TimerOwner current_owner) const;
    bool IsArmed(TimerHook hook) const;

private:
    struct HookState {
        TimerToken token{};
        bool armed{false};
    };

    static constexpr std::size_t HookCount = 4;
    static std::size_t HookIndex(TimerHook hook);
    std::uint32_t NextGeneration();

    std::array<HookState, HookCount> m_hooks{};
    std::uint32_t m_next_generation{1};
};

} // namespace wgnx::wireguard
