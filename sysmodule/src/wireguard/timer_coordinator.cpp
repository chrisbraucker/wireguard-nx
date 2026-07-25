#include "wireguard/timer_coordinator.hpp"

#include <limits>

namespace wgnx::wireguard {

std::size_t TimerCoordinator::HookIndex(TimerHook hook) {
    switch (hook) {
    case TimerHook::RetransmitHandshake:
        return 0;
    case TimerHook::SendKeepalive:
        return 1;
    case TimerHook::NewHandshake:
        return 2;
    case TimerHook::ZeroKeyMaterial:
        return 3;
    case TimerHook::PersistentKeepalive:
        return 4;
    }
    return 0;
}

std::uint32_t TimerCoordinator::NextGeneration() {
    const std::uint32_t generation = m_next_generation;
    ++m_next_generation;
    if (m_next_generation == 0) {
        m_next_generation = 1;
    }
    return generation == 0 ? NextGeneration() : generation;
}

TimerToken TimerCoordinator::Arm(TimerHook hook, TimerOwner owner) {
    HookState& state = m_hooks[HookIndex(hook)];
    state.token = {
        .hook = hook,
        .owner = owner,
        .generation = NextGeneration(),
    };
    state.armed = true;
    return state.token;
}

TimerToken TimerCoordinator::Cancel(TimerHook hook) {
    HookState& state = m_hooks[HookIndex(hook)];
    const TimerToken canceled = state.armed ? state.token : TimerToken{};
    state = {};
    static_cast<void>(NextGeneration());
    return canceled;
}

void TimerCoordinator::CancelAll() {
    for (std::size_t i = 0; i < HookCount; ++i) {
        m_hooks[i] = {};
    }
    static_cast<void>(NextGeneration());
}

bool TimerCoordinator::IsCurrent(const TimerToken& token, TimerOwner current_owner) const {
    if (!token.IsValid() || token.owner != current_owner) {
        return false;
    }
    const HookState& state = m_hooks[HookIndex(token.hook)];
    return state.armed && state.token == token;
}

bool TimerCoordinator::IsArmed(TimerHook hook) const {
    return m_hooks[HookIndex(hook)].armed;
}

} // namespace wgnx::wireguard
