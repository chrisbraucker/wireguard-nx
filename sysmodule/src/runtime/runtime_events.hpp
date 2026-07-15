#pragma once

#include "wgnx/platform/clock.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <variant>

namespace wgnx::sysmodule::runtime {

struct PeerIdentity {
    std::uint32_t peer_index{0};
    std::uint32_t activation_generation{0};
};

struct SessionEstablishedEvent {
    PeerIdentity peer{};
    wgnx::platform::ktime_t occurred_at{0};
};

using PeerEvent = std::variant<SessionEstablishedEvent>;

struct QueueInnerPacketSubmissionEffect {
    PeerIdentity peer{};
};

using RuntimeEffect = std::variant<QueueInnerPacketSubmissionEffect>;

class EffectBatch {
public:
    static constexpr std::size_t Capacity = 8;

    bool Push(const RuntimeEffect &effect) {
        if (m_size == m_effects.size()) {
            return false;
        }
        m_effects[m_size++] = effect;
        return true;
    }

    constexpr std::size_t Size() const { return m_size; }
    constexpr bool Empty() const { return m_size == 0; }
    constexpr const RuntimeEffect *begin() const { return m_effects.data(); }
    constexpr const RuntimeEffect *end() const { return m_effects.data() + m_size; }

private:
    std::array<RuntimeEffect, Capacity> m_effects{};
    std::size_t m_size{0};
};

inline PeerIdentity GetPeerIdentity(const PeerEvent &event) {
    return std::visit([](const auto &value) { return value.peer; }, event);
}

} // namespace wgnx::sysmodule::runtime
