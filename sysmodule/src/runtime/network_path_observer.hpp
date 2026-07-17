#pragma once

#include "wgnx/platform/udp.hpp"

#include <cstdint>

namespace wgnx::sysmodule::runtime {

struct NetworkPathObservedEvent {
    std::uint64_t sequence{0};
    wgnx::platform::NetworkPathSnapshot snapshot{};
};

struct NetworkPathObservationOutcome {
    std::uint64_t sequence{0};
    bool changed{false};
};

class NetworkPathObserver {
public:
    std::uint64_t BeginObservation();
    NetworkPathObservationOutcome Commit(const NetworkPathObservedEvent &event);
    bool HasObservation() const { return m_has_last; }
    const wgnx::platform::NetworkPathSnapshot &LastObservation() const { return m_last; }

private:
    wgnx::platform::NetworkPathSnapshot m_last{};
    std::uint64_t m_next_sequence{1};
    bool m_has_last{false};
};

} // namespace wgnx::sysmodule::runtime
