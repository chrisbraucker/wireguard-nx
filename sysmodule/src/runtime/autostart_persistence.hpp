#pragma once

#include "runtime/domain_types.hpp"

#include "wgnx/protocol.hpp"

#include <array>
#include <cstdint>
#include <cstring>

namespace wgnx::sysmodule::runtime {

struct AutoStartPersistenceRequest {
    AutoStartRequestGeneration generation{};
    std::int32_t peer_index{-1};
    std::array<char, sizeof(wgnx::PeerInfo::name)> peer_name{};
};

// This state machine is intentionally platform-free. DaemonRuntime serializes
// filesystem work separately and uses this token to reject obsolete requests
// before and after a persistence attempt.
class AutoStartPersistenceState {
public:
    [[nodiscard]] AutoStartPersistenceRequest Begin(
        std::int32_t peer_index,
        const char *peer_name) {
        AutoStartPersistenceRequest request{
            .generation = AllocateGeneration(m_next_generation),
            .peer_index = peer_index,
        };
        if (peer_name != nullptr) {
            std::strncpy(
                request.peer_name.data(),
                peer_name,
                request.peer_name.size() - 1);
        }
        m_current_generation = request.generation;
        return request;
    }

    [[nodiscard]] bool IsCurrent(const AutoStartPersistenceRequest &request) const {
        return request.generation == m_current_generation;
    }

private:
    AutoStartRequestGeneration m_next_generation{1};
    AutoStartRequestGeneration m_current_generation{};
};

} // namespace wgnx::sysmodule::runtime
