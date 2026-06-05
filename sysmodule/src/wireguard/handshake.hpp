#pragma once

#include "wgnx/platform/clock.hpp"

#include <cstdint>

namespace wgnx::wireguard {

enum class HandshakeState : std::uint8_t {
    Zeroed = 0,
    InitiationCreated = 1,
    InitiationReceived = 2,
    ResponseCreated = 3,
    ResponseReceived = 4,
    SessionDerived = 5,
    Failed = 6,
};

struct noise_handshake {
    HandshakeState state{HandshakeState::Zeroed};
    std::uint32_t local_index{0};
    std::uint32_t remote_index{0};
    std::uint32_t transition_count{0};
    wgnx::platform::ktime_t last_transition_ns{0};
};

const char *GetHandshakeStateName(HandshakeState state);

void noise_handshake_init(noise_handshake *handshake);
bool noise_handshake_transition(
    noise_handshake *handshake,
    HandshakeState new_state,
    const char *peer_name,
    const char *reason);
void noise_handshake_set_local_index(noise_handshake *handshake, std::uint32_t local_index);
void noise_handshake_set_remote_index(noise_handshake *handshake, std::uint32_t remote_index);

} // namespace wgnx::wireguard
