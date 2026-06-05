#include "wireguard/handshake.hpp"

#include "logger.hpp"

namespace wgnx::wireguard {

const char *GetHandshakeStateName(HandshakeState state) {
    switch (state) {
        case HandshakeState::Zeroed:
            return "zeroed";
        case HandshakeState::InitiationCreated:
            return "initiation_created";
        case HandshakeState::InitiationReceived:
            return "initiation_received";
        case HandshakeState::ResponseCreated:
            return "response_created";
        case HandshakeState::ResponseReceived:
            return "response_received";
        case HandshakeState::SessionDerived:
            return "session_derived";
        case HandshakeState::Failed:
            return "failed";
    }

    return "unknown";
}

void noise_handshake_init(noise_handshake *handshake) {
    if (handshake == nullptr) {
        return;
    }

    *handshake = {};
    handshake->state = HandshakeState::Zeroed;
    handshake->last_transition_ns = wgnx::platform::ktime_get_coarse_boottime_ns();
}

bool noise_handshake_transition(
    noise_handshake *handshake,
    HandshakeState new_state,
    const char *peer_name,
    const char *reason) {
    if (handshake == nullptr) {
        return false;
    }

    const HandshakeState old_state = handshake->state;
    handshake->state = new_state;
    handshake->last_transition_ns = wgnx::platform::ktime_get_coarse_boottime_ns();
    ++handshake->transition_count;

    wgnx::sysmodule::logger::Log(
        "WG handshake peer='%s' %s -> %s reason='%s' local=0x%08x remote=0x%08x transitions=%u",
        peer_name != nullptr ? peer_name : "<unnamed>",
        GetHandshakeStateName(old_state),
        GetHandshakeStateName(new_state),
        reason != nullptr ? reason : "none",
        handshake->local_index,
        handshake->remote_index,
        handshake->transition_count);
    return old_state != new_state;
}

void noise_handshake_set_local_index(noise_handshake *handshake, std::uint32_t local_index) {
    if (handshake == nullptr) {
        return;
    }

    handshake->local_index = local_index;
}

void noise_handshake_set_remote_index(noise_handshake *handshake, std::uint32_t remote_index) {
    if (handshake == nullptr) {
        return;
    }

    handshake->remote_index = remote_index;
}

} // namespace wgnx::wireguard
