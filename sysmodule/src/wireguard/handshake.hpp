#pragma once

#include "wireguard/messages.hpp"
#include "wireguard/session.hpp"

#include <cstdint>
#include <span>

namespace wgnx::wireguard {

struct wg_device;
struct wg_peer;
struct noise_keypair;

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
    MonotonicTimePoint last_transition{};
    std::array<std::uint8_t, TAI64NTimestampSize> last_initiation_timestamp{};
    MonotonicTimePoint last_initiation_consumption{};
    bool has_last_initiation_timestamp{false};
};

enum class HandshakePacketOutcome : std::uint8_t {
    Invalid = 0,
    InitiationConsumed = 1,
    ResponseConsumed = 2,
    CookieReplyConsumed = 3,
};

const char *GetHandshakeStateName(HandshakeState state);
const char *GetHandshakePacketOutcomeName(HandshakePacketOutcome outcome);

void noise_handshake_init(noise_handshake *handshake);
void noise_handshake_clear_transcript(wg_peer *peer);
bool noise_handshake_transition(
    noise_handshake *handshake,
    HandshakeState new_state,
    const char *peer_name,
    const char *reason);
void noise_handshake_set_local_index(noise_handshake *handshake, std::uint32_t local_index);
void noise_handshake_set_remote_index(noise_handshake *handshake, std::uint32_t remote_index);
bool noise_handshake_create_initiation(message_handshake_initiation *dst, wg_peer *peer);
bool noise_handshake_consume_initiation(const message_handshake_initiation *src, wg_peer *peer);
bool noise_handshake_create_response(message_handshake_response *dst, wg_peer *peer);
bool noise_handshake_consume_response(const message_handshake_response *src, const wg_device *device, wg_peer *peer);
bool noise_handshake_consume_cookie_reply(const message_handshake_cookie *src, const wg_device *device, wg_peer *peer);
bool noise_handshake_begin_session(wg_device *device, wg_peer *peer);
HandshakePacketOutcome noise_handshake_consume_incoming_packet(
    std::span<const std::uint8_t> packet,
    wg_device *device,
    wg_peer *peer);

} // namespace wgnx::wireguard
