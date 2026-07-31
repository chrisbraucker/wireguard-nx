#pragma once

#include "wireguard/messages.hpp"
#include "wireguard/session.hpp"
#include "wgnx/platform/udp.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace wgnx::wireguard {

struct wg_device;
struct wg_peer;

struct HandshakeRateLimitEntry {
    wgnx::platform::address_family family{wgnx::platform::address_family::unspecified};
    std::array<std::uint8_t, 16> address{};
    MonotonicTimePoint last_update{};
    std::int64_t tokens{0};
    bool active{false};
    bool initialized{false};
};

struct ResponderCookieState {
    noise_secret32 secret{};
    MonotonicTimePoint secret_birth{};
    MonotonicTimePoint arrival_last_update{};
    MonotonicTimePoint under_load_until{};
    std::int64_t arrival_tokens{0};
    bool arrival_initialized{false};
    std::array<HandshakeRateLimitEntry, HandshakeRateLimitSlots> rate_limits{};
};

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

enum class ResponderHandshakeAdmission : std::uint8_t {
    Accepted = 0,
    CookieReply,
    RateLimited,
    Invalid,
};

const char* GetHandshakeStateName(HandshakeState state);
const char* GetHandshakePacketOutcomeName(HandshakePacketOutcome outcome);
const char* GetResponderHandshakeAdmissionName(ResponderHandshakeAdmission admission);

void noise_handshake_init(noise_handshake* handshake);
void noise_handshake_clear_transcript(wg_peer* peer);
bool noise_handshake_transition(noise_handshake* handshake, HandshakeState new_state, const char* peer_name, const char* reason);
void noise_handshake_set_local_index(noise_handshake* handshake, std::uint32_t local_index);
void noise_handshake_set_remote_index(noise_handshake* handshake, std::uint32_t remote_index);
bool noise_handshake_create_initiation(message_handshake_initiation* dst, wg_peer* peer);
bool noise_handshake_consume_initiation(const message_handshake_initiation* src, wg_peer* peer);
bool noise_handshake_create_response(message_handshake_response* dst, wg_peer* peer);
bool noise_handshake_consume_response(const message_handshake_response* src, const wg_device* device, wg_peer* peer);
bool noise_handshake_consume_cookie_reply(const message_handshake_cookie* src, const wg_device* device, wg_peer* peer);
bool noise_handshake_begin_session(wg_device* device, wg_peer* peer);
HandshakePacketOutcome noise_handshake_consume_incoming_packet(std::span<const std::uint8_t> packet, wg_device* device, wg_peer* peer);
ResponderHandshakeAdmission noise_handshake_admit_responder_packet(
    wg_device* device,
    std::span<const std::uint8_t> packet,
    const wgnx::platform::endpoint& source,
    MonotonicTimePoint now,
    message_handshake_cookie* out_cookie
);

} // namespace wgnx::wireguard
