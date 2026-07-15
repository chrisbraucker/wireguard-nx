#pragma once

#include "wgnx/config.hpp"
#include "wgnx/platform/clock.hpp"
#include "wgnx/platform/udp.hpp"

#include "wireguard/handshake.hpp"
#include "wireguard/inner_packet.hpp"
#include "wireguard/messages.hpp"
#include "wireguard/session.hpp"
#include "wireguard/timers.hpp"

#include <cstdint>

namespace wgnx::wireguard {

constexpr inline std::size_t PeerStagedPacketCapacity = 8;

enum class OutboundStagingAction : std::uint8_t {
    Idle = 0,
    Send,
    InitiateHandshake,
};

enum class HandshakeRetryTimeoutAction : std::uint8_t {
    Ignore = 0,
    Retry,
    Exhausted,
};

struct HandshakeRetryTimeoutResult {
    HandshakeRetryTimeoutAction action{HandshakeRetryTimeoutAction::Ignore};
    std::size_t dropped_staged_packets{0};
};

struct HandshakeRetryState {
    bool active{false};
    std::uint32_t send_attempts{0};
    std::uint32_t sequence_count{0};
    std::uint32_t exhausted_sequence_count{0};
};

/*
 * The peer owns protocol identity, handshake and keypair state, timer intent,
 * and staged outbound packets. Horizon UDP transport and asynchronous work
 * dispatch remain runtime concerns outside this protocol object.
 */
struct wg_peer {
    char name[sizeof(wgnx::PeerInfo::name)]{};
    char allowed_ips[sizeof(wgnx::PeerConfigEntry::allowed_ips)]{};
    char endpoint_text[sizeof(wgnx::PeerInfo::endpoint)]{};
    char public_key[sizeof(wgnx::PeerConfigEntry::public_key)]{};
    char preshared_key[sizeof(wgnx::PeerConfigEntry::preshared_key)]{};
    char resolved_endpoint_text[sizeof(wgnx::PeerInfo::resolved_endpoint)]{};
    std::uint16_t persistent_keepalive_interval{0};
    bool has_preshared_key{false};
    bool has_resolved_endpoint{false};
    wgnx::platform::endpoint resolved_endpoint{};
    noise_static_identity static_identity{};
    noise_handshake_material handshake_material{};
    noise_cookie cookie{};
    noise_handshake handshake{};
    wg_timers timers{};
    noise_keypair current_keypair{};
    noise_keypair next_keypair{};
    noise_keypair previous_keypair{};
    InnerPacketQueue<PeerStagedPacketCapacity> staged_outbound_packets{};
    HandshakeRetryState handshake_retry{};
    // Retained only as the serialized boundary between creation and UDP send.
    message_handshake_initiation last_initiation{};
    bool has_last_initiation{false};
};

void wg_peer_init_from_config(wg_peer *peer, const wgnx::PeerConfigEntry &config);
bool wg_peer_prepare_static_identity(wg_peer *peer, const char *local_private_key_text);
void wg_peer_set_resolved_endpoint(
    wg_peer *peer,
    const wgnx::platform::endpoint &endpoint,
    const char *endpoint_text);
void wg_peer_clear_resolved_endpoint(wg_peer *peer);
void wg_peer_reset_keypairs(wg_peer *peer);
OutboundStagingAction wg_peer_get_outbound_staging_action(
    const wg_peer &peer,
    MonotonicTime now);
std::size_t wg_peer_clear_staged_outbound_packets(wg_peer *peer);
void wg_peer_clear_last_initiation(wg_peer *peer);
void wg_peer_begin_handshake_retry_sequence(wg_peer *peer);
HandshakeRetryTimeoutResult wg_peer_handle_handshake_retry_timeout(wg_peer *peer);
void wg_peer_complete_handshake_retry_sequence(wg_peer *peer);
void wg_peer_zero_key_material(wg_peer *peer);
void wg_peer_scrub_transient_state(wg_peer *peer);

} // namespace wgnx::wireguard
