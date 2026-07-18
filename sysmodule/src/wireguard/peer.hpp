#pragma once

#include "wireguard/handshake.hpp"
#include "wireguard/inner_packet.hpp"
#include "wireguard/messages.hpp"
#include "wireguard/session.hpp"
#include "wireguard/timers.hpp"

#include <cstdint>

namespace wgnx::wireguard {

constexpr inline std::size_t PeerNameCapacity = 32;
constexpr inline std::size_t PeerStagedPacketCapacity =
    wgnx::resource_budget::PacketQueueSlots;

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
    char name[PeerNameCapacity]{};
    std::uint16_t persistent_keepalive_interval{0};
    bool has_preshared_key{false};
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

struct PeerInitializationView {
    const char *name{nullptr};
    const noise_private_key *local_private_key{nullptr};
    const char *remote_public_key{nullptr};
    const noise_symmetric_key *preshared_key{nullptr};
    std::uint16_t persistent_keepalive_interval{0};
};

bool wg_peer_initialize(wg_peer *peer, const PeerInitializationView &config);
void wg_peer_reset_keypairs(wg_peer *peer);
OutboundStagingAction wg_peer_get_outbound_staging_action(
    const wg_peer &peer,
    MonotonicTimePoint now);
std::size_t wg_peer_clear_staged_outbound_packets(
    wg_peer *peer,
    QueueDisposition disposition = QueueDisposition::Cleared);
void wg_peer_clear_last_initiation(wg_peer *peer);
void wg_peer_begin_handshake_retry_sequence(wg_peer *peer);
HandshakeRetryTimeoutResult wg_peer_handle_handshake_retry_timeout(wg_peer *peer);
void wg_peer_complete_handshake_retry_sequence(wg_peer *peer);
void wg_peer_zero_key_material(wg_peer *peer);
void wg_peer_scrub_transient_state(wg_peer *peer);

} // namespace wgnx::wireguard
