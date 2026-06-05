#pragma once

#include "wgnx/config.hpp"
#include "wgnx/platform/clock.hpp"
#include "wgnx/platform/udp.hpp"

#include "wireguard/handshake.hpp"
#include "wireguard/session.hpp"
#include "wireguard/timers.hpp"

#include <cstdint>

namespace wgnx::wireguard {

/*
 * Deviation from Linux:
 * This peer skeleton keeps only the ownership and state fields Milestone 4
 * needs and does not yet model queues, cryptographic key material, or packet
 * processing internals. The implication is that Milestone 5/6 can extend this
 * object in-place, but it is not yet a drop-in equivalent of upstream
 * `wg_peer`.
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
    noise_handshake handshake{};
    wg_timers timers{};
    noise_keypair current_keypair{};
    noise_keypair next_keypair{};
    noise_keypair previous_keypair{};
};

void wg_peer_init_from_config(wg_peer *peer, const wgnx::PeerConfigEntry &config);
void wg_peer_set_resolved_endpoint(
    wg_peer *peer,
    const wgnx::platform::endpoint &endpoint,
    const char *endpoint_text);
void wg_peer_clear_resolved_endpoint(wg_peer *peer);
void wg_peer_reset_keypairs(wg_peer *peer);

} // namespace wgnx::wireguard
