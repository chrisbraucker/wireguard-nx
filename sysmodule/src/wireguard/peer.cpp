#include "wireguard/peer.hpp"

#include "wireguard/crypto/primitives.hpp"

#include "logger.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string_view>

namespace wgnx::wireguard {

void wg_peer_init_from_config(wg_peer *peer, const wgnx::PeerConfigEntry &config) {
    if (peer == nullptr) {
        return;
    }

    *peer = {};
    std::snprintf(peer->name, sizeof(peer->name), "%s", config.name);
    std::snprintf(peer->allowed_ips, sizeof(peer->allowed_ips), "%s", config.allowed_ips);
    std::snprintf(peer->endpoint_text, sizeof(peer->endpoint_text), "%s", config.endpoint);
    std::snprintf(peer->public_key, sizeof(peer->public_key), "%s", config.public_key);
    std::snprintf(peer->preshared_key, sizeof(peer->preshared_key), "%s", config.preshared_key);
    peer->persistent_keepalive_interval = config.persistent_keepalive;
    peer->has_preshared_key = config.preshared_key[0] != '\0';
    noise_static_identity_reset(&peer->static_identity);
    noise_handshake_material_reset(&peer->handshake_material);
    noise_cookie_reset(&peer->cookie);
    noise_handshake_init(&peer->handshake);
    wg_timers_init(&peer->timers);
    wg_peer_reset_keypairs(peer);
    wg_peer_clear_last_initiation(peer);
}

bool wg_peer_prepare_static_identity(wg_peer *peer, std::string_view local_private_key_text) {
    if (peer == nullptr) {
        return false;
    }

    noise_static_identity_reset(&peer->static_identity);
    noise_handshake_material_reset(&peer->handshake_material);
    if (!noise_static_identity_init(
            &peer->static_identity,
            local_private_key_text,
            peer->public_key,
            peer->preshared_key)) {
        wgnx::sysmodule::logger::Log("WG peer '%s': invalid static identity or peer keys", peer->name);
        return false;
    }
    if (!noise_precompute_static_static(&peer->handshake_material, &peer->static_identity)) {
        wgnx::sysmodule::logger::Log("WG peer '%s': failed to precompute static-static DH", peer->name);
        noise_static_identity_reset(&peer->static_identity);
        noise_handshake_material_reset(&peer->handshake_material);
        return false;
    }

    return true;
}

void wg_peer_set_resolved_endpoint(
    wg_peer *peer,
    const wgnx::platform::endpoint &endpoint,
    std::string_view endpoint_text) {
    if (peer == nullptr) {
        return;
    }

    peer->resolved_endpoint = endpoint;
    peer->has_resolved_endpoint = true;
    std::memset(peer->resolved_endpoint_text, 0, sizeof(peer->resolved_endpoint_text));
    const std::size_t copy_size = std::min(endpoint_text.size(), sizeof(peer->resolved_endpoint_text) - 1);
    std::memcpy(peer->resolved_endpoint_text, endpoint_text.data(), copy_size);
}

void wg_peer_clear_resolved_endpoint(wg_peer *peer) {
    if (peer == nullptr) {
        return;
    }

    peer->resolved_endpoint = {};
    peer->resolved_endpoint_text[0] = '\0';
    peer->has_resolved_endpoint = false;
}

void wg_peer_reset_keypairs(wg_peer *peer) {
    if (peer == nullptr) {
        return;
    }

    noise_keypair_reset(&peer->current_keypair);
    noise_keypair_reset(&peer->next_keypair);
    noise_keypair_reset(&peer->previous_keypair);
}

void wg_peer_clear_last_initiation(wg_peer *peer) {
    if (peer == nullptr) {
        return;
    }

    peer->last_initiation = {};
    peer->has_last_initiation = false;
}

void wg_peer_scrub_transient_state(wg_peer *peer) {
    if (peer == nullptr) {
        return;
    }

    crypto::secure_clear(
        peer->handshake_material.ephemeral_private.bytes,
        sizeof(peer->handshake_material.ephemeral_private.bytes));
    peer->handshake_material.ephemeral_private.valid = false;
    crypto::secure_clear(
        peer->handshake_material.ephemeral_public.bytes,
        sizeof(peer->handshake_material.ephemeral_public.bytes));
    peer->handshake_material.ephemeral_public.valid = false;
    crypto::secure_clear(
        peer->handshake_material.remote_ephemeral.bytes,
        sizeof(peer->handshake_material.remote_ephemeral.bytes));
    peer->handshake_material.remote_ephemeral.valid = false;
    crypto::secure_clear(peer->handshake_material.chaining_key.bytes, sizeof(peer->handshake_material.chaining_key.bytes));
    peer->handshake_material.chaining_key.valid = false;
    crypto::secure_clear(peer->handshake_material.hash.bytes, sizeof(peer->handshake_material.hash.bytes));
    peer->handshake_material.hash.valid = false;
    noise_cookie_reset(&peer->cookie);
    wg_peer_clear_last_initiation(peer);
    wg_peer_reset_keypairs(peer);
}

} // namespace wgnx::wireguard
