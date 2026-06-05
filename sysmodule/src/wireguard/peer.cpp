#include "wireguard/peer.hpp"

#include <cstdio>
#include <cstring>

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
    noise_handshake_init(&peer->handshake);
    wg_timers_init(&peer->timers);
    wg_peer_reset_keypairs(peer);
}

void wg_peer_set_resolved_endpoint(
    wg_peer *peer,
    const wgnx::platform::endpoint &endpoint,
    const char *endpoint_text) {
    if (peer == nullptr) {
        return;
    }

    peer->resolved_endpoint = endpoint;
    peer->has_resolved_endpoint = true;
    std::snprintf(
        peer->resolved_endpoint_text,
        sizeof(peer->resolved_endpoint_text),
        "%s",
        endpoint_text != nullptr ? endpoint_text : "");
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

} // namespace wgnx::wireguard
