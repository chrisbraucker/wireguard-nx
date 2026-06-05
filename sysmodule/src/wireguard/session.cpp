#include "wireguard/session.hpp"

namespace wgnx::wireguard {

void noise_static_identity_reset(noise_static_identity *identity) {
    if (identity == nullptr) {
        return;
    }

    *identity = {};
}

void noise_handshake_material_reset(noise_handshake_material *material) {
    if (material == nullptr) {
        return;
    }

    *material = {};
}

void noise_keypair_reset(noise_keypair *keypair) {
    if (keypair == nullptr) {
        return;
    }

    *keypair = {};
}

} // namespace wgnx::wireguard
