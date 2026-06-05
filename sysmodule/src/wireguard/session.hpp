#pragma once

#include "wgnx/platform/clock.hpp"

#include "wireguard/constants.hpp"

#include <cstdint>

namespace wgnx::wireguard {

struct noise_public_key {
    std::uint8_t bytes[NoisePublicKeySize]{};
    bool valid{false};
};

struct noise_private_key {
    std::uint8_t bytes[NoisePublicKeySize]{};
    bool valid{false};
};

struct noise_symmetric_key {
    std::uint8_t bytes[32]{};
    bool valid{false};
};

struct noise_static_identity {
    noise_private_key static_private{};
    noise_public_key static_public{};
    noise_public_key remote_static{};
    noise_symmetric_key preshared_key{};
};

struct noise_handshake_material {
    noise_private_key ephemeral_private{};
    noise_public_key ephemeral_public{};
    noise_public_key remote_ephemeral{};
    noise_symmetric_key chaining_key{};
    noise_symmetric_key hash{};
};

struct noise_keypair {
    bool valid{false};
    std::uint32_t local_index{0};
    std::uint32_t remote_index{0};
    std::uint64_t send_counter{0};
    wgnx::platform::ktime_t birthdate_ns{0};
    noise_symmetric_key sending_key{};
    noise_symmetric_key receiving_key{};
};

void noise_static_identity_reset(noise_static_identity *identity);
void noise_handshake_material_reset(noise_handshake_material *material);
void noise_keypair_reset(noise_keypair *keypair);

} // namespace wgnx::wireguard
