#pragma once

#include "wgnx/platform/clock.hpp"

#include "wireguard/constants.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

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

struct noise_secret32 {
    std::uint8_t bytes[32]{};
    bool valid{false};
};

struct noise_cookie {
    std::uint8_t value[CookieValueSize]{};
    std::uint8_t last_mac1[NoiseMacSize]{};
    wgnx::platform::ktime_t birthdate_ns{0};
    bool valid{false};
    bool has_last_mac1{false};
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
    noise_secret32 precomputed_static_static{};
    noise_symmetric_key chaining_key{};
    noise_symmetric_key hash{};
};

struct noise_keypair {
    bool valid{false};
    std::uint32_t local_index{0};
    std::uint32_t remote_index{0};
    std::uint64_t send_counter{0};
    /*
     * Deviation from Linux:
     * Replay tracking is currently compressed to a 64-packet window instead of
     * the larger upstream bitmap. The current sysmodule shape is single-active-
     * peer and memory-sensitive, so this keeps per-keypair state compact while
     * still making duplicate and stale transport-data packets fail
     * deterministically. The implication is that packets arriving more than 63
     * counters behind the highest accepted value are rejected earlier than they
     * would be upstream.
     */
    std::uint64_t receive_counter{0};
    std::uint64_t replay_window{0};
    wgnx::platform::ktime_t birthdate_ns{0};
    noise_symmetric_key sending_key{};
    noise_symmetric_key receiving_key{};
    bool has_receive_counter{false};
};

void noise_cookie_reset(noise_cookie *cookie);
void noise_cookie_record_last_mac1(noise_cookie *cookie, const std::uint8_t mac1[NoiseMacSize]);
bool noise_cookie_is_valid(const noise_cookie *cookie);
void noise_static_identity_reset(noise_static_identity *identity);
void noise_handshake_material_reset(noise_handshake_material *material);
void noise_keypair_reset(noise_keypair *keypair);

bool noise_is_valid_encoded_key(std::string_view text, bool allow_empty = false);
bool noise_parse_private_key(noise_private_key *out_key, std::string_view text);
bool noise_parse_public_key(noise_public_key *out_key, std::string_view text);
bool noise_parse_preshared_key(noise_symmetric_key *out_key, std::string_view text);
bool noise_public_key_to_text(std::span<char> out_text, const noise_public_key *key);
bool noise_derive_public_key_text(std::span<char> out_text, std::string_view private_key_text);
bool noise_static_identity_init(
    noise_static_identity *identity,
    std::string_view private_key_text,
    std::string_view peer_public_key_text,
    std::string_view preshared_key_text);
bool noise_precompute_static_static(
    noise_handshake_material *material,
    const noise_static_identity *identity);

} // namespace wgnx::wireguard
