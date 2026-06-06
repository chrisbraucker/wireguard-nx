#include "wireguard/handshake.hpp"

#include "wireguard/crypto/primitives.hpp"
#include "wireguard/endian.hpp"
#include "wireguard/peer.hpp"
#include "wgnx/platform/random.hpp"

#include "logger.hpp"

#include <cstddef>
#include <cstring>

namespace wgnx::wireguard {

namespace {

constexpr std::size_t NoiseHashSize = crypto::Blake2sHashSize;
constexpr std::size_t NoiseSymmetricKeySize = 32;
constexpr std::uint32_t InitiationsPerSecond = 50;
constexpr std::uint64_t Tai64nBaseSeconds = 0x400000000000000aULL;
constexpr std::uint8_t ZeroNonce[crypto::ChaCha20NonceSize] = {};
constexpr char HandshakeName[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
constexpr char IdentifierName[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
constexpr char Mac1KeyLabel[] = "mac1----";

struct HandshakeInitCache {
    std::uint8_t chaining_key[NoiseHashSize]{};
    std::uint8_t hash[NoiseHashSize]{};
    bool ready{false};
};

constinit HandshakeInitCache g_handshake_init_cache{};

bool IsAllZero(const std::uint8_t *bytes, std::size_t size) {
    if (bytes == nullptr) {
        return true;
    }

    std::uint8_t value = 0;
    for (std::size_t i = 0; i < size; ++i) {
        value |= bytes[i];
    }
    return value == 0;
}

std::uint64_t RoundDownToPowerOfTwo(std::uint64_t value) {
    if (value == 0) {
        return 0;
    }

    std::uint64_t result = 1;
    while ((result << 1U) > result && (result << 1U) <= value) {
        result <<= 1U;
    }
    return result;
}

void StoreBe64(std::uint8_t *out, std::uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        out[7 - i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xffU);
    }
}

void StoreBe32(std::uint8_t *out, std::uint32_t value) {
    out[0] = static_cast<std::uint8_t>((value >> 24) & 0xffU);
    out[1] = static_cast<std::uint8_t>((value >> 16) & 0xffU);
    out[2] = static_cast<std::uint8_t>((value >> 8) & 0xffU);
    out[3] = static_cast<std::uint8_t>(value & 0xffU);
}

void EnsureHandshakeInitCache() {
    if (g_handshake_init_cache.ready) {
        return;
    }

    static_cast<void>(crypto::blake2s(
        g_handshake_init_cache.chaining_key,
        sizeof(g_handshake_init_cache.chaining_key),
        HandshakeName,
        sizeof(HandshakeName) - 1,
        nullptr,
        0));

    crypto::blake2s_state state{};
    static_cast<void>(crypto::blake2s_init(&state, sizeof(g_handshake_init_cache.hash), nullptr, 0));
    crypto::blake2s_update(&state, g_handshake_init_cache.chaining_key, sizeof(g_handshake_init_cache.chaining_key));
    crypto::blake2s_update(&state, IdentifierName, sizeof(IdentifierName) - 1);
    static_cast<void>(crypto::blake2s_final(&state, g_handshake_init_cache.hash, sizeof(g_handshake_init_cache.hash)));
    g_handshake_init_cache.ready = true;
}

bool Blake2sHmac(
    std::uint8_t *out,
    std::size_t out_size,
    const std::uint8_t *key,
    std::size_t key_size,
    const std::uint8_t *data,
    std::size_t data_size) {
    if (out == nullptr || key == nullptr || (data == nullptr && data_size != 0)) {
        return false;
    }

    std::uint8_t normalized_key[crypto::Blake2sBlockSize]{};
    std::uint8_t inner_hash[crypto::Blake2sHashSize]{};
    std::uint8_t inner_pad[crypto::Blake2sBlockSize]{};
    std::uint8_t outer_pad[crypto::Blake2sBlockSize]{};

    if (key_size > sizeof(normalized_key)) {
        if (!crypto::blake2s(normalized_key, crypto::Blake2sHashSize, key, key_size, nullptr, 0)) {
            crypto::secure_clear(normalized_key, sizeof(normalized_key));
            return false;
        }
    } else {
        std::memcpy(normalized_key, key, key_size);
    }

    for (std::size_t i = 0; i < sizeof(normalized_key); ++i) {
        inner_pad[i] = normalized_key[i] ^ 0x36U;
        outer_pad[i] = normalized_key[i] ^ 0x5cU;
    }

    crypto::blake2s_state state{};
    static_cast<void>(crypto::blake2s_init(&state, sizeof(inner_hash), nullptr, 0));
    crypto::blake2s_update(&state, inner_pad, sizeof(inner_pad));
    crypto::blake2s_update(&state, data, data_size);
    static_cast<void>(crypto::blake2s_final(&state, inner_hash, sizeof(inner_hash)));

    static_cast<void>(crypto::blake2s_init(&state, out_size, nullptr, 0));
    crypto::blake2s_update(&state, outer_pad, sizeof(outer_pad));
    crypto::blake2s_update(&state, inner_hash, sizeof(inner_hash));
    const bool ok = crypto::blake2s_final(&state, out, out_size);

    crypto::secure_clear(normalized_key, sizeof(normalized_key));
    crypto::secure_clear(inner_hash, sizeof(inner_hash));
    crypto::secure_clear(inner_pad, sizeof(inner_pad));
    crypto::secure_clear(outer_pad, sizeof(outer_pad));
    return ok;
}

void Kdf(
    std::uint8_t *first_dst,
    std::size_t first_size,
    std::uint8_t *second_dst,
    std::size_t second_size,
    std::uint8_t *third_dst,
    std::size_t third_size,
    const std::uint8_t *data,
    std::size_t data_size,
    const std::uint8_t chaining_key[NoiseHashSize]) {
    std::uint8_t secret[crypto::Blake2sHashSize]{};
    std::uint8_t output[crypto::Blake2sHashSize + 1]{};
    static_cast<void>(Blake2sHmac(secret, sizeof(secret), chaining_key, NoiseHashSize, data, data_size));

    if (first_dst != nullptr && first_size != 0) {
        output[0] = 1;
        static_cast<void>(Blake2sHmac(output, crypto::Blake2sHashSize, secret, sizeof(secret), output, 1));
        std::memcpy(first_dst, output, first_size);
    }
    if (second_dst != nullptr && second_size != 0) {
        output[crypto::Blake2sHashSize] = 2;
        static_cast<void>(Blake2sHmac(
            output,
            crypto::Blake2sHashSize,
            secret,
            sizeof(secret),
            output,
            crypto::Blake2sHashSize + 1));
        std::memcpy(second_dst, output, second_size);
    }
    if (third_dst != nullptr && third_size != 0) {
        output[crypto::Blake2sHashSize] = 3;
        static_cast<void>(Blake2sHmac(
            output,
            crypto::Blake2sHashSize,
            secret,
            sizeof(secret),
            output,
            crypto::Blake2sHashSize + 1));
        std::memcpy(third_dst, output, third_size);
    }

    crypto::secure_clear(secret, sizeof(secret));
    crypto::secure_clear(output, sizeof(output));
}

void MixHash(std::uint8_t hash[NoiseHashSize], const std::uint8_t *src, std::size_t src_size) {
    crypto::blake2s_state state{};
    static_cast<void>(crypto::blake2s_init(&state, NoiseHashSize, nullptr, 0));
    crypto::blake2s_update(&state, hash, NoiseHashSize);
    crypto::blake2s_update(&state, src, src_size);
    static_cast<void>(crypto::blake2s_final(&state, hash, NoiseHashSize));
}

void HandshakeInit(
    std::uint8_t chaining_key[NoiseHashSize],
    std::uint8_t hash[NoiseHashSize],
    const noise_public_key &remote_static) {
    EnsureHandshakeInitCache();
    std::memcpy(chaining_key, g_handshake_init_cache.chaining_key, NoiseHashSize);
    std::memcpy(hash, g_handshake_init_cache.hash, NoiseHashSize);
    MixHash(hash, remote_static.bytes, sizeof(remote_static.bytes));
}

bool MixDh(
    std::uint8_t chaining_key[NoiseHashSize],
    std::uint8_t key[NoiseSymmetricKeySize],
    const std::uint8_t private_key[NoisePublicKeySize],
    const std::uint8_t public_key[NoisePublicKeySize]) {
    std::uint8_t dh[NoisePublicKeySize]{};
    if (!crypto::x25519(dh, private_key, public_key) || IsAllZero(dh, sizeof(dh))) {
        crypto::secure_clear(dh, sizeof(dh));
        return false;
    }

    Kdf(
        chaining_key,
        NoiseHashSize,
        key,
        NoiseSymmetricKeySize,
        nullptr,
        0,
        dh,
        sizeof(dh),
        chaining_key);
    crypto::secure_clear(dh, sizeof(dh));
    return true;
}

bool MixPrecomputedDh(
    std::uint8_t chaining_key[NoiseHashSize],
    std::uint8_t key[NoiseSymmetricKeySize],
    const noise_secret32 &precomputed) {
    if (!precomputed.valid || IsAllZero(precomputed.bytes, sizeof(precomputed.bytes))) {
        return false;
    }

    Kdf(
        chaining_key,
        NoiseHashSize,
        key,
        NoiseSymmetricKeySize,
        nullptr,
        0,
        precomputed.bytes,
        sizeof(precomputed.bytes),
        chaining_key);
    return true;
}

bool MessageEncrypt(
    std::uint8_t *dst_ciphertext,
    const std::uint8_t *src_plaintext,
    std::size_t src_size,
    std::uint8_t key[NoiseSymmetricKeySize],
    std::uint8_t hash[NoiseHashSize]) {
    if (dst_ciphertext == nullptr || src_plaintext == nullptr) {
        return false;
    }

    std::uint8_t tag[NoiseTagSize]{};
    if (!crypto::chacha20poly1305_encrypt(
            dst_ciphertext,
            tag,
            src_plaintext,
            src_size,
            hash,
            NoiseHashSize,
            key,
            ZeroNonce)) {
        return false;
    }

    std::memcpy(dst_ciphertext + src_size, tag, sizeof(tag));
    MixHash(hash, dst_ciphertext, src_size + sizeof(tag));
    crypto::secure_clear(tag, sizeof(tag));
    return true;
}

void MessageEphemeral(
    std::uint8_t ephemeral_dst[NoisePublicKeySize],
    const std::uint8_t ephemeral_src[NoisePublicKeySize],
    std::uint8_t chaining_key[NoiseHashSize],
    std::uint8_t hash[NoiseHashSize]) {
    if (ephemeral_dst != ephemeral_src) {
        std::memcpy(ephemeral_dst, ephemeral_src, NoisePublicKeySize);
    }
    MixHash(hash, ephemeral_src, NoisePublicKeySize);
    Kdf(
        chaining_key,
        NoiseHashSize,
        nullptr,
        0,
        nullptr,
        0,
        ephemeral_src,
        NoisePublicKeySize,
        chaining_key);
}

void Tai64nNow(std::uint8_t output[TAI64NTimestampSize]) {
    wgnx::platform::timespec64 now{};
    wgnx::platform::ktime_get_real_ts64(&now);

    const std::uint64_t rounding = RoundDownToPowerOfTwo(
        static_cast<std::uint64_t>(wgnx::platform::NSEC_PER_SEC / InitiationsPerSecond));
    if (rounding != 0) {
        now.tv_nsec -= now.tv_nsec % static_cast<std::int64_t>(rounding);
    }

    StoreBe64(output, Tai64nBaseSeconds + static_cast<std::uint64_t>(now.tv_sec));
    StoreBe32(output + sizeof(std::uint64_t), static_cast<std::uint32_t>(now.tv_nsec));
}

void ComputeMac1(message_handshake_initiation *message, const noise_public_key &remote_static) {
    std::uint8_t mac1_key[NoiseSymmetricKeySize]{};
    crypto::blake2s_state state{};
    static_cast<void>(crypto::blake2s_init(&state, sizeof(mac1_key), nullptr, 0));
    crypto::blake2s_update(&state, Mac1KeyLabel, sizeof(Mac1KeyLabel) - 1);
    crypto::blake2s_update(&state, remote_static.bytes, sizeof(remote_static.bytes));
    static_cast<void>(crypto::blake2s_final(&state, mac1_key, sizeof(mac1_key)));

    const std::size_t mac1_input_size =
        sizeof(*message) - sizeof(message->macs) + offsetof(message_macs, mac1);
    static_cast<void>(crypto::blake2s(
        message->macs.mac1,
        sizeof(message->macs.mac1),
        message,
        mac1_input_size,
        mac1_key,
        sizeof(mac1_key)));
    crypto::secure_clear(mac1_key, sizeof(mac1_key));
}

} // namespace

const char *GetHandshakeStateName(HandshakeState state) {
    switch (state) {
        case HandshakeState::Zeroed:
            return "zeroed";
        case HandshakeState::InitiationCreated:
            return "initiation_created";
        case HandshakeState::InitiationReceived:
            return "initiation_received";
        case HandshakeState::ResponseCreated:
            return "response_created";
        case HandshakeState::ResponseReceived:
            return "response_received";
        case HandshakeState::SessionDerived:
            return "session_derived";
        case HandshakeState::Failed:
            return "failed";
    }

    return "unknown";
}

void noise_handshake_init(noise_handshake *handshake) {
    if (handshake == nullptr) {
        return;
    }

    *handshake = {};
    handshake->state = HandshakeState::Zeroed;
    handshake->last_transition_ns = wgnx::platform::ktime_get_coarse_boottime_ns();
}

bool noise_handshake_transition(
    noise_handshake *handshake,
    HandshakeState new_state,
    const char *peer_name,
    const char *reason) {
    if (handshake == nullptr) {
        return false;
    }

    const HandshakeState old_state = handshake->state;
    handshake->state = new_state;
    handshake->last_transition_ns = wgnx::platform::ktime_get_coarse_boottime_ns();
    ++handshake->transition_count;

    wgnx::sysmodule::logger::Log(
        "WG handshake peer='%s' %s -> %s reason='%s' local=0x%08x remote=0x%08x transitions=%u",
        peer_name != nullptr ? peer_name : "<unnamed>",
        GetHandshakeStateName(old_state),
        GetHandshakeStateName(new_state),
        reason != nullptr ? reason : "none",
        handshake->local_index,
        handshake->remote_index,
        handshake->transition_count);
    return old_state != new_state;
}

void noise_handshake_set_local_index(noise_handshake *handshake, std::uint32_t local_index) {
    if (handshake == nullptr) {
        return;
    }

    handshake->local_index = local_index;
}

void noise_handshake_set_remote_index(noise_handshake *handshake, std::uint32_t remote_index) {
    if (handshake == nullptr) {
        return;
    }

    handshake->remote_index = remote_index;
}

bool noise_handshake_create_initiation(message_handshake_initiation *dst, wg_peer *peer) {
    if (dst == nullptr || peer == nullptr || !peer->static_identity.static_private.valid ||
        !peer->static_identity.static_public.valid || !peer->static_identity.remote_static.valid ||
        !peer->handshake_material.precomputed_static_static.valid || peer->handshake.local_index == 0) {
        return false;
    }

    std::uint8_t timestamp[TAI64NTimestampSize]{};
    std::uint8_t key[NoiseSymmetricKeySize]{};
    std::uint8_t ephemeral_private[NoisePublicKeySize]{};

    *dst = {};
    SetMessageType(&dst->type, MessageType::HandshakeInitiation);
    dst->sender_index = peer->handshake.local_index;

    HandshakeInit(
        peer->handshake_material.chaining_key.bytes,
        peer->handshake_material.hash.bytes,
        peer->static_identity.remote_static);
    peer->handshake_material.chaining_key.valid = true;
    peer->handshake_material.hash.valid = true;

    wgnx::platform::get_random_bytes(ephemeral_private, sizeof(ephemeral_private));
    ephemeral_private[0] &= 248U;
    ephemeral_private[31] &= 127U;
    ephemeral_private[31] |= 64U;
    std::memcpy(peer->handshake_material.ephemeral_private.bytes, ephemeral_private, sizeof(ephemeral_private));
    peer->handshake_material.ephemeral_private.valid = true;

    if (!crypto::x25519_public_key(
            peer->handshake_material.ephemeral_public.bytes,
            peer->handshake_material.ephemeral_private.bytes)) {
        crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
        return false;
    }
    peer->handshake_material.ephemeral_public.valid = true;

    MessageEphemeral(
        dst->unencrypted_ephemeral,
        peer->handshake_material.ephemeral_public.bytes,
        peer->handshake_material.chaining_key.bytes,
        peer->handshake_material.hash.bytes);

    if (!MixDh(
            peer->handshake_material.chaining_key.bytes,
            key,
            peer->handshake_material.ephemeral_private.bytes,
            peer->static_identity.remote_static.bytes)) {
        crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
        crypto::secure_clear(key, sizeof(key));
        return false;
    }
    if (!MessageEncrypt(
            dst->encrypted_static,
            peer->static_identity.static_public.bytes,
            NoisePublicKeySize,
            key,
            peer->handshake_material.hash.bytes)) {
        crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
        crypto::secure_clear(key, sizeof(key));
        return false;
    }
    if (!MixPrecomputedDh(
            peer->handshake_material.chaining_key.bytes,
            key,
            peer->handshake_material.precomputed_static_static)) {
        crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
        crypto::secure_clear(key, sizeof(key));
        return false;
    }

    Tai64nNow(timestamp);
    if (!MessageEncrypt(
            dst->encrypted_timestamp,
            timestamp,
            sizeof(timestamp),
            key,
            peer->handshake_material.hash.bytes)) {
        crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
        crypto::secure_clear(key, sizeof(key));
        crypto::secure_clear(timestamp, sizeof(timestamp));
        return false;
    }

    std::memset(&dst->macs, 0, sizeof(dst->macs));
    ComputeMac1(dst, peer->static_identity.remote_static);
    peer->last_initiation = *dst;
    peer->has_last_initiation = true;

    static_cast<void>(noise_handshake_transition(
        &peer->handshake,
        HandshakeState::InitiationCreated,
        peer->name,
        "created real handshake initiation"));

    crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
    crypto::secure_clear(key, sizeof(key));
    crypto::secure_clear(timestamp, sizeof(timestamp));
    return true;
}

} // namespace wgnx::wireguard
