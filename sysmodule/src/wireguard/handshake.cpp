#include "wireguard/handshake.hpp"

#include "wireguard/crypto/primitives.hpp"
#include "wireguard/device.hpp"
#include "wireguard/endian.hpp"
#include "wireguard/peer.hpp"
#include "wgnx/platform/clock.hpp"
#include "wgnx/platform/random.hpp"

#include "logger.hpp"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iterator>

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
constexpr char CookieKeyLabel[] = "cookie--";

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
    MixHash(hash, remote_static.bytes.data(), remote_static.bytes.size());
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
    if (!precomputed.valid || IsAllZero(precomputed.bytes.data(), precomputed.bytes.size())) {
        return false;
    }

    Kdf(
        chaining_key,
        NoiseHashSize,
        key,
        NoiseSymmetricKeySize,
        nullptr,
        0,
        precomputed.bytes.data(),
        precomputed.bytes.size(),
        chaining_key);
    return true;
}

void MixPsk(
    std::uint8_t chaining_key[NoiseHashSize],
    std::uint8_t hash[NoiseHashSize],
    std::uint8_t key[NoiseSymmetricKeySize],
    const std::uint8_t preshared_key[NoiseSymmetricKeySize]) {
    std::uint8_t temp_hash[NoiseHashSize]{};
    Kdf(
        chaining_key,
        NoiseHashSize,
        temp_hash,
        NoiseHashSize,
        key,
        NoiseSymmetricKeySize,
        preshared_key,
        NoiseSymmetricKeySize,
        chaining_key);
    MixHash(hash, temp_hash, sizeof(temp_hash));
    crypto::secure_clear(temp_hash, sizeof(temp_hash));
}

bool MessageEncrypt(
    std::uint8_t *dst_ciphertext,
    const std::uint8_t *src_plaintext,
    std::size_t src_size,
    std::uint8_t key[NoiseSymmetricKeySize],
    std::uint8_t hash[NoiseHashSize]) {
    if (dst_ciphertext == nullptr || (src_plaintext == nullptr && src_size != 0)) {
        return false;
    }

    std::uint8_t tag[NoiseTagSize]{};
    std::uint8_t empty_plaintext = 0;
    const std::uint8_t *plaintext_src = src_plaintext != nullptr ? src_plaintext : &empty_plaintext;
    if (!crypto::chacha20poly1305_encrypt(
            dst_ciphertext,
            tag,
            plaintext_src,
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

bool MessageDecrypt(
    std::uint8_t *dst_plaintext,
    const std::uint8_t *src_ciphertext,
    std::size_t src_size,
    std::uint8_t key[NoiseSymmetricKeySize],
    std::uint8_t hash[NoiseHashSize]) {
    if (src_ciphertext == nullptr || src_size < NoiseTagSize) {
        return false;
    }

    const std::size_t plaintext_size = src_size - NoiseTagSize;
    std::uint8_t empty_plaintext = 0;
    std::uint8_t *plaintext_dst = dst_plaintext;
    if (plaintext_dst == nullptr) {
        if (plaintext_size != 0) {
            return false;
        }
        plaintext_dst = &empty_plaintext;
    }

    const bool ok = crypto::chacha20poly1305_decrypt(
        plaintext_dst,
        src_ciphertext,
        plaintext_size,
        src_ciphertext + plaintext_size,
        hash,
        NoiseHashSize,
        key,
        ZeroNonce);
    if (!ok) {
        crypto::secure_clear(&empty_plaintext, sizeof(empty_plaintext));
        return false;
    }

    MixHash(hash, src_ciphertext, src_size);
    crypto::secure_clear(&empty_plaintext, sizeof(empty_plaintext));
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
    if (message == nullptr) {
        return;
    }

    std::uint8_t mac1_key[NoiseSymmetricKeySize]{};
    crypto::blake2s_state state{};
    static_cast<void>(crypto::blake2s_init(&state, sizeof(mac1_key), nullptr, 0));
    crypto::blake2s_update(&state, Mac1KeyLabel, sizeof(Mac1KeyLabel) - 1);
    crypto::blake2s_update(&state, remote_static.bytes.data(), remote_static.bytes.size());
    static_cast<void>(crypto::blake2s_final(&state, mac1_key, sizeof(mac1_key)));

    std::array<std::uint8_t, HandshakeInitiationSize> serialized{};
    if (SerializeHandshakeInitiation(serialized, *message) != ParseError::None) {
        crypto::secure_clear(mac1_key, sizeof(mac1_key));
        return;
    }
    constexpr std::size_t mac1_input_size = HandshakeInitiationSize - (2 * NoiseMacSize);
    static_cast<void>(crypto::blake2s(
        message->macs.mac1.data(),
        message->macs.mac1.size(),
        serialized.data(),
        mac1_input_size,
        mac1_key,
        sizeof(mac1_key)));
    crypto::secure_clear(mac1_key, sizeof(mac1_key));
    crypto::secure_clear(serialized.data(), serialized.size());
}

void ComputeMac1(message_handshake_response *message, const noise_public_key &remote_static) {
    if (message == nullptr) {
        return;
    }

    std::uint8_t mac1_key[NoiseSymmetricKeySize]{};
    crypto::blake2s_state state{};
    static_cast<void>(crypto::blake2s_init(&state, sizeof(mac1_key), nullptr, 0));
    crypto::blake2s_update(&state, Mac1KeyLabel, sizeof(Mac1KeyLabel) - 1);
    crypto::blake2s_update(&state, remote_static.bytes.data(), remote_static.bytes.size());
    static_cast<void>(crypto::blake2s_final(&state, mac1_key, sizeof(mac1_key)));

    std::array<std::uint8_t, HandshakeResponseSize> serialized{};
    if (SerializeHandshakeResponse(serialized, *message) != ParseError::None) {
        crypto::secure_clear(mac1_key, sizeof(mac1_key));
        return;
    }
    constexpr std::size_t mac1_input_size = HandshakeResponseSize - (2 * NoiseMacSize);
    static_cast<void>(crypto::blake2s(
        message->macs.mac1.data(),
        message->macs.mac1.size(),
        serialized.data(),
        mac1_input_size,
        mac1_key,
        sizeof(mac1_key)));
    crypto::secure_clear(mac1_key, sizeof(mac1_key));
    crypto::secure_clear(serialized.data(), serialized.size());
}

template <typename Message>
bool VerifyMac1(
    const Message &message,
    const noise_public_key &local_static,
    void (*compute)(Message *, const noise_public_key &)) {
    if (!local_static.valid) {
        return false;
    }

    Message expected = message;
    compute(&expected, local_static);
    const bool matches = crypto::secure_equal(
        expected.macs.mac1.data(),
        message.macs.mac1.data(),
        message.macs.mac1.size());
    crypto::secure_clear(expected.macs.mac1.data(), expected.macs.mac1.size());
    return matches;
}

bool ComputeCookieKey(
    std::uint8_t key[NoiseSymmetricKeySize],
    const noise_public_key &remote_static) {
    if (key == nullptr || !remote_static.valid) {
        return false;
    }

    crypto::blake2s_state state{};
    if (!crypto::blake2s_init(&state, NoiseSymmetricKeySize, nullptr, 0)) {
        return false;
    }
    crypto::blake2s_update(&state, CookieKeyLabel, sizeof(CookieKeyLabel) - 1);
    crypto::blake2s_update(&state, remote_static.bytes.data(), remote_static.bytes.size());
    return crypto::blake2s_final(&state, key, NoiseSymmetricKeySize);
}

template <typename T, std::size_t Size>
void ComputeMac2(
    const T &message,
    const noise_cookie &cookie,
    std::array<std::uint8_t, NoiseMacSize> &out_mac2,
    ParseError (*serialize)(std::span<std::uint8_t>, const T &)) {
    std::array<std::uint8_t, Size> serialized{};
    if (serialize(serialized, message) != ParseError::None) {
        return;
    }
    constexpr std::size_t mac2_input_size = Size - NoiseMacSize;
    static_cast<void>(crypto::blake2s(
        out_mac2.data(),
        NoiseMacSize,
        serialized.data(),
        mac2_input_size,
        cookie.value.data(),
        CookieValueSize));
    crypto::secure_clear(serialized.data(), serialized.size());
}

void ComputeMac2(
    const message_handshake_initiation &message,
    const noise_cookie &cookie,
    std::array<std::uint8_t, NoiseMacSize> &out_mac2) {
    ComputeMac2<message_handshake_initiation, HandshakeInitiationSize>(
        message,
        cookie,
        out_mac2,
        SerializeHandshakeInitiation);
}

void ComputeMac2(
    const message_handshake_response &message,
    const noise_cookie &cookie,
    std::array<std::uint8_t, NoiseMacSize> &out_mac2) {
    ComputeMac2<message_handshake_response, HandshakeResponseSize>(
        message,
        cookie,
        out_mac2,
        SerializeHandshakeResponse);
}

bool MatchesCookieReceiverIndex(const wg_device *device, std::uint32_t receiver_index) {
    if (device == nullptr || receiver_index == 0) {
        return false;
    }

    const ::wgnx::wireguard::wg_index_slot slot =
        ::wgnx::wireguard::wg_device_lookup_index_slot(device, receiver_index);
    return slot == ::wgnx::wireguard::wg_index_slot::Handshake ||
           slot == ::wgnx::wireguard::wg_index_slot::CurrentKeypair ||
           slot == ::wgnx::wireguard::wg_index_slot::NextKeypair ||
           slot == ::wgnx::wireguard::wg_index_slot::PreviousKeypair;
}

template <typename T>
void ApplyOutgoingMacs(T *message, const noise_public_key &remote_static, wg_peer *peer) {
    if (message == nullptr) {
        return;
    }

    message->macs = {};
    ComputeMac1(message, remote_static);
    if (peer != nullptr) {
        noise_cookie_record_last_mac1(&peer->cookie, message->macs.mac1.data());
        if (noise_cookie_is_valid(&peer->cookie)) {
            ComputeMac2(*message, peer->cookie, message->macs.mac2);
        }
    }
}

void ClearHandshakeTranscript(wg_peer *peer) {
    if (peer == nullptr) {
        return;
    }

    peer->handshake_material.ephemeral_private.Clear();
    crypto::secure_clear(
        peer->handshake_material.ephemeral_public.bytes.data(),
        peer->handshake_material.ephemeral_public.bytes.size());
    peer->handshake_material.ephemeral_public.valid = false;
    crypto::secure_clear(
        peer->handshake_material.remote_ephemeral.bytes.data(),
        peer->handshake_material.remote_ephemeral.bytes.size());
    peer->handshake_material.remote_ephemeral.valid = false;
    peer->handshake_material.chaining_key.Clear();
    peer->handshake_material.hash.Clear();
    peer->handshake.local_index = 0;
    peer->handshake.remote_index = 0;
}

void DeriveSessionKeys(
    noise_symmetric_key *first_dst,
    noise_symmetric_key *second_dst,
    const std::uint8_t chaining_key[NoiseHashSize]) {
    if (first_dst == nullptr || second_dst == nullptr) {
        return;
    }

    Kdf(
        first_dst->bytes.data(),
        first_dst->bytes.size(),
        second_dst->bytes.data(),
        second_dst->bytes.size(),
        nullptr,
        0,
        nullptr,
        0,
        chaining_key);
    first_dst->valid = true;
    second_dst->valid = true;
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

const char *GetHandshakePacketOutcomeName(HandshakePacketOutcome outcome) {
    switch (outcome) {
        case HandshakePacketOutcome::Invalid:
            return "invalid";
        case HandshakePacketOutcome::InitiationConsumed:
            return "initiation_consumed";
        case HandshakePacketOutcome::ResponseConsumed:
            return "response_consumed";
        case HandshakePacketOutcome::CookieReplyConsumed:
            return "cookie_reply_consumed";
    }

    return "unknown";
}

void noise_handshake_clear_transcript(wg_peer *peer) {
    ClearHandshakeTranscript(peer);
}

void noise_handshake_init(noise_handshake *handshake) {
    if (handshake == nullptr) {
        return;
    }

    *handshake = {};
    handshake->state = HandshakeState::Zeroed;
    handshake->last_transition = GetMonotonicTime();
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
    handshake->last_transition = GetMonotonicTime();
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
    SetMessageType(dst->type, MessageType::HandshakeInitiation);
    dst->sender_index = peer->handshake.local_index;

    HandshakeInit(
        peer->handshake_material.chaining_key.bytes.data(),
        peer->handshake_material.hash.bytes.data(),
        peer->static_identity.remote_static);
    peer->handshake_material.chaining_key.valid = true;
    peer->handshake_material.hash.valid = true;

    wgnx::platform::get_random_bytes(ephemeral_private, sizeof(ephemeral_private));
    ephemeral_private[0] &= 248U;
    ephemeral_private[31] &= 127U;
    ephemeral_private[31] |= 64U;
    std::memcpy(peer->handshake_material.ephemeral_private.bytes.data(), ephemeral_private, sizeof(ephemeral_private));
    peer->handshake_material.ephemeral_private.valid = true;

    if (!crypto::x25519_public_key(
            peer->handshake_material.ephemeral_public.bytes.data(),
            peer->handshake_material.ephemeral_private.bytes.data())) {
        crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
        return false;
    }
    peer->handshake_material.ephemeral_public.valid = true;

    MessageEphemeral(
        dst->unencrypted_ephemeral.data(),
        peer->handshake_material.ephemeral_public.bytes.data(),
        peer->handshake_material.chaining_key.bytes.data(),
        peer->handshake_material.hash.bytes.data());

    if (!MixDh(
            peer->handshake_material.chaining_key.bytes.data(),
            key,
            peer->handshake_material.ephemeral_private.bytes.data(),
            peer->static_identity.remote_static.bytes.data())) {
        crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
        crypto::secure_clear(key, sizeof(key));
        return false;
    }
    if (!MessageEncrypt(
            dst->encrypted_static.data(),
            peer->static_identity.static_public.bytes.data(),
            NoisePublicKeySize,
            key,
            peer->handshake_material.hash.bytes.data())) {
        crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
        crypto::secure_clear(key, sizeof(key));
        return false;
    }
    if (!MixPrecomputedDh(
            peer->handshake_material.chaining_key.bytes.data(),
            key,
            peer->handshake_material.precomputed_static_static)) {
        crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
        crypto::secure_clear(key, sizeof(key));
        return false;
    }

    Tai64nNow(timestamp);
    if (!MessageEncrypt(
            dst->encrypted_timestamp.data(),
            timestamp,
            sizeof(timestamp),
            key,
            peer->handshake_material.hash.bytes.data())) {
        crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
        crypto::secure_clear(key, sizeof(key));
        crypto::secure_clear(timestamp, sizeof(timestamp));
        return false;
    }

    ApplyOutgoingMacs(dst, peer->static_identity.remote_static, peer);
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

bool noise_handshake_consume_initiation(const message_handshake_initiation *src, wg_peer *peer) {
    if (src == nullptr || peer == nullptr || !peer->static_identity.static_private.valid ||
        !peer->static_identity.static_public.valid || !peer->static_identity.remote_static.valid ||
        !peer->handshake_material.precomputed_static_static.valid) {
        return false;
    }
    std::uint8_t key[NoiseSymmetricKeySize]{};
    std::uint8_t chaining_key[NoiseHashSize]{};
    std::uint8_t hash[NoiseHashSize]{};
    std::uint8_t remote_ephemeral[NoisePublicKeySize]{};
    std::uint8_t remote_static[NoisePublicKeySize]{};
    std::uint8_t timestamp[TAI64NTimestampSize]{};
    MonotonicTimePoint now{};
    bool ok = false;

    if (GetMessageType(src->type) != MessageType::HandshakeInitiation) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected initiation with wrong message type", peer->name);
        goto out;
    }
    if (src->sender_index == 0) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected initiation with zero sender index", peer->name);
        goto out;
    }
    if (!VerifyMac1(*src, peer->static_identity.static_public, ComputeMac1)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected initiation mac1", peer->name);
        goto out;
    }

    HandshakeInit(chaining_key, hash, peer->static_identity.static_public);
    MessageEphemeral(remote_ephemeral, src->unencrypted_ephemeral.data(), chaining_key, hash);
    if (!MixDh(chaining_key, key, peer->static_identity.static_private.bytes.data(), remote_ephemeral)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': initiation es DH failed", peer->name);
        goto out;
    }
    if (!MessageDecrypt(remote_static, src->encrypted_static.data(), src->encrypted_static.size(), key, hash)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': initiation static decrypt failed", peer->name);
        goto out;
    }
    if (!crypto::secure_equal(
            remote_static,
            peer->static_identity.remote_static.bytes.data(),
            sizeof(remote_static))) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': initiation remote static mismatch", peer->name);
        goto out;
    }
    if (!MixPrecomputedDh(chaining_key, key, peer->handshake_material.precomputed_static_static)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': initiation static-static DH failed", peer->name);
        goto out;
    }
    if (!MessageDecrypt(timestamp, src->encrypted_timestamp.data(), src->encrypted_timestamp.size(), key, hash)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': initiation timestamp decrypt failed", peer->name);
        goto out;
    }

    if (peer->handshake.has_last_initiation_timestamp &&
        !std::lexicographical_compare(
            peer->handshake.last_initiation_timestamp.begin(),
            peer->handshake.last_initiation_timestamp.end(),
            std::begin(timestamp),
            std::end(timestamp))) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected replayed initiation", peer->name);
        goto out;
    }
    now = GetMonotonicTime();
    if (peer->handshake.last_initiation_consumption > MonotonicTimePoint{} &&
        (now < peer->handshake.last_initiation_consumption ||
         now - peer->handshake.last_initiation_consumption <= HandshakeInitiationRate)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected flooded initiation", peer->name);
        goto out;
    }

    std::memcpy(peer->handshake_material.remote_ephemeral.bytes.data(), remote_ephemeral, sizeof(remote_ephemeral));
    peer->handshake_material.remote_ephemeral.valid = true;
    std::memcpy(peer->handshake_material.hash.bytes.data(), hash, sizeof(hash));
    peer->handshake_material.hash.valid = true;
    std::memcpy(peer->handshake_material.chaining_key.bytes.data(), chaining_key, sizeof(chaining_key));
    peer->handshake_material.chaining_key.valid = true;
    peer->handshake.remote_index = src->sender_index;
    std::copy(std::begin(timestamp), std::end(timestamp), peer->handshake.last_initiation_timestamp.begin());
    peer->handshake.has_last_initiation_timestamp = true;
    peer->handshake.last_initiation_consumption = now;
    static_cast<void>(noise_handshake_transition(
        &peer->handshake,
        HandshakeState::InitiationReceived,
        peer->name,
        "consumed real handshake initiation"));
    ok = true;

out:
    crypto::secure_clear(key, sizeof(key));
    crypto::secure_clear(chaining_key, sizeof(chaining_key));
    crypto::secure_clear(hash, sizeof(hash));
    crypto::secure_clear(remote_ephemeral, sizeof(remote_ephemeral));
    crypto::secure_clear(remote_static, sizeof(remote_static));
    crypto::secure_clear(timestamp, sizeof(timestamp));
    return ok;
}

bool noise_handshake_create_response(message_handshake_response *dst, wg_peer *peer) {
    if (dst == nullptr || peer == nullptr || !peer->static_identity.remote_static.valid ||
        !peer->handshake_material.remote_ephemeral.valid || peer->handshake.local_index == 0 ||
        peer->handshake.remote_index == 0 || peer->handshake.state != HandshakeState::InitiationReceived) {
        return false;
    }

    std::uint8_t key[NoiseSymmetricKeySize]{};
    std::uint8_t ephemeral_private[NoisePublicKeySize]{};

    *dst = {};
    SetMessageType(dst->type, MessageType::HandshakeResponse);
    dst->receiver_index = peer->handshake.remote_index;

    wgnx::platform::get_random_bytes(ephemeral_private, sizeof(ephemeral_private));
    ephemeral_private[0] &= 248U;
    ephemeral_private[31] &= 127U;
    ephemeral_private[31] |= 64U;
    std::memcpy(peer->handshake_material.ephemeral_private.bytes.data(), ephemeral_private, sizeof(ephemeral_private));
    peer->handshake_material.ephemeral_private.valid = true;

    if (!crypto::x25519_public_key(
            peer->handshake_material.ephemeral_public.bytes.data(),
            peer->handshake_material.ephemeral_private.bytes.data())) {
        crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
        return false;
    }
    peer->handshake_material.ephemeral_public.valid = true;

    MessageEphemeral(
        dst->unencrypted_ephemeral.data(),
        peer->handshake_material.ephemeral_public.bytes.data(),
        peer->handshake_material.chaining_key.bytes.data(),
        peer->handshake_material.hash.bytes.data());
    if (!MixDh(
            peer->handshake_material.chaining_key.bytes.data(),
            nullptr,
            peer->handshake_material.ephemeral_private.bytes.data(),
            peer->handshake_material.remote_ephemeral.bytes.data())) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': response ee DH failed", peer->name);
        crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
        return false;
    }
    if (!MixDh(
            peer->handshake_material.chaining_key.bytes.data(),
            nullptr,
            peer->handshake_material.ephemeral_private.bytes.data(),
            peer->static_identity.remote_static.bytes.data())) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': response se DH failed", peer->name);
        crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
        return false;
    }

    MixPsk(
        peer->handshake_material.chaining_key.bytes.data(),
        peer->handshake_material.hash.bytes.data(),
        key,
        peer->static_identity.preshared_key.bytes.data());
    if (!MessageEncrypt(
            dst->encrypted_nothing.data(),
            nullptr,
            0,
            key,
            peer->handshake_material.hash.bytes.data())) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': response payload encrypt failed", peer->name);
        crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
        crypto::secure_clear(key, sizeof(key));
        return false;
    }

    dst->sender_index = peer->handshake.local_index;
    ApplyOutgoingMacs(dst, peer->static_identity.remote_static, peer);
    static_cast<void>(noise_handshake_transition(
        &peer->handshake,
        HandshakeState::ResponseCreated,
        peer->name,
        "created real handshake response"));
    crypto::secure_clear(ephemeral_private, sizeof(ephemeral_private));
    crypto::secure_clear(key, sizeof(key));
    return true;
}

bool noise_handshake_consume_response(const message_handshake_response *src, const wg_device *device, wg_peer *peer) {
    if (src == nullptr || device == nullptr || peer == nullptr || !peer->static_identity.static_private.valid ||
        !peer->handshake_material.ephemeral_private.valid || peer->handshake.state != HandshakeState::InitiationCreated) {
        return false;
    }

    std::uint8_t key[NoiseSymmetricKeySize]{};
    std::uint8_t hash[NoiseHashSize]{};
    std::uint8_t chaining_key[NoiseHashSize]{};
    std::uint8_t remote_ephemeral[NoisePublicKeySize]{};
    bool ok = false;

    if (GetMessageType(src->type) != MessageType::HandshakeResponse) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected response with wrong message type", peer->name);
        goto out;
    }
    if (src->sender_index == 0) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected response with zero sender index", peer->name);
        goto out;
    }
    if (!VerifyMac1(*src, peer->static_identity.static_public, ComputeMac1)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected response mac1", peer->name);
        goto out;
    }
    if (src->sender_index == peer->handshake.local_index) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected response reusing local sender index", peer->name);
        goto out;
    }
    if (!::wgnx::wireguard::wg_device_index_matches_slot(
            device,
            ::wgnx::wireguard::wg_index_slot::Handshake,
            src->receiver_index)) {
        wgnx::sysmodule::logger::Log(
            "WG handshake peer='%s': response receiver index mismatch local=0x%08x got=0x%08x",
            peer->name,
            peer->handshake.local_index,
            src->receiver_index);
        goto out;
    }
    if (peer->current_keypair.IsValid() &&
        src->sender_index == peer->current_keypair.RemoteIndex()) {
        wgnx::sysmodule::logger::Log(
            "WG handshake peer='%s': rejected replayed response sender=0x%08x",
            peer->name,
            src->sender_index);
        goto out;
    }

    std::memcpy(hash, peer->handshake_material.hash.bytes.data(), sizeof(hash));
    std::memcpy(chaining_key, peer->handshake_material.chaining_key.bytes.data(), sizeof(chaining_key));

    MessageEphemeral(remote_ephemeral, src->unencrypted_ephemeral.data(), chaining_key, hash);
    if (!MixDh(chaining_key, nullptr, peer->handshake_material.ephemeral_private.bytes.data(), remote_ephemeral)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': response ee DH failed", peer->name);
        goto out;
    }
    if (!MixDh(chaining_key, nullptr, peer->static_identity.static_private.bytes.data(), remote_ephemeral)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': response se DH failed", peer->name);
        goto out;
    }
    MixPsk(chaining_key, hash, key, peer->static_identity.preshared_key.bytes.data());
    if (!MessageDecrypt(nullptr, src->encrypted_nothing.data(), src->encrypted_nothing.size(), key, hash)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': response payload decrypt failed", peer->name);
        goto out;
    }

    std::memcpy(peer->handshake_material.remote_ephemeral.bytes.data(), remote_ephemeral, sizeof(remote_ephemeral));
    peer->handshake_material.remote_ephemeral.valid = true;
    std::memcpy(peer->handshake_material.hash.bytes.data(), hash, sizeof(hash));
    peer->handshake_material.hash.valid = true;
    std::memcpy(peer->handshake_material.chaining_key.bytes.data(), chaining_key, sizeof(chaining_key));
    peer->handshake_material.chaining_key.valid = true;
    peer->handshake.remote_index = src->sender_index;
    static_cast<void>(noise_handshake_transition(
        &peer->handshake,
        HandshakeState::ResponseReceived,
        peer->name,
        "consumed real handshake response"));
    ok = true;

out:
    crypto::secure_clear(key, sizeof(key));
    crypto::secure_clear(hash, sizeof(hash));
    crypto::secure_clear(chaining_key, sizeof(chaining_key));
    crypto::secure_clear(remote_ephemeral, sizeof(remote_ephemeral));
    return ok;
}

bool noise_handshake_consume_cookie_reply(const message_handshake_cookie *src, const wg_device *device, wg_peer *peer) {
    if (src == nullptr || device == nullptr || peer == nullptr || !peer->static_identity.remote_static.valid) {
        return false;
    }

    std::uint8_t cookie_key[NoiseSymmetricKeySize]{};
    std::uint8_t cookie_value[CookieValueSize]{};
    bool ok = false;

    if (GetMessageType(src->type) != MessageType::CookieReply) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected cookie reply with wrong message type", peer->name);
        goto out;
    }
    if (!MatchesCookieReceiverIndex(device, src->receiver_index)) {
        wgnx::sysmodule::logger::Log(
            "WG handshake peer='%s': rejected cookie reply receiver mismatch local=0x%08x got=0x%08x",
            peer->name,
            peer->handshake.local_index,
            src->receiver_index);
        goto out;
    }
    if (!peer->cookie.has_last_mac1) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected cookie reply without prior mac1", peer->name);
        goto out;
    }
    if (!ComputeCookieKey(cookie_key, peer->static_identity.remote_static)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': failed to derive cookie reply key", peer->name);
        goto out;
    }
    if (!crypto::xchacha20poly1305_decrypt(
            cookie_value,
            src->encrypted_cookie.data(),
            CookieValueSize,
            src->encrypted_cookie.data() + CookieValueSize,
            peer->cookie.last_mac1.data(),
            peer->cookie.last_mac1.size(),
            cookie_key,
            src->nonce.data())) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': cookie reply decrypt failed", peer->name);
        goto out;
    }

    std::memcpy(peer->cookie.value.data(), cookie_value, peer->cookie.value.size());
    peer->cookie.valid = true;
    peer->cookie.birth_time = GetMonotonicTime();
    if (peer->has_last_initiation) {
        ApplyOutgoingMacs(&peer->last_initiation, peer->static_identity.remote_static, peer);
    }
    wgnx::sysmodule::logger::Log(
        "WG handshake peer='%s': consumed cookie reply for receiver=0x%08x",
        peer->name,
        src->receiver_index);
    ok = true;

out:
    crypto::secure_clear(cookie_key, sizeof(cookie_key));
    crypto::secure_clear(cookie_value, sizeof(cookie_value));
    return ok;
}

bool noise_handshake_begin_session(wg_device *device, wg_peer *peer) {
    if (device == nullptr || peer == nullptr) {
        return false;
    }

    const HandshakeState state = peer->handshake.state;
    if (state != HandshakeState::ResponseCreated && state != HandshakeState::ResponseReceived) {
        return false;
    }
    if (!peer->handshake_material.chaining_key.valid) {
        return false;
    }

    noise_symmetric_key sending_key{};
    noise_symmetric_key receiving_key{};

    if (state == HandshakeState::ResponseReceived) {
        DeriveSessionKeys(
            &sending_key,
            &receiving_key,
            peer->handshake_material.chaining_key.bytes.data());
    } else {
        DeriveSessionKeys(
            &receiving_key,
            &sending_key,
            peer->handshake_material.chaining_key.bytes.data());
    }

    noise_keypair new_keypair{};
    new_keypair.Establish(
        peer->handshake.local_index,
        peer->handshake.remote_index,
        GetMonotonicTime(),
        sending_key,
        receiving_key);
    if (!new_keypair.IsValid()) {
        return false;
    }

    if (state == HandshakeState::ResponseReceived) {
        peer->previous_keypair.Reset();
        if (peer->next_keypair.IsValid()) {
            peer->previous_keypair = std::move(peer->next_keypair);
            peer->next_keypair.Reset();
            peer->current_keypair.Reset();
        } else {
            peer->previous_keypair = std::move(peer->current_keypair);
            peer->current_keypair.Reset();
        }
        peer->current_keypair = std::move(new_keypair);
    } else {
        peer->next_keypair.Reset();
        peer->next_keypair = std::move(new_keypair);
        peer->previous_keypair.Reset();
    }
    new_keypair.Reset();
    ::wgnx::wireguard::wg_device_refresh_keypair_indices(device, peer);
    static_cast<void>(noise_handshake_transition(
        &peer->handshake,
        HandshakeState::SessionDerived,
        peer->name,
        "derived real session keys"));
    noise_handshake_clear_transcript(peer);
    return true;
}

HandshakePacketOutcome noise_handshake_consume_incoming_packet(
    std::span<const std::uint8_t> packet,
    wg_device *device,
    wg_peer *peer) {
    if (device == nullptr || peer == nullptr) {
        return HandshakePacketOutcome::Invalid;
    }

    const ParseResult type_result = InspectMessageType(packet);
    if (!type_result.success) {
        wgnx::sysmodule::logger::Log(
            "WG handshake peer='%s': rejected packet at type inspection err=%s",
            peer->name,
            GetParseErrorName(type_result.error));
        return HandshakePacketOutcome::Invalid;
    }

    switch (type_result.type) {
        case MessageType::HandshakeInitiation: {
            message_handshake_initiation initiation{};
            const ParseResult parse_result = ParseHandshakeInitiation(packet, initiation);
            if (!parse_result.success) {
                wgnx::sysmodule::logger::Log(
                    "WG handshake peer='%s': rejected initiation packet err=%s",
                    peer->name,
                    GetParseErrorName(parse_result.error));
                return HandshakePacketOutcome::Invalid;
            }
            if (!noise_handshake_consume_initiation(&initiation, peer)) {
                return HandshakePacketOutcome::Invalid;
            }
            const std::uint32_t local_index = wg_device_allocate_index(device);
            if (local_index == 0) {
                noise_handshake_clear_transcript(peer);
                return HandshakePacketOutcome::Invalid;
            }
            noise_handshake_set_local_index(&peer->handshake, local_index);
            wg_device_register_handshake_index(device, local_index);
            return HandshakePacketOutcome::InitiationConsumed;
        }
        case MessageType::HandshakeResponse: {
            message_handshake_response response{};
            const ParseResult parse_result = ParseHandshakeResponse(packet, response);
            if (!parse_result.success) {
                wgnx::sysmodule::logger::Log(
                    "WG handshake peer='%s': rejected response packet err=%s",
                    peer->name,
                    GetParseErrorName(parse_result.error));
                return HandshakePacketOutcome::Invalid;
            }
            return noise_handshake_consume_response(&response, device, peer)
                ? HandshakePacketOutcome::ResponseConsumed
                : HandshakePacketOutcome::Invalid;
        }
        case MessageType::CookieReply: {
            message_handshake_cookie cookie{};
            const ParseResult parse_result = ParseHandshakeCookie(packet, cookie);
            if (!parse_result.success) {
                wgnx::sysmodule::logger::Log(
                    "WG handshake peer='%s': rejected cookie reply packet err=%s",
                    peer->name,
                    GetParseErrorName(parse_result.error));
                return HandshakePacketOutcome::Invalid;
            }
            return noise_handshake_consume_cookie_reply(&cookie, device, peer)
                ? HandshakePacketOutcome::CookieReplyConsumed
                : HandshakePacketOutcome::Invalid;
        }
        case MessageType::TransportData:
        case MessageType::Invalid:
            break;
    }

    wgnx::sysmodule::logger::Log(
        "WG handshake peer='%s': rejected unsupported incoming packet type=%s",
        peer->name,
        GetMessageTypeName(type_result.type));
    return HandshakePacketOutcome::Invalid;
}

} // namespace wgnx::wireguard
