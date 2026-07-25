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
constexpr crypto::ChaCha20Nonce ZeroNonce{};
constexpr char HandshakeName[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
constexpr char IdentifierName[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
constexpr char Mac1KeyLabel[] = "mac1----";
constexpr char CookieKeyLabel[] = "cookie--";

struct HandshakeInitCache {
    crypto::Blake2sDigest chaining_key{};
    crypto::Blake2sDigest hash{};
    bool ready{false};
};

using NoiseValue = crypto::Blake2sDigest;

bool IsAllZero(crypto::ByteSpan bytes) {
    return std::ranges::all_of(bytes, [](std::uint8_t byte) { return byte == 0; });
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

void StoreBe64(std::uint8_t* out, std::uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        out[7 - i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xffU);
    }
}

void StoreBe32(std::uint8_t* out, std::uint32_t value) {
    out[0] = static_cast<std::uint8_t>((value >> 24) & 0xffU);
    out[1] = static_cast<std::uint8_t>((value >> 16) & 0xffU);
    out[2] = static_cast<std::uint8_t>((value >> 8) & 0xffU);
    out[3] = static_cast<std::uint8_t>(value & 0xffU);
}

template <std::size_t Size> crypto::ByteSpan ByteView(const std::array<std::uint8_t, Size>& data) {
    return data;
}

template <std::size_t Size> crypto::ByteSpan ByteView(const char (&data)[Size]) {
    static_assert(Size > 0);
    return {reinterpret_cast<const std::uint8_t*>(data), Size - 1};
}

const HandshakeInitCache& GetHandshakeInitCache() {
    static const HandshakeInitCache cache = [] {
        HandshakeInitCache initialized{};
        const bool chaining_key_ready = crypto::Blake2sHash(initialized.chaining_key, ByteView(HandshakeName));
        crypto::Blake2sHasher hash{};
        initialized.ready = chaining_key_ready && hash.Initialize<NoiseHashSize>() && hash.Update(initialized.chaining_key) &&
                            hash.Update(ByteView(IdentifierName)) && hash.Final(initialized.hash);
        return initialized;
    }();
    return cache;
}

bool Kdf(NoiseValue& first, crypto::ByteSpan data, const NoiseValue& chaining_key) {
    crypto::SensitiveBuffer<NoiseHashSize> secret{};
    if (!crypto::Blake2sHmac(secret.bytes(), chaining_key, data))
        return false;
    constexpr std::array<std::uint8_t, 1> FirstCounter{1};
    return crypto::Blake2sHmac(first, secret.span(), FirstCounter);
}

bool Kdf(NoiseValue& first, NoiseValue& second, crypto::ByteSpan data, const NoiseValue& chaining_key) {
    crypto::SensitiveBuffer<NoiseHashSize> secret{};
    crypto::SensitiveBuffer<NoiseHashSize + 1> second_input{};
    if (!crypto::Blake2sHmac(secret.bytes(), chaining_key, data))
        return false;
    constexpr std::array<std::uint8_t, 1> FirstCounter{1};
    if (!crypto::Blake2sHmac(first, secret.span(), FirstCounter))
        return false;
    std::ranges::copy(first, second_input.bytes().begin());
    second_input.bytes().back() = 2;
    return crypto::Blake2sHmac(second, secret.span(), second_input.span());
}

bool Kdf(NoiseValue& first, NoiseValue& second, NoiseValue& third, crypto::ByteSpan data, const NoiseValue& chaining_key) {
    crypto::SensitiveBuffer<NoiseHashSize> secret{};
    crypto::SensitiveBuffer<NoiseHashSize + 1> second_input{};
    crypto::SensitiveBuffer<NoiseHashSize + 1> third_input{};
    if (!crypto::Blake2sHmac(secret.bytes(), chaining_key, data))
        return false;
    constexpr std::array<std::uint8_t, 1> FirstCounter{1};
    if (!crypto::Blake2sHmac(first, secret.span(), FirstCounter))
        return false;
    std::ranges::copy(first, second_input.bytes().begin());
    second_input.bytes().back() = 2;
    if (!crypto::Blake2sHmac(second, secret.span(), second_input.span()))
        return false;
    std::ranges::copy(second, third_input.bytes().begin());
    third_input.bytes().back() = 3;
    return crypto::Blake2sHmac(third, secret.span(), third_input.span());
}

bool MixHash(NoiseValue& hash, crypto::ByteSpan src) {
    crypto::Blake2sHasher hasher{};
    return hasher.Initialize<NoiseHashSize>() && hasher.Update(hash) && hasher.Update(src) && hasher.Final(hash);
}

bool HandshakeInit(NoiseValue& chaining_key, NoiseValue& hash, const noise_public_key& remote_static) {
    const HandshakeInitCache& cache = GetHandshakeInitCache();
    if (!cache.ready)
        return false;
    chaining_key = cache.chaining_key;
    hash = cache.hash;
    return MixHash(hash, remote_static.bytes);
}

bool MixDh(NoiseValue& chaining_key, NoiseValue& key, const crypto::X25519Key& private_key, const crypto::X25519Key& public_key) {
    crypto::SensitiveBuffer<NoisePublicKeySize> dh{};
    if (!crypto::x25519(dh.bytes(), private_key, public_key) || IsAllZero(dh.span())) {
        return false;
    }
    return Kdf(chaining_key, key, dh.span(), chaining_key);
}

bool MixDh(NoiseValue& chaining_key, const crypto::X25519Key& private_key, const crypto::X25519Key& public_key) {
    crypto::SensitiveBuffer<NoiseHashSize> discarded{};
    return MixDh(chaining_key, discarded.bytes(), private_key, public_key);
}

bool MixPrecomputedDh(NoiseValue& chaining_key, NoiseValue& key, const noise_secret32& precomputed) {
    if (!precomputed.valid || IsAllZero(precomputed.bytes)) {
        return false;
    }

    return Kdf(chaining_key, key, precomputed.bytes, chaining_key);
}

bool MixPsk(NoiseValue& chaining_key, NoiseValue& hash, NoiseValue& key, const NoiseValue& preshared_key) {
    crypto::SensitiveBuffer<NoiseHashSize> temp_hash{};
    return Kdf(chaining_key, temp_hash.bytes(), key, preshared_key, chaining_key) && MixHash(hash, temp_hash.span());
}

bool MessageEncrypt(crypto::MutableByteSpan dst_ciphertext, crypto::ByteSpan src_plaintext, const NoiseValue& key, NoiseValue& hash) {
    if (dst_ciphertext.size() != src_plaintext.size() + NoiseTagSize) {
        return false;
    }
    crypto::Poly1305Tag tag{};
    if (!crypto::chacha20poly1305_encrypt(dst_ciphertext.first(src_plaintext.size()), tag, src_plaintext, hash, key, ZeroNonce)) {
        return false;
    }
    std::ranges::copy(tag, dst_ciphertext.begin() + static_cast<std::ptrdiff_t>(src_plaintext.size()));
    const bool ok = MixHash(hash, dst_ciphertext);
    crypto::secure_clear(tag);
    return ok;
}

bool MessageDecrypt(crypto::MutableByteSpan dst_plaintext, crypto::ByteSpan src_ciphertext, const NoiseValue& key, NoiseValue& hash) {
    if (src_ciphertext.size() < NoiseTagSize || dst_plaintext.size() != src_ciphertext.size() - NoiseTagSize) {
        return false;
    }
    crypto::Poly1305Tag tag{};
    std::ranges::copy(src_ciphertext.last(NoiseTagSize), tag.begin());
    const bool ok = crypto::chacha20poly1305_decrypt(dst_plaintext, src_ciphertext.first(dst_plaintext.size()), tag, hash, key, ZeroNonce);
    crypto::secure_clear(tag);
    return ok && MixHash(hash, src_ciphertext);
}

bool MessageEphemeral(crypto::X25519Key& ephemeral_dst, const crypto::X25519Key& ephemeral_src, NoiseValue& chaining_key,
                      NoiseValue& hash) {
    ephemeral_dst = ephemeral_src;
    return MixHash(hash, ephemeral_src) && Kdf(chaining_key, ephemeral_src, chaining_key);
}

void Tai64nNow(std::uint8_t output[TAI64NTimestampSize]) {
    wgnx::platform::timespec64 now{};
    wgnx::platform::ktime_get_real_ts64(&now);

    const std::uint64_t rounding = RoundDownToPowerOfTwo(static_cast<std::uint64_t>(wgnx::platform::NSEC_PER_SEC / InitiationsPerSecond));
    if (rounding != 0) {
        now.tv_nsec -= now.tv_nsec % static_cast<std::int64_t>(rounding);
    }

    StoreBe64(output, Tai64nBaseSeconds + static_cast<std::uint64_t>(now.tv_sec));
    StoreBe32(output + sizeof(std::uint64_t), static_cast<std::uint32_t>(now.tv_nsec));
}

bool ComputeMac1(message_handshake_initiation* message, const noise_public_key& remote_static) {
    if (message == nullptr || !remote_static.valid)
        return false;
    crypto::SensitiveBuffer<NoiseSymmetricKeySize> mac1_key{};
    crypto::Blake2sHasher key_hasher{};
    if (!key_hasher.Initialize<NoiseSymmetricKeySize>() || !key_hasher.Update(ByteView(Mac1KeyLabel)) ||
        !key_hasher.Update(remote_static.bytes) || !key_hasher.Final(mac1_key.bytes()))
        return false;

    std::array<std::uint8_t, HandshakeInitiationSize> serialized{};
    if (SerializeHandshakeInitiation(serialized, *message) != ParseError::None) {
        return false;
    }
    constexpr std::size_t mac1_input_size = HandshakeInitiationSize - (2 * NoiseMacSize);
    const bool ok = crypto::Blake2sHash(message->macs.mac1, std::span{serialized}.first(mac1_input_size), mac1_key.span());
    crypto::secure_clear(serialized);
    return ok;
}

bool ComputeMac1(message_handshake_response* message, const noise_public_key& remote_static) {
    if (message == nullptr || !remote_static.valid)
        return false;
    crypto::SensitiveBuffer<NoiseSymmetricKeySize> mac1_key{};
    crypto::Blake2sHasher key_hasher{};
    if (!key_hasher.Initialize<NoiseSymmetricKeySize>() || !key_hasher.Update(ByteView(Mac1KeyLabel)) ||
        !key_hasher.Update(remote_static.bytes) || !key_hasher.Final(mac1_key.bytes()))
        return false;

    std::array<std::uint8_t, HandshakeResponseSize> serialized{};
    if (SerializeHandshakeResponse(serialized, *message) != ParseError::None) {
        return false;
    }
    constexpr std::size_t mac1_input_size = HandshakeResponseSize - (2 * NoiseMacSize);
    const bool ok = crypto::Blake2sHash(message->macs.mac1, std::span{serialized}.first(mac1_input_size), mac1_key.span());
    crypto::secure_clear(serialized);
    return ok;
}

template <typename Message>
bool VerifyMac1(const Message& message, const noise_public_key& local_static, bool (*compute)(Message*, const noise_public_key&)) {
    if (!local_static.valid) {
        return false;
    }

    Message expected = message;
    const bool computed = compute(&expected, local_static);
    const bool matches = computed && crypto::secure_equal(expected.macs.mac1, message.macs.mac1);
    crypto::secure_clear(expected.macs.mac1);
    return matches;
}

bool ComputeCookieKey(NoiseValue& key, const noise_public_key& remote_static) {
    if (!remote_static.valid) {
        return false;
    }

    crypto::Blake2sHasher hasher{};
    return hasher.Initialize<NoiseSymmetricKeySize>() && hasher.Update(ByteView(CookieKeyLabel)) && hasher.Update(remote_static.bytes) &&
           hasher.Final(key);
}

template <typename T, std::size_t Size>
bool ComputeMac2(const T& message, const noise_cookie& cookie, std::array<std::uint8_t, NoiseMacSize>& out_mac2,
                 ParseError (*serialize)(std::span<std::uint8_t>, const T&)) {
    std::array<std::uint8_t, Size> serialized{};
    if (serialize(serialized, message) != ParseError::None) {
        return false;
    }
    constexpr std::size_t mac2_input_size = Size - NoiseMacSize;
    const bool ok = crypto::Blake2sHash(out_mac2, std::span{serialized}.first(mac2_input_size), cookie.value);
    crypto::secure_clear(serialized);
    return ok;
}

bool ComputeMac2(const message_handshake_initiation& message, const noise_cookie& cookie,
                 std::array<std::uint8_t, NoiseMacSize>& out_mac2) {
    return ComputeMac2<message_handshake_initiation, HandshakeInitiationSize>(message, cookie, out_mac2, SerializeHandshakeInitiation);
}

bool ComputeMac2(const message_handshake_response& message, const noise_cookie& cookie, std::array<std::uint8_t, NoiseMacSize>& out_mac2) {
    return ComputeMac2<message_handshake_response, HandshakeResponseSize>(message, cookie, out_mac2, SerializeHandshakeResponse);
}

bool MatchesCookieReceiverIndex(const wg_device* device, std::uint32_t receiver_index) {
    if (device == nullptr || receiver_index == 0) {
        return false;
    }

    const ::wgnx::wireguard::wg_index_slot slot = ::wgnx::wireguard::wg_device_lookup_index_slot(device, receiver_index);
    return slot == ::wgnx::wireguard::wg_index_slot::Handshake || slot == ::wgnx::wireguard::wg_index_slot::CurrentKeypair ||
           slot == ::wgnx::wireguard::wg_index_slot::NextKeypair || slot == ::wgnx::wireguard::wg_index_slot::PreviousKeypair;
}

template <typename T> bool ApplyOutgoingMacs(T* message, const noise_public_key& remote_static, wg_peer* peer) {
    if (message == nullptr) {
        return false;
    }

    message->macs = {};
    if (!ComputeMac1(message, remote_static))
        return false;
    if (peer != nullptr) {
        noise_cookie_record_last_mac1(&peer->cookie, message->macs.mac1.data());
        if (noise_cookie_is_valid(&peer->cookie)) {
            if (!ComputeMac2(*message, peer->cookie, message->macs.mac2))
                return false;
        }
    }
    return true;
}

void ClearHandshakeTranscript(wg_peer* peer) {
    if (peer == nullptr) {
        return;
    }

    peer->handshake_material.ephemeral_private.Clear();
    crypto::secure_clear(peer->handshake_material.ephemeral_public.bytes);
    peer->handshake_material.ephemeral_public.valid = false;
    crypto::secure_clear(peer->handshake_material.remote_ephemeral.bytes);
    peer->handshake_material.remote_ephemeral.valid = false;
    peer->handshake_material.chaining_key.Clear();
    peer->handshake_material.hash.Clear();
    peer->handshake.local_index = 0;
    peer->handshake.remote_index = 0;
}

bool DeriveSessionKeys(noise_symmetric_key* first_dst, noise_symmetric_key* second_dst, const NoiseValue& chaining_key) {
    if (first_dst == nullptr || second_dst == nullptr) {
        return false;
    }

    if (!Kdf(first_dst->bytes, second_dst->bytes, {}, chaining_key))
        return false;
    first_dst->valid = true;
    second_dst->valid = true;
    return true;
}

} // namespace

// Internal self-test adapter. Deliberately omitted from handshake.hpp so the
// production protocol surface stays independent of its deterministic fixtures.
bool RunHandshakeCryptoSelfTest() {
    static constexpr NoiseValue ChainingKey = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    };
    static constexpr char Input[] = "noise-kdf-vector";
    static constexpr NoiseValue ExpectedFirst = {
        0x81, 0x58, 0x86, 0xce, 0xaf, 0xbd, 0xb3, 0x05, 0x17, 0x99, 0x3b, 0x0f, 0x79, 0xa8, 0xa8, 0xd7,
        0x39, 0x83, 0x1b, 0xb2, 0x48, 0xf7, 0x86, 0x0c, 0xa4, 0xb7, 0x95, 0xe0, 0x18, 0x03, 0x00, 0xa6,
    };
    static constexpr NoiseValue ExpectedSecond = {
        0x76, 0x28, 0x10, 0xa0, 0x5a, 0x0b, 0xec, 0x8f, 0xf4, 0x47, 0xfc, 0xba, 0x27, 0xdb, 0x05, 0x44,
        0x21, 0x24, 0x8b, 0x7e, 0x42, 0xf6, 0x98, 0x6d, 0x75, 0x39, 0xcb, 0xbb, 0xba, 0x61, 0x0d, 0x72,
    };
    static constexpr NoiseValue ExpectedThird = {
        0xf6, 0x0b, 0x2f, 0x4c, 0x8e, 0x0e, 0x3d, 0xc3, 0x27, 0x72, 0x1a, 0xe4, 0x43, 0xd5, 0x76, 0xd4,
        0x79, 0xc1, 0xee, 0xfb, 0x37, 0xf9, 0x69, 0xc8, 0x08, 0x6d, 0x5e, 0x36, 0x63, 0x69, 0x3b, 0x10,
    };

    NoiseValue first{};
    NoiseValue second{};
    NoiseValue third{};
    const bool ok = Kdf(first, second, third, ByteView(Input), ChainingKey) && crypto::secure_equal(first, ExpectedFirst) &&
                    crypto::secure_equal(second, ExpectedSecond) && crypto::secure_equal(third, ExpectedThird);
    crypto::secure_clear(first);
    crypto::secure_clear(second);
    crypto::secure_clear(third);
    return ok;
}

const char* GetHandshakeStateName(HandshakeState state) {
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

const char* GetHandshakePacketOutcomeName(HandshakePacketOutcome outcome) {
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

void noise_handshake_clear_transcript(wg_peer* peer) {
    ClearHandshakeTranscript(peer);
}

void noise_handshake_init(noise_handshake* handshake) {
    if (handshake == nullptr) {
        return;
    }

    *handshake = {};
    handshake->state = HandshakeState::Zeroed;
    handshake->last_transition = GetMonotonicTime();
}

bool noise_handshake_transition(noise_handshake* handshake, HandshakeState new_state, const char* peer_name, const char* reason) {
    if (handshake == nullptr) {
        return false;
    }

    const HandshakeState old_state = handshake->state;
    handshake->state = new_state;
    handshake->last_transition = GetMonotonicTime();
    ++handshake->transition_count;

    wgnx::sysmodule::logger::Log("WG handshake peer='%s' %s -> %s reason='%s' local=0x%08x remote=0x%08x transitions=%u",
                                 peer_name != nullptr ? peer_name : "<unnamed>", GetHandshakeStateName(old_state),
                                 GetHandshakeStateName(new_state), reason != nullptr ? reason : "none", handshake->local_index,
                                 handshake->remote_index, handshake->transition_count);
    return old_state != new_state;
}

void noise_handshake_set_local_index(noise_handshake* handshake, std::uint32_t local_index) {
    if (handshake == nullptr) {
        return;
    }

    handshake->local_index = local_index;
}

void noise_handshake_set_remote_index(noise_handshake* handshake, std::uint32_t remote_index) {
    if (handshake == nullptr) {
        return;
    }

    handshake->remote_index = remote_index;
}

bool noise_handshake_create_initiation(message_handshake_initiation* dst, wg_peer* peer) {
    if (dst == nullptr || peer == nullptr || !peer->static_identity.static_private.valid || !peer->static_identity.static_public.valid ||
        !peer->static_identity.remote_static.valid || !peer->handshake_material.precomputed_static_static.valid ||
        peer->handshake.local_index == 0) {
        return false;
    }

    crypto::SensitiveBuffer<TAI64NTimestampSize> timestamp{};
    crypto::SensitiveBuffer<NoiseSymmetricKeySize> key{};
    crypto::SensitiveBuffer<NoisePublicKeySize> ephemeral_private{};

    *dst = {};
    SetMessageType(dst->type, MessageType::HandshakeInitiation);
    dst->sender_index = peer->handshake.local_index;

    if (!HandshakeInit(peer->handshake_material.chaining_key.bytes, peer->handshake_material.hash.bytes,
                       peer->static_identity.remote_static))
        return false;
    peer->handshake_material.chaining_key.valid = true;
    peer->handshake_material.hash.valid = true;

    wgnx::platform::get_random_bytes(ephemeral_private.bytes().data(), ephemeral_private.bytes().size());
    ephemeral_private.bytes()[0] &= 248U;
    ephemeral_private.bytes()[31] &= 127U;
    ephemeral_private.bytes()[31] |= 64U;
    peer->handshake_material.ephemeral_private.bytes = ephemeral_private.bytes();
    peer->handshake_material.ephemeral_private.valid = true;

    if (!crypto::x25519_public_key(peer->handshake_material.ephemeral_public.bytes, peer->handshake_material.ephemeral_private.bytes))
        return false;
    peer->handshake_material.ephemeral_public.valid = true;

    if (!MessageEphemeral(dst->unencrypted_ephemeral, peer->handshake_material.ephemeral_public.bytes,
                          peer->handshake_material.chaining_key.bytes, peer->handshake_material.hash.bytes))
        return false;

    if (!MixDh(peer->handshake_material.chaining_key.bytes, key.bytes(), peer->handshake_material.ephemeral_private.bytes,
               peer->static_identity.remote_static.bytes))
        return false;
    if (!MessageEncrypt(dst->encrypted_static, peer->static_identity.static_public.bytes, key.bytes(), peer->handshake_material.hash.bytes))
        return false;
    if (!MixPrecomputedDh(peer->handshake_material.chaining_key.bytes, key.bytes(), peer->handshake_material.precomputed_static_static))
        return false;

    Tai64nNow(timestamp.bytes().data());
    if (!MessageEncrypt(dst->encrypted_timestamp, timestamp.span(), key.bytes(), peer->handshake_material.hash.bytes))
        return false;

    if (!ApplyOutgoingMacs(dst, peer->static_identity.remote_static, peer))
        return false;
    peer->last_initiation = *dst;
    peer->has_last_initiation = true;

    static_cast<void>(
        noise_handshake_transition(&peer->handshake, HandshakeState::InitiationCreated, peer->name, "created real handshake initiation"));

    return true;
}

bool noise_handshake_consume_initiation(const message_handshake_initiation* src, wg_peer* peer) {
    if (src == nullptr || peer == nullptr || !peer->static_identity.static_private.valid || !peer->static_identity.static_public.valid ||
        !peer->static_identity.remote_static.valid || !peer->handshake_material.precomputed_static_static.valid) {
        return false;
    }
    crypto::SensitiveBuffer<NoiseSymmetricKeySize> key{};
    crypto::SensitiveBuffer<NoiseHashSize> chaining_key{};
    crypto::SensitiveBuffer<NoiseHashSize> hash{};
    crypto::SensitiveBuffer<NoisePublicKeySize> remote_ephemeral{};
    crypto::SensitiveBuffer<NoisePublicKeySize> remote_static{};
    crypto::SensitiveBuffer<TAI64NTimestampSize> timestamp{};
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

    if (!HandshakeInit(chaining_key.bytes(), hash.bytes(), peer->static_identity.static_public) ||
        !MessageEphemeral(remote_ephemeral.bytes(), src->unencrypted_ephemeral, chaining_key.bytes(), hash.bytes()) ||
        !MixDh(chaining_key.bytes(), key.bytes(), peer->static_identity.static_private.bytes, remote_ephemeral.bytes())) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': initiation es DH failed", peer->name);
        goto out;
    }
    if (!MessageDecrypt(remote_static.mutable_span(), src->encrypted_static, key.bytes(), hash.bytes())) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': initiation static decrypt failed", peer->name);
        goto out;
    }
    if (!crypto::secure_equal(remote_static.bytes(), peer->static_identity.remote_static.bytes)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': initiation remote static mismatch", peer->name);
        goto out;
    }
    if (!MixPrecomputedDh(chaining_key.bytes(), key.bytes(), peer->handshake_material.precomputed_static_static)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': initiation static-static DH failed", peer->name);
        goto out;
    }
    if (!MessageDecrypt(timestamp.mutable_span(), src->encrypted_timestamp, key.bytes(), hash.bytes())) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': initiation timestamp decrypt failed", peer->name);
        goto out;
    }

    if (peer->handshake.has_last_initiation_timestamp &&
        !std::lexicographical_compare(peer->handshake.last_initiation_timestamp.begin(), peer->handshake.last_initiation_timestamp.end(),
                                      timestamp.bytes().begin(), timestamp.bytes().end())) {
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

    peer->handshake_material.remote_ephemeral.bytes = remote_ephemeral.bytes();
    peer->handshake_material.remote_ephemeral.valid = true;
    peer->handshake_material.hash.bytes = hash.bytes();
    peer->handshake_material.hash.valid = true;
    peer->handshake_material.chaining_key.bytes = chaining_key.bytes();
    peer->handshake_material.chaining_key.valid = true;
    peer->handshake.remote_index = src->sender_index;
    std::ranges::copy(timestamp.bytes(), peer->handshake.last_initiation_timestamp.begin());
    peer->handshake.has_last_initiation_timestamp = true;
    peer->handshake.last_initiation_consumption = now;
    static_cast<void>(
        noise_handshake_transition(&peer->handshake, HandshakeState::InitiationReceived, peer->name, "consumed real handshake initiation"));
    ok = true;

out:
    return ok;
}

bool noise_handshake_create_response(message_handshake_response* dst, wg_peer* peer) {
    if (dst == nullptr || peer == nullptr || !peer->static_identity.remote_static.valid ||
        !peer->handshake_material.remote_ephemeral.valid || peer->handshake.local_index == 0 || peer->handshake.remote_index == 0 ||
        peer->handshake.state != HandshakeState::InitiationReceived) {
        return false;
    }

    crypto::SensitiveBuffer<NoiseSymmetricKeySize> key{};
    crypto::SensitiveBuffer<NoisePublicKeySize> ephemeral_private{};

    *dst = {};
    SetMessageType(dst->type, MessageType::HandshakeResponse);
    dst->receiver_index = peer->handshake.remote_index;

    wgnx::platform::get_random_bytes(ephemeral_private.bytes().data(), ephemeral_private.bytes().size());
    ephemeral_private.bytes()[0] &= 248U;
    ephemeral_private.bytes()[31] &= 127U;
    ephemeral_private.bytes()[31] |= 64U;
    peer->handshake_material.ephemeral_private.bytes = ephemeral_private.bytes();
    peer->handshake_material.ephemeral_private.valid = true;

    if (!crypto::x25519_public_key(peer->handshake_material.ephemeral_public.bytes, peer->handshake_material.ephemeral_private.bytes))
        return false;
    peer->handshake_material.ephemeral_public.valid = true;

    if (!MessageEphemeral(dst->unencrypted_ephemeral, peer->handshake_material.ephemeral_public.bytes,
                          peer->handshake_material.chaining_key.bytes, peer->handshake_material.hash.bytes))
        return false;
    if (!MixDh(peer->handshake_material.chaining_key.bytes, peer->handshake_material.ephemeral_private.bytes,
               peer->handshake_material.remote_ephemeral.bytes)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': response ee DH failed", peer->name);
        return false;
    }
    if (!MixDh(peer->handshake_material.chaining_key.bytes, peer->handshake_material.ephemeral_private.bytes,
               peer->static_identity.remote_static.bytes)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': response se DH failed", peer->name);
        return false;
    }

    if (!MixPsk(peer->handshake_material.chaining_key.bytes, peer->handshake_material.hash.bytes, key.bytes(),
                peer->static_identity.preshared_key.bytes))
        return false;
    if (!MessageEncrypt(dst->encrypted_nothing, {}, key.bytes(), peer->handshake_material.hash.bytes)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': response payload encrypt failed", peer->name);
        return false;
    }

    dst->sender_index = peer->handshake.local_index;
    if (!ApplyOutgoingMacs(dst, peer->static_identity.remote_static, peer))
        return false;
    static_cast<void>(
        noise_handshake_transition(&peer->handshake, HandshakeState::ResponseCreated, peer->name, "created real handshake response"));
    return true;
}

bool noise_handshake_consume_response(const message_handshake_response* src, const wg_device* device, wg_peer* peer) {
    if (src == nullptr || device == nullptr || peer == nullptr || !peer->static_identity.static_private.valid ||
        !peer->handshake_material.ephemeral_private.valid || peer->handshake.state != HandshakeState::InitiationCreated) {
        return false;
    }

    crypto::SensitiveBuffer<NoiseSymmetricKeySize> key{};
    crypto::SensitiveBuffer<NoiseHashSize> hash{};
    crypto::SensitiveBuffer<NoiseHashSize> chaining_key{};
    crypto::SensitiveBuffer<NoisePublicKeySize> remote_ephemeral{};
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
    if (!::wgnx::wireguard::wg_device_index_matches_slot(device, ::wgnx::wireguard::wg_index_slot::Handshake, src->receiver_index)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': response receiver index mismatch local=0x%08x got=0x%08x", peer->name,
                                     peer->handshake.local_index, src->receiver_index);
        goto out;
    }
    if (peer->current_keypair.IsValid() && src->sender_index == peer->current_keypair.RemoteIndex()) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected replayed response sender=0x%08x", peer->name, src->sender_index);
        goto out;
    }

    hash.bytes() = peer->handshake_material.hash.bytes;
    chaining_key.bytes() = peer->handshake_material.chaining_key.bytes;

    if (!MessageEphemeral(remote_ephemeral.bytes(), src->unencrypted_ephemeral, chaining_key.bytes(), hash.bytes()) ||
        !MixDh(chaining_key.bytes(), peer->handshake_material.ephemeral_private.bytes, remote_ephemeral.bytes())) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': response ee DH failed", peer->name);
        goto out;
    }
    if (!MixDh(chaining_key.bytes(), peer->static_identity.static_private.bytes, remote_ephemeral.bytes())) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': response se DH failed", peer->name);
        goto out;
    }
    if (!MixPsk(chaining_key.bytes(), hash.bytes(), key.bytes(), peer->static_identity.preshared_key.bytes) ||
        !MessageDecrypt({}, src->encrypted_nothing, key.bytes(), hash.bytes())) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': response payload decrypt failed", peer->name);
        goto out;
    }

    peer->handshake_material.remote_ephemeral.bytes = remote_ephemeral.bytes();
    peer->handshake_material.remote_ephemeral.valid = true;
    peer->handshake_material.hash.bytes = hash.bytes();
    peer->handshake_material.hash.valid = true;
    peer->handshake_material.chaining_key.bytes = chaining_key.bytes();
    peer->handshake_material.chaining_key.valid = true;
    peer->handshake.remote_index = src->sender_index;
    static_cast<void>(
        noise_handshake_transition(&peer->handshake, HandshakeState::ResponseReceived, peer->name, "consumed real handshake response"));
    ok = true;

out:
    return ok;
}

bool noise_handshake_consume_cookie_reply(const message_handshake_cookie* src, const wg_device* device, wg_peer* peer) {
    if (src == nullptr || device == nullptr || peer == nullptr || !peer->static_identity.remote_static.valid) {
        return false;
    }

    crypto::SensitiveBuffer<NoiseSymmetricKeySize> cookie_key{};
    crypto::SensitiveBuffer<CookieValueSize> cookie_value{};
    crypto::Poly1305Tag cookie_tag{};
    bool ok = false;

    if (GetMessageType(src->type) != MessageType::CookieReply) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected cookie reply with wrong message type", peer->name);
        goto out;
    }
    if (!MatchesCookieReceiverIndex(device, src->receiver_index)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected cookie reply receiver mismatch local=0x%08x got=0x%08x", peer->name,
                                     peer->handshake.local_index, src->receiver_index);
        goto out;
    }
    if (!peer->cookie.has_last_mac1) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected cookie reply without prior mac1", peer->name);
        goto out;
    }
    if (!ComputeCookieKey(cookie_key.bytes(), peer->static_identity.remote_static)) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': failed to derive cookie reply key", peer->name);
        goto out;
    }
    std::ranges::copy(std::span{src->encrypted_cookie}.last(NoiseTagSize), cookie_tag.begin());
    if (!crypto::xchacha20poly1305_decrypt(cookie_value.mutable_span(), std::span{src->encrypted_cookie}.first(CookieValueSize), cookie_tag,
                                           peer->cookie.last_mac1, cookie_key.bytes(), src->nonce)) {
        crypto::secure_clear(cookie_tag);
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': cookie reply decrypt failed", peer->name);
        goto out;
    }
    crypto::secure_clear(cookie_tag);

    peer->cookie.value = cookie_value.bytes();
    peer->cookie.valid = true;
    peer->cookie.birth_time = GetMonotonicTime();
    if (peer->has_last_initiation) {
        if (!ApplyOutgoingMacs(&peer->last_initiation, peer->static_identity.remote_static, peer))
            goto out;
    }
    wgnx::sysmodule::logger::Log("WG handshake peer='%s': consumed cookie reply for receiver=0x%08x", peer->name, src->receiver_index);
    ok = true;

out:
    return ok;
}

bool noise_handshake_begin_session(wg_device* device, wg_peer* peer) {
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
        if (!DeriveSessionKeys(&sending_key, &receiving_key, peer->handshake_material.chaining_key.bytes)) {
            return false;
        }
    } else {
        if (!DeriveSessionKeys(&receiving_key, &sending_key, peer->handshake_material.chaining_key.bytes)) {
            return false;
        }
    }

    noise_keypair new_keypair{};
    new_keypair.Establish(peer->handshake.local_index, peer->handshake.remote_index, GetMonotonicTime(), sending_key, receiving_key, 0,
                          state == HandshakeState::ResponseReceived);
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
    static_cast<void>(
        noise_handshake_transition(&peer->handshake, HandshakeState::SessionDerived, peer->name, "derived real session keys"));
    noise_handshake_clear_transcript(peer);
    return true;
}

HandshakePacketOutcome noise_handshake_consume_incoming_packet(std::span<const std::uint8_t> packet, wg_device* device, wg_peer* peer) {
    if (device == nullptr || peer == nullptr) {
        return HandshakePacketOutcome::Invalid;
    }

    const ParseResult type_result = InspectMessageType(packet);
    if (!type_result.success) {
        wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected packet at type inspection err=%s", peer->name,
                                     GetParseErrorName(type_result.error));
        return HandshakePacketOutcome::Invalid;
    }

    switch (type_result.type) {
    case MessageType::HandshakeInitiation: {
        message_handshake_initiation initiation{};
        const ParseResult parse_result = ParseHandshakeInitiation(packet, initiation);
        if (!parse_result.success) {
            wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected initiation packet err=%s", peer->name,
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
            wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected response packet err=%s", peer->name,
                                         GetParseErrorName(parse_result.error));
            return HandshakePacketOutcome::Invalid;
        }
        return noise_handshake_consume_response(&response, device, peer) ? HandshakePacketOutcome::ResponseConsumed
                                                                         : HandshakePacketOutcome::Invalid;
    }
    case MessageType::CookieReply: {
        message_handshake_cookie cookie{};
        const ParseResult parse_result = ParseHandshakeCookie(packet, cookie);
        if (!parse_result.success) {
            wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected cookie reply packet err=%s", peer->name,
                                         GetParseErrorName(parse_result.error));
            return HandshakePacketOutcome::Invalid;
        }
        return noise_handshake_consume_cookie_reply(&cookie, device, peer) ? HandshakePacketOutcome::CookieReplyConsumed
                                                                           : HandshakePacketOutcome::Invalid;
    }
    case MessageType::TransportData:
    case MessageType::Invalid:
        break;
    }

    wgnx::sysmodule::logger::Log("WG handshake peer='%s': rejected unsupported incoming packet type=%s", peer->name,
                                 GetMessageTypeName(type_result.type));
    return HandshakePacketOutcome::Invalid;
}

} // namespace wgnx::wireguard
