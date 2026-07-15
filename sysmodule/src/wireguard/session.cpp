#include "wireguard/session.hpp"

#include "wgnx/platform/clock.hpp"
#include "wireguard/crypto/primitives.hpp"

#include <cstddef>
#include <cstring>
#include <memory>
#include <span>
#include <string_view>
#include <utility>

namespace wgnx::wireguard {

namespace {

constexpr std::size_t WireGuardEncodedKeySize = 44;
constexpr char Base64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int DecodeBase64Char(char ch) {
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A';
    }
    if (ch >= 'a' && ch <= 'z') {
        return ch - 'a' + 26;
    }
    if (ch >= '0' && ch <= '9') {
        return ch - '0' + 52;
    }
    if (ch == '+') {
        return 62;
    }
    if (ch == '/') {
        return 63;
    }
    return -1;
}

bool IsAllZero(std::span<const std::uint8_t> bytes) {
    std::uint8_t value = 0;
    for (const std::uint8_t byte : bytes) {
        value |= byte;
    }
    return value == 0;
}

void ClampX25519PrivateKey(std::array<std::uint8_t, NoisePublicKeySize> &bytes) {
    bytes[0] &= 248U;
    bytes[31] &= 127U;
    bytes[31] |= 64U;
}

bool DecodeWireGuardKey(
    std::array<std::uint8_t, NoisePublicKeySize> &out,
    std::string_view text) {
    if (text.size() != WireGuardEncodedKeySize || text.back() != '=') {
        return false;
    }

    std::size_t out_index = 0;
    for (std::size_t i = 0; i < text.size(); i += 4) {
        const bool last_group = (i + 4) == text.size();
        const int a = DecodeBase64Char(text[i]);
        const int b = DecodeBase64Char(text[i + 1]);
        const int c = text[i + 2] == '=' ? -2 : DecodeBase64Char(text[i + 2]);
        const int d = text[i + 3] == '=' ? -2 : DecodeBase64Char(text[i + 3]);
        if (a < 0 || b < 0 || c == -1 || d == -1) {
            return false;
        }
        if (!last_group && (c < 0 || d < 0)) {
            return false;
        }
        if (last_group) {
            if (c < 0 || d != -2) {
                return false;
            }
        } else if (c < 0 || d < 0) {
            return false;
        }

        const std::uint32_t value =
            (static_cast<std::uint32_t>(a) << 18) |
            (static_cast<std::uint32_t>(b) << 12) |
            (static_cast<std::uint32_t>(c < 0 ? 0 : c) << 6) |
            static_cast<std::uint32_t>(d < 0 ? 0 : d);

        if (out_index >= NoisePublicKeySize) {
            return false;
        }
        out[out_index++] = static_cast<std::uint8_t>((value >> 16) & 0xffU);
        if (c >= 0) {
            if (out_index >= NoisePublicKeySize) {
                return false;
            }
            out[out_index++] = static_cast<std::uint8_t>((value >> 8) & 0xffU);
        }
        if (d >= 0) {
            if (out_index >= NoisePublicKeySize) {
                return false;
            }
            out[out_index++] = static_cast<std::uint8_t>(value & 0xffU);
        }
    }

    return out_index == NoisePublicKeySize;
}

bool EncodeWireGuardKey(
    std::span<char> out_text,
    const std::array<std::uint8_t, NoisePublicKeySize> &bytes) {
    if (out_text.size() < (WireGuardEncodedKeySize + 1)) {
        return false;
    }

    std::size_t out_index = 0;
    for (std::size_t i = 0; i < NoisePublicKeySize; i += 3) {
        const int remaining = static_cast<int>(NoisePublicKeySize - i);
        const std::uint32_t value =
            (static_cast<std::uint32_t>(bytes[i]) << 16) |
            (static_cast<std::uint32_t>(remaining > 1 ? bytes[i + 1] : 0) << 8) |
            static_cast<std::uint32_t>(remaining > 2 ? bytes[i + 2] : 0);

        out_text[out_index++] = Base64Alphabet[(value >> 18) & 0x3fU];
        out_text[out_index++] = Base64Alphabet[(value >> 12) & 0x3fU];
        out_text[out_index++] = remaining > 1 ? Base64Alphabet[(value >> 6) & 0x3fU] : '=';
        out_text[out_index++] = remaining > 2 ? Base64Alphabet[value & 0x3fU] : '=';
    }

    out_text[out_index] = '\0';
    return out_index == WireGuardEncodedKeySize;
}

} // namespace

namespace {

template <typename Secret>
void MoveSecret(Secret &destination, Secret &source) {
    destination.Clear();
    destination.bytes = source.bytes;
    destination.valid = source.valid;
    source.Clear();
}

} // namespace

noise_private_key::~noise_private_key() {
    Clear();
}

noise_private_key::noise_private_key(noise_private_key &&other) noexcept {
    MoveSecret(*this, other);
}

noise_private_key &noise_private_key::operator=(noise_private_key &&other) noexcept {
    if (this != std::addressof(other)) {
        MoveSecret(*this, other);
    }
    return *this;
}

void noise_private_key::Clear() {
    crypto::secure_clear(bytes.data(), bytes.size());
    valid = false;
}

noise_symmetric_key::~noise_symmetric_key() {
    Clear();
}

noise_symmetric_key::noise_symmetric_key(noise_symmetric_key &&other) noexcept {
    MoveSecret(*this, other);
}

noise_symmetric_key &noise_symmetric_key::operator=(noise_symmetric_key &&other) noexcept {
    if (this != std::addressof(other)) {
        MoveSecret(*this, other);
    }
    return *this;
}

void noise_symmetric_key::Clear() {
    crypto::secure_clear(bytes.data(), bytes.size());
    valid = false;
}

noise_secret32::~noise_secret32() {
    Clear();
}

noise_secret32::noise_secret32(noise_secret32 &&other) noexcept {
    MoveSecret(*this, other);
}

noise_secret32 &noise_secret32::operator=(noise_secret32 &&other) noexcept {
    if (this != std::addressof(other)) {
        MoveSecret(*this, other);
    }
    return *this;
}

void noise_secret32::Clear() {
    crypto::secure_clear(bytes.data(), bytes.size());
    valid = false;
}

noise_cookie::~noise_cookie() {
    Clear();
}

noise_cookie::noise_cookie(noise_cookie &&other) noexcept {
    *this = std::move(other);
}

noise_cookie &noise_cookie::operator=(noise_cookie &&other) noexcept {
    if (this != std::addressof(other)) {
        Clear();
        value = other.value;
        last_mac1 = other.last_mac1;
        birth_time = other.birth_time;
        valid = other.valid;
        has_last_mac1 = other.has_last_mac1;
        other.Clear();
    }
    return *this;
}

void noise_cookie::Clear() {
    crypto::secure_clear(value.data(), value.size());
    crypto::secure_clear(last_mac1.data(), last_mac1.size());
    birth_time = {};
    valid = false;
    has_last_mac1 = false;
}

MonotonicTimePoint GetMonotonicTime() {
    return MonotonicTimePoint{
        MonotonicDuration{wgnx::platform::ktime_get_coarse_boottime_ns()}};
}

void noise_cookie_reset(noise_cookie *cookie) {
    if (cookie == nullptr) {
        return;
    }

    cookie->Clear();
}

void noise_cookie_record_last_mac1(noise_cookie *cookie, const std::uint8_t mac1[NoiseMacSize]) {
    if (cookie == nullptr || mac1 == nullptr) {
        return;
    }

    std::memcpy(cookie->last_mac1.data(), mac1, cookie->last_mac1.size());
    cookie->has_last_mac1 = true;
}

bool noise_cookie_is_valid(const noise_cookie *cookie) {
    if (cookie == nullptr || !cookie->valid) {
        return false;
    }

    constexpr MonotonicDuration CookieLifetime = std::chrono::seconds{120};
    const MonotonicTimePoint now = GetMonotonicTime();
    return cookie->birth_time > MonotonicTimePoint{} && now >= cookie->birth_time &&
           (now - cookie->birth_time) <= CookieLifetime;
}

void noise_static_identity_reset(noise_static_identity *identity) {
    if (identity == nullptr) {
        return;
    }

    identity->static_private.Clear();
    crypto::secure_clear(identity->static_public.bytes.data(), identity->static_public.bytes.size());
    identity->static_public.valid = false;
    crypto::secure_clear(identity->remote_static.bytes.data(), identity->remote_static.bytes.size());
    identity->remote_static.valid = false;
    identity->preshared_key.Clear();
}

void noise_handshake_material_reset(noise_handshake_material *material) {
    if (material == nullptr) {
        return;
    }

    material->ephemeral_private.Clear();
    crypto::secure_clear(material->ephemeral_public.bytes.data(), material->ephemeral_public.bytes.size());
    material->ephemeral_public.valid = false;
    crypto::secure_clear(material->remote_ephemeral.bytes.data(), material->remote_ephemeral.bytes.size());
    material->remote_ephemeral.valid = false;
    material->precomputed_static_static.Clear();
    material->chaining_key.Clear();
    material->hash.Clear();
}

bool ReplayWindow::TryAdvance(std::uint64_t counter) {
    std::uint64_t index_block = counter >> BlockBitLog;
    if (counter > m_highest_counter) {
        const std::uint64_t current = m_highest_counter >> BlockBitLog;
        std::uint64_t diff = index_block - current;
        if (diff > RingBlocks) {
            diff = RingBlocks;
        }
        for (std::uint64_t i = current + 1; i <= current + diff; ++i) {
            m_ring[i & BlockMask] = 0;
        }
        m_highest_counter = counter;
    } else if (m_initialized && m_highest_counter - counter > WindowSize) {
        return false;
    }

    index_block &= BlockMask;
    const std::uint64_t index_bit = counter & BitMask;
    const std::uint64_t old_block = m_ring[index_block];
    const std::uint64_t new_block = old_block | (std::uint64_t{1} << index_bit);
    m_ring[index_block] = new_block;
    m_initialized = true;
    return old_block != new_block;
}

void ReplayWindow::Reset() {
    m_highest_counter = 0;
    m_ring.fill(0);
    m_initialized = false;
}

void noise_keypair::Establish(
    std::uint32_t local_index,
    std::uint32_t remote_index,
    MonotonicTimePoint birth_time,
    const noise_symmetric_key &sending_key,
    const noise_symmetric_key &receiving_key,
    std::uint64_t send_counter) {
    Reset();
    if (local_index == 0 || remote_index == 0 ||
        birth_time < MonotonicTimePoint{} ||
        !sending_key.valid || !receiving_key.valid) {
        return;
    }

    m_state = KeypairState::Established;
    m_local_index = local_index;
    m_remote_index = remote_index;
    m_birth_time = birth_time;
    m_sending_key.bytes = sending_key.bytes;
    m_sending_key.valid = sending_key.valid;
    m_receiving_key.bytes = receiving_key.bytes;
    m_receiving_key.valid = receiving_key.valid;
    m_send_counter = send_counter;
}

void noise_keypair::Reset() {
    m_state = KeypairState::Empty;
    m_local_index = 0;
    m_remote_index = 0;
    m_send_counter = 0;
    m_birth_time = {};
    m_sending_key.Clear();
    m_receiving_key.Clear();
    m_receive_replay_window.Reset();
}

noise_keypair::~noise_keypair() {
    Reset();
}

noise_keypair::noise_keypair(noise_keypair &&other) noexcept {
    *this = std::move(other);
}

noise_keypair &noise_keypair::operator=(noise_keypair &&other) noexcept {
    if (this != std::addressof(other)) {
        Reset();
        m_state = other.m_state;
        m_local_index = other.m_local_index;
        m_remote_index = other.m_remote_index;
        m_send_counter = other.m_send_counter;
        m_birth_time = other.m_birth_time;
        m_sending_key = std::move(other.m_sending_key);
        m_receiving_key = std::move(other.m_receiving_key);
        m_receive_replay_window = other.m_receive_replay_window;
        other.m_state = KeypairState::Empty;
        other.m_local_index = 0;
        other.m_remote_index = 0;
        other.m_send_counter = 0;
        other.m_birth_time = {};
        other.m_receive_replay_window.Reset();
    }
    return *this;
}

bool noise_keypair::IsValid() const {
    return m_state == KeypairState::Established &&
           m_local_index != 0 && m_remote_index != 0 &&
           m_sending_key.valid && m_receiving_key.valid;
}

bool noise_keypair::CanSendAt(MonotonicTimePoint now) const {
    return SendStateAt(now) == KeypairSendState::Ready;
}

bool noise_keypair::CanReceiveAt(MonotonicTimePoint now) const {
    const KeypairAgeResult age = AgeAt(now);
    return age.valid && age.age < RejectAfterTime;
}

KeypairSendState noise_keypair::SendStateAt(MonotonicTimePoint now) const {
    const KeypairAgeResult age = AgeAt(now);
    if (!age.valid) {
        return KeypairSendState::Invalid;
    }
    if (age.age >= RejectAfterTime) {
        return KeypairSendState::Expired;
    }
    if (m_send_counter >= RejectAfterMessages) {
        return KeypairSendState::CounterExhausted;
    }

    return KeypairSendState::Ready;
}

const char *GetKeypairSendStateName(KeypairSendState state) {
    switch (state) {
        case KeypairSendState::Ready:
            return "ready";
        case KeypairSendState::Invalid:
            return "invalid";
        case KeypairSendState::Expired:
            return "expired";
        case KeypairSendState::CounterExhausted:
            return "counter_exhausted";
    }

    return "unknown";
}

KeypairSendState noise_keypair::ReserveSendCounterAt(
    MonotonicTimePoint now,
    std::uint64_t &out_counter) {
    const KeypairSendState state = SendStateAt(now);
    if (state != KeypairSendState::Ready) {
        return state;
    }

    out_counter = m_send_counter;
    ++m_send_counter;
    return KeypairSendState::Ready;
}

KeypairAgeResult noise_keypair::AgeAt(MonotonicTimePoint now) const {
    if (!IsValid() || now < m_birth_time) {
        return {};
    }
    return {.valid = true, .age = now - m_birth_time};
}

bool noise_is_valid_encoded_key(std::string_view text, bool allow_empty) {
    if (text.empty()) {
        return allow_empty;
    }

    std::array<std::uint8_t, NoisePublicKeySize> decoded{};
    const bool ok = DecodeWireGuardKey(decoded, text);
    crypto::secure_clear(decoded.data(), decoded.size());
    return ok;
}

bool noise_parse_private_key(noise_private_key *out_key, std::string_view text) {
    if (out_key == nullptr) {
        return false;
    }

    noise_private_key key{};
    if (!DecodeWireGuardKey(key.bytes, text)) {
        return false;
    }

    if (IsAllZero(key.bytes)) {
        key.Clear();
        return false;
    }
    ClampX25519PrivateKey(key.bytes);

    key.valid = true;
    *out_key = std::move(key);
    return true;
}

bool noise_parse_public_key(noise_public_key *out_key, std::string_view text) {
    if (out_key == nullptr) {
        return false;
    }

    noise_public_key key{};
    if (!DecodeWireGuardKey(key.bytes, text)) {
        return false;
    }

    key.valid = true;
    *out_key = std::move(key);
    return true;
}

bool noise_parse_preshared_key(noise_symmetric_key *out_key, std::string_view text) {
    if (out_key == nullptr || text.empty()) {
        return false;
    }

    noise_symmetric_key key{};
    if (!DecodeWireGuardKey(key.bytes, text)) {
        return false;
    }

    key.valid = true;
    *out_key = std::move(key);
    return true;
}

bool noise_public_key_to_text(std::span<char> out_text, const noise_public_key *key) {
    if (key == nullptr || !key->valid) {
        return false;
    }

    return EncodeWireGuardKey(out_text, key->bytes);
}

bool noise_derive_public_key(noise_public_key *out_key, const noise_private_key *private_key) {
    if (out_key == nullptr || private_key == nullptr || !private_key->valid) {
        return false;
    }

    noise_public_key public_key{};
    if (!crypto::x25519_public_key(public_key.bytes.data(), private_key->bytes.data())) {
        return false;
    }
    public_key.valid = true;
    *out_key = public_key;
    return true;
}

bool noise_derive_public_key_text(
    std::span<char> out_text,
    const noise_private_key *private_key) {
    noise_public_key public_key{};
    if (!noise_derive_public_key(&public_key, private_key)) {
        return false;
    }
    const bool ok = noise_public_key_to_text(out_text, &public_key);
    crypto::secure_clear(public_key.bytes.data(), public_key.bytes.size());
    public_key.valid = false;
    return ok;
}

bool noise_derive_public_key_text(std::span<char> out_text, std::string_view private_key_text) {
    noise_private_key private_key{};
    if (!noise_parse_private_key(&private_key, private_key_text)) {
        private_key.Clear();
        return false;
    }
    const bool ok = noise_derive_public_key_text(out_text, &private_key);
    private_key.Clear();
    return ok;
}

bool noise_static_identity_init_from_keys(
    noise_static_identity *identity,
    const noise_private_key *private_key,
    std::string_view peer_public_key_text,
    const noise_symmetric_key *preshared_key) {
    if (identity == nullptr || private_key == nullptr || !private_key->valid) {
        return false;
    }

    noise_static_identity_reset(identity);
    identity->static_private.bytes = private_key->bytes;
    identity->static_private.valid = true;
    if (!noise_derive_public_key(&identity->static_public, &identity->static_private) ||
        !noise_parse_public_key(&identity->remote_static, peer_public_key_text)) {
        noise_static_identity_reset(identity);
        return false;
    }
    if (preshared_key != nullptr && preshared_key->valid) {
        identity->preshared_key.bytes = preshared_key->bytes;
        identity->preshared_key.valid = true;
    }
    return true;
}

bool noise_static_identity_init(
    noise_static_identity *identity,
    std::string_view private_key_text,
    std::string_view peer_public_key_text,
    std::string_view preshared_key_text) {
    if (identity == nullptr) {
        return false;
    }

    noise_static_identity_reset(identity);
    if (!noise_parse_private_key(&identity->static_private, private_key_text)) {
        noise_static_identity_reset(identity);
        return false;
    }
    if (!crypto::x25519_public_key(
            identity->static_public.bytes.data(),
            identity->static_private.bytes.data())) {
        noise_static_identity_reset(identity);
        return false;
    }
    identity->static_public.valid = true;
    if (!noise_parse_public_key(&identity->remote_static, peer_public_key_text)) {
        noise_static_identity_reset(identity);
        return false;
    }
    if (!preshared_key_text.empty() &&
        !noise_parse_preshared_key(&identity->preshared_key, preshared_key_text)) {
        noise_static_identity_reset(identity);
        return false;
    }

    return true;
}

bool noise_precompute_static_static(
    noise_handshake_material *material,
    const noise_static_identity *identity) {
    if (material == nullptr || identity == nullptr ||
        !identity->static_private.valid || !identity->remote_static.valid) {
        return false;
    }

    noise_secret32 precomputed{};
    if (!crypto::x25519(
            precomputed.bytes.data(),
            identity->static_private.bytes.data(),
            identity->remote_static.bytes.data()) ||
        IsAllZero(precomputed.bytes)) {
        precomputed.Clear();
        return false;
    }

    precomputed.valid = true;
    material->precomputed_static_static = std::move(precomputed);
    return true;
}

} // namespace wgnx::wireguard
