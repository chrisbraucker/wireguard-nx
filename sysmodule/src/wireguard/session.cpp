#include "wireguard/session.hpp"

#include "wireguard/crypto/primitives.hpp"

#include <cstddef>
#include <cstring>

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

void ClampX25519PrivateKey(std::uint8_t bytes[NoisePublicKeySize]) {
    if (bytes == nullptr) {
        return;
    }

    bytes[0] &= 248U;
    bytes[31] &= 127U;
    bytes[31] |= 64U;
}

bool DecodeWireGuardKey(std::uint8_t out[NoisePublicKeySize], const char *text) {
    if (out == nullptr || text == nullptr) {
        return false;
    }

    const std::size_t length = std::strlen(text);
    if (length != WireGuardEncodedKeySize || text[WireGuardEncodedKeySize - 1] != '=') {
        return false;
    }

    std::size_t out_index = 0;
    for (std::size_t i = 0; i < length; i += 4) {
        const bool last_group = (i + 4) == length;
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

bool EncodeWireGuardKey(char *out_text, std::size_t out_size, const std::uint8_t bytes[NoisePublicKeySize]) {
    if (out_text == nullptr || bytes == nullptr || out_size < (WireGuardEncodedKeySize + 1)) {
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

void noise_cookie_reset(noise_cookie *cookie) {
    if (cookie == nullptr) {
        return;
    }

    crypto::secure_clear(cookie, sizeof(*cookie));
}

void noise_cookie_record_last_mac1(noise_cookie *cookie, const std::uint8_t mac1[NoiseMacSize]) {
    if (cookie == nullptr || mac1 == nullptr) {
        return;
    }

    std::memcpy(cookie->last_mac1, mac1, sizeof(cookie->last_mac1));
    cookie->has_last_mac1 = true;
}

bool noise_cookie_is_valid(const noise_cookie *cookie) {
    if (cookie == nullptr || !cookie->valid) {
        return false;
    }

    constexpr wgnx::platform::ktime_t CookieLifetimeNs = 120LL * wgnx::platform::NSEC_PER_SEC;
    const wgnx::platform::ktime_t now = wgnx::platform::ktime_get_coarse_boottime_ns();
    return cookie->birthdate_ns != 0 && now >= cookie->birthdate_ns &&
           (now - cookie->birthdate_ns) <= CookieLifetimeNs;
}

void noise_static_identity_reset(noise_static_identity *identity) {
    if (identity == nullptr) {
        return;
    }

    crypto::secure_clear(identity, sizeof(*identity));
}

void noise_handshake_material_reset(noise_handshake_material *material) {
    if (material == nullptr) {
        return;
    }

    crypto::secure_clear(material, sizeof(*material));
}

void noise_keypair_reset(noise_keypair *keypair) {
    if (keypair == nullptr) {
        return;
    }

    crypto::secure_clear(keypair, sizeof(*keypair));
}

bool noise_is_valid_encoded_key(const char *text, bool allow_empty) {
    if (text == nullptr) {
        return false;
    }
    if (text[0] == '\0') {
        return allow_empty;
    }

    std::uint8_t decoded[NoisePublicKeySize] = {};
    const bool ok = DecodeWireGuardKey(decoded, text);
    crypto::secure_clear(decoded, sizeof(decoded));
    return ok;
}

bool noise_parse_private_key(noise_private_key *out_key, const char *text) {
    if (out_key == nullptr || text == nullptr) {
        return false;
    }

    noise_private_key key{};
    if (!DecodeWireGuardKey(key.bytes, text)) {
        return false;
    }

    ClampX25519PrivateKey(key.bytes);
    if (IsAllZero(key.bytes, sizeof(key.bytes))) {
        crypto::secure_clear(&key, sizeof(key));
        return false;
    }

    key.valid = true;
    *out_key = key;
    return true;
}

bool noise_parse_public_key(noise_public_key *out_key, const char *text) {
    if (out_key == nullptr || text == nullptr) {
        return false;
    }

    noise_public_key key{};
    if (!DecodeWireGuardKey(key.bytes, text)) {
        return false;
    }

    key.valid = true;
    *out_key = key;
    return true;
}

bool noise_parse_preshared_key(noise_symmetric_key *out_key, const char *text) {
    if (out_key == nullptr || text == nullptr || text[0] == '\0') {
        return false;
    }

    noise_symmetric_key key{};
    if (!DecodeWireGuardKey(key.bytes, text)) {
        return false;
    }

    key.valid = true;
    *out_key = key;
    return true;
}

bool noise_public_key_to_text(char *out_text, std::size_t out_size, const noise_public_key *key) {
    if (out_text == nullptr || key == nullptr || !key->valid) {
        return false;
    }

    return EncodeWireGuardKey(out_text, out_size, key->bytes);
}

bool noise_derive_public_key_text(char *out_text, std::size_t out_size, const char *private_key_text) {
    if (out_text == nullptr || private_key_text == nullptr) {
        return false;
    }

    noise_private_key private_key{};
    noise_public_key public_key{};
    if (!noise_parse_private_key(&private_key, private_key_text) ||
        !crypto::x25519_public_key(public_key.bytes, private_key.bytes)) {
        crypto::secure_clear(&private_key, sizeof(private_key));
        crypto::secure_clear(&public_key, sizeof(public_key));
        return false;
    }

    public_key.valid = true;
    const bool ok = noise_public_key_to_text(out_text, out_size, &public_key);
    crypto::secure_clear(&private_key, sizeof(private_key));
    crypto::secure_clear(&public_key, sizeof(public_key));
    return ok;
}

bool noise_static_identity_init(
    noise_static_identity *identity,
    const char *private_key_text,
    const char *peer_public_key_text,
    const char *preshared_key_text) {
    if (identity == nullptr || private_key_text == nullptr || peer_public_key_text == nullptr ||
        preshared_key_text == nullptr) {
        return false;
    }

    noise_static_identity_reset(identity);
    if (!noise_parse_private_key(&identity->static_private, private_key_text)) {
        noise_static_identity_reset(identity);
        return false;
    }
    if (!crypto::x25519_public_key(identity->static_public.bytes, identity->static_private.bytes)) {
        noise_static_identity_reset(identity);
        return false;
    }
    identity->static_public.valid = true;
    if (!noise_parse_public_key(&identity->remote_static, peer_public_key_text)) {
        noise_static_identity_reset(identity);
        return false;
    }
    if (preshared_key_text[0] != '\0' &&
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
            precomputed.bytes,
            identity->static_private.bytes,
            identity->remote_static.bytes) ||
        IsAllZero(precomputed.bytes, sizeof(precomputed.bytes))) {
        crypto::secure_clear(&precomputed, sizeof(precomputed));
        return false;
    }

    precomputed.valid = true;
    material->precomputed_static_static = precomputed;
    return true;
}

} // namespace wgnx::wireguard
