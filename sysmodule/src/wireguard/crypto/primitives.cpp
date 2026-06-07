#include "wireguard/crypto/primitives.hpp"

#include "wireguard/crypto/monocypher.h"

#include <vapours/crypto.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace wgnx::wireguard::crypto {

namespace {

constexpr std::uint32_t Blake2sIv[8] = {
    0x6A09E667U,
    0xBB67AE85U,
    0x3C6EF372U,
    0xA54FF53AU,
    0x510E527FU,
    0x9B05688CU,
    0x1F83D9ABU,
    0x5BE0CD19U,
};

constexpr std::uint8_t Blake2sSigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

constexpr std::uint32_t Rotr32(std::uint32_t value, unsigned shift) {
    return (value >> shift) | (value << (32 - shift));
}

constexpr std::uint32_t LoadLe32(const std::uint8_t *src) {
    return static_cast<std::uint32_t>(src[0]) |
           (static_cast<std::uint32_t>(src[1]) << 8) |
           (static_cast<std::uint32_t>(src[2]) << 16) |
           (static_cast<std::uint32_t>(src[3]) << 24);
}

void StoreLe32(std::uint8_t *dst, std::uint32_t value) {
    dst[0] = static_cast<std::uint8_t>(value >> 0);
    dst[1] = static_cast<std::uint8_t>(value >> 8);
    dst[2] = static_cast<std::uint8_t>(value >> 16);
    dst[3] = static_cast<std::uint8_t>(value >> 24);
}

void Blake2sIncrement(blake2s_state *state, std::size_t amount) {
    state->t[0] += static_cast<std::uint32_t>(amount);
    if (state->t[0] < amount) {
        ++state->t[1];
    }
}

void Blake2sRound(
    std::uint32_t &a,
    std::uint32_t &b,
    std::uint32_t &c,
    std::uint32_t &d,
    std::uint32_t x,
    std::uint32_t y) {
    a = a + b + x;
    d = Rotr32(d ^ a, 16);
    c = c + d;
    b = Rotr32(b ^ c, 12);
    a = a + b + y;
    d = Rotr32(d ^ a, 8);
    c = c + d;
    b = Rotr32(b ^ c, 7);
}

void Blake2sCompress(blake2s_state *state, const std::uint8_t block[Blake2sBlockSize]) {
    std::uint32_t m[16]{};
    std::uint32_t v[16]{};

    for (std::size_t i = 0; i < 16; ++i) {
        m[i] = LoadLe32(block + (i * 4));
    }
    for (std::size_t i = 0; i < 8; ++i) {
        v[i] = state->h[i];
        v[i + 8] = Blake2sIv[i];
    }

    v[12] ^= state->t[0];
    v[13] ^= state->t[1];
    v[14] ^= state->f[0];
    v[15] ^= state->f[1];

    for (std::size_t round = 0; round < 10; ++round) {
        Blake2sRound(v[0], v[4], v[8], v[12], m[Blake2sSigma[round][0]], m[Blake2sSigma[round][1]]);
        Blake2sRound(v[1], v[5], v[9], v[13], m[Blake2sSigma[round][2]], m[Blake2sSigma[round][3]]);
        Blake2sRound(v[2], v[6], v[10], v[14], m[Blake2sSigma[round][4]], m[Blake2sSigma[round][5]]);
        Blake2sRound(v[3], v[7], v[11], v[15], m[Blake2sSigma[round][6]], m[Blake2sSigma[round][7]]);
        Blake2sRound(v[0], v[5], v[10], v[15], m[Blake2sSigma[round][8]], m[Blake2sSigma[round][9]]);
        Blake2sRound(v[1], v[6], v[11], v[12], m[Blake2sSigma[round][10]], m[Blake2sSigma[round][11]]);
        Blake2sRound(v[2], v[7], v[8], v[13], m[Blake2sSigma[round][12]], m[Blake2sSigma[round][13]]);
        Blake2sRound(v[3], v[4], v[9], v[14], m[Blake2sSigma[round][14]], m[Blake2sSigma[round][15]]);
    }

    for (std::size_t i = 0; i < 8; ++i) {
        state->h[i] ^= v[i] ^ v[i + 8];
    }
}

bool DecodeHex(std::uint8_t *out, std::size_t out_size, const char *hex) {
    if (out == nullptr || hex == nullptr) {
        return false;
    }

    std::size_t produced = 0;
    int high_nybble = -1;
    for (const char *cursor = hex; *cursor != '\0'; ++cursor) {
        const char ch = *cursor;
        if (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t') {
            continue;
        }

        int value = -1;
        if (ch >= '0' && ch <= '9') {
            value = ch - '0';
        } else if (ch >= 'a' && ch <= 'f') {
            value = 10 + (ch - 'a');
        } else if (ch >= 'A' && ch <= 'F') {
            value = 10 + (ch - 'A');
        }

        if (value < 0) {
            return false;
        }

        if (high_nybble < 0) {
            high_nybble = value;
            continue;
        }

        if (produced >= out_size) {
            return false;
        }
        out[produced++] = static_cast<std::uint8_t>((high_nybble << 4) | value);
        high_nybble = -1;
    }

    return high_nybble < 0 && produced == out_size;
}

bool TestBlake2sVector() {
    static constexpr std::uint8_t Expected[Blake2sHashSize] = {
        0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2,
        0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb, 0x45, 0x2f,
        0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29,
        0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67, 0x59, 0x82,
    };

    std::uint8_t digest[Blake2sHashSize]{};
    const char *message = "abc";
    const bool ok = blake2s(digest, sizeof(digest), message, 3, nullptr, 0);
    const bool same = ok && secure_equal(digest, Expected, sizeof(Expected));
    secure_clear(digest, sizeof(digest));
    return same;
}

bool TestChaCha20BlockVector() {
    static constexpr std::uint8_t Key[ChaCha20KeySize] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static constexpr std::uint8_t Nonce[ChaCha20NonceSize] = {
        0x00, 0x00, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00,
    };
    static constexpr std::uint8_t Expected[ChaCha20BlockSize] = {
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
        0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
        0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
        0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
        0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    };

    std::uint8_t block[ChaCha20BlockSize]{};
    chacha20_block(block, Key, 1, Nonce);
    const bool same = secure_equal(block, Expected, sizeof(Expected));
    secure_clear(block, sizeof(block));
    return same;
}

bool TestPoly1305Vector() {
    static constexpr std::uint8_t Key[Poly1305KeySize] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
    };
    static constexpr std::uint8_t Expected[Poly1305TagSize] = {
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
    };
    static constexpr char Message[] = "Cryptographic Forum Research Group";

    std::uint8_t tag[Poly1305TagSize]{};
    poly1305_auth(
        tag,
        reinterpret_cast<const std::uint8_t *>(Message),
        sizeof(Message) - 1,
        Key);
    const bool same = secure_equal(tag, Expected, sizeof(Expected));
    secure_clear(tag, sizeof(tag));
    return same;
}

bool TestChaCha20Poly1305Vector() {
    static constexpr std::uint8_t Key[ChaCha20KeySize] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    static constexpr std::uint8_t Nonce[ChaCha20NonceSize] = {
        0x07, 0x00, 0x00, 0x00,
        0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47,
    };
    static constexpr std::uint8_t Aad[12] = {
        0x50, 0x51, 0x52, 0x53,
        0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    };
    static constexpr char Plaintext[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    static constexpr std::uint8_t ExpectedCiphertext[114] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    };
    static constexpr std::uint8_t ExpectedTag[Poly1305TagSize] = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    };

    std::uint8_t ciphertext[sizeof(ExpectedCiphertext)]{};
    std::uint8_t tag[Poly1305TagSize]{};
    std::uint8_t decrypted[sizeof(ExpectedCiphertext)]{};

    const bool encrypted = chacha20poly1305_encrypt(
        ciphertext,
        tag,
        reinterpret_cast<const std::uint8_t *>(Plaintext),
        sizeof(Plaintext) - 1,
        Aad,
        sizeof(Aad),
        Key,
        Nonce);
    if (!encrypted ||
        !secure_equal(ciphertext, ExpectedCiphertext, sizeof(ExpectedCiphertext)) ||
        !secure_equal(tag, ExpectedTag, sizeof(ExpectedTag))) {
        secure_clear(ciphertext, sizeof(ciphertext));
        secure_clear(tag, sizeof(tag));
        secure_clear(decrypted, sizeof(decrypted));
        return false;
    }

    const bool decrypted_ok = chacha20poly1305_decrypt(
        decrypted,
        ciphertext,
        sizeof(ciphertext),
        tag,
        Aad,
        sizeof(Aad),
        Key,
        Nonce);
    const bool same_plaintext = decrypted_ok &&
        secure_equal(
            decrypted,
            reinterpret_cast<const std::uint8_t *>(Plaintext),
            sizeof(Plaintext) - 1);

    secure_clear(ciphertext, sizeof(ciphertext));
    secure_clear(tag, sizeof(tag));
    secure_clear(decrypted, sizeof(decrypted));
    return same_plaintext;
}

bool TestXChaCha20Poly1305Vector() {
    static constexpr std::uint8_t Key[ChaCha20KeySize] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    static constexpr std::uint8_t Nonce[XChaCha20NonceSize] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    };
    static constexpr std::uint8_t Aad[12] = {
        0x50, 0x51, 0x52, 0x53,
        0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    };
    static constexpr char Plaintext[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    std::uint8_t expected[130]{};
    if (!DecodeHex(
            expected,
            sizeof(expected),
            "BD6D179D3E83D43B9576579493C0E939"
            "572A1700252BFACCBED2902C21396CBB"
            "731C7F1B0B4AA6440BF3A82F4EDA7E39"
            "AE64C6708C54C216CB96B72E1213B452"
            "2F8C9BA40DB5D945B11B69B982C1BB9E"
            "3F3FAC2BC369488F76B2383565D3FFF9"
            "21F9664C97637DA9768812F615C68B13"
            "B52EC0875924C1C7987947DEAFD8780A"
            "CF49")) {
        return false;
    }

    std::uint8_t ciphertext[114]{};
    std::uint8_t tag[Poly1305TagSize]{};
    std::uint8_t decrypted[114]{};
    std::memcpy(tag, expected + sizeof(ciphertext), sizeof(tag));

    const bool encrypted = xchacha20poly1305_encrypt(
        ciphertext,
        tag,
        reinterpret_cast<const std::uint8_t *>(Plaintext),
        sizeof(Plaintext) - 1,
        Aad,
        sizeof(Aad),
        Key,
        Nonce);
    const bool same_ciphertext = encrypted &&
        secure_equal(ciphertext, expected, sizeof(ciphertext)) &&
        secure_equal(tag, expected + sizeof(ciphertext), Poly1305TagSize);
    if (!same_ciphertext) {
        secure_clear(expected, sizeof(expected));
        secure_clear(ciphertext, sizeof(ciphertext));
        secure_clear(tag, sizeof(tag));
        secure_clear(decrypted, sizeof(decrypted));
        return false;
    }

    const bool decrypted_ok = xchacha20poly1305_decrypt(
        decrypted,
        ciphertext,
        sizeof(ciphertext),
        tag,
        Aad,
        sizeof(Aad),
        Key,
        Nonce);
    const bool same_plaintext = decrypted_ok &&
        secure_equal(
            decrypted,
            reinterpret_cast<const std::uint8_t *>(Plaintext),
            sizeof(Plaintext) - 1);

    secure_clear(expected, sizeof(expected));
    secure_clear(ciphertext, sizeof(ciphertext));
    secure_clear(tag, sizeof(tag));
    secure_clear(decrypted, sizeof(decrypted));
    return same_plaintext;
}

bool TestX25519Vector() {
    std::uint8_t expected[X25519KeySize]{};
    const bool decoded = DecodeHex(
        expected,
        sizeof(expected),
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    static constexpr std::uint8_t Scalar[X25519KeySize] = {9};
    std::uint8_t result[X25519KeySize]{};
    const bool computed = decoded && x25519(result, Scalar, Scalar);
    const bool same = computed && secure_equal(result, expected, sizeof(expected));
    secure_clear(result, sizeof(result));
    secure_clear(expected, sizeof(expected));
    return same;
}

} // namespace

void secure_clear(void *mem, std::size_t size) {
    ams::crypto::ClearMemory(mem, size);
}

bool secure_equal(const void *lhs, const void *rhs, std::size_t size) {
    return ams::crypto::IsSameBytes(lhs, rhs, size);
}

bool blake2s_init(
    blake2s_state *state,
    std::size_t out_len,
    const void *key,
    std::size_t key_len) {
    if (state == nullptr || out_len == 0 || out_len > Blake2sHashSize || key_len > Blake2sBlockSize) {
        return false;
    }

    *state = {};
    state->out_len = out_len;
    for (std::size_t i = 0; i < 8; ++i) {
        state->h[i] = Blake2sIv[i];
    }
    state->h[0] ^= 0x01010000U ^ static_cast<std::uint32_t>(key_len << 8) ^ static_cast<std::uint32_t>(out_len);

    if (key != nullptr && key_len != 0) {
        std::uint8_t block[Blake2sBlockSize]{};
        std::memcpy(block, key, key_len);
        blake2s_update(state, block, sizeof(block));
        secure_clear(block, sizeof(block));
    }

    return true;
}

void blake2s_update(blake2s_state *state, const void *data, std::size_t size) {
    if (state == nullptr || (data == nullptr && size != 0)) {
        return;
    }

    const auto *bytes = static_cast<const std::uint8_t *>(data);
    while (size != 0) {
        if (state->buffer_len == Blake2sBlockSize) {
            Blake2sIncrement(state, Blake2sBlockSize);
            Blake2sCompress(state, state->buffer);
            state->buffer_len = 0;
        }

        const std::size_t amount = std::min<std::size_t>(Blake2sBlockSize - state->buffer_len, size);
        std::memcpy(state->buffer + state->buffer_len, bytes, amount);
        state->buffer_len += amount;
        bytes += amount;
        size -= amount;
    }
}

bool blake2s_final(blake2s_state *state, void *out, std::size_t out_len) {
    if (state == nullptr || out == nullptr || out_len < state->out_len) {
        return false;
    }

    Blake2sIncrement(state, state->buffer_len);
    state->f[0] = 0xffffffffU;
    std::memset(state->buffer + state->buffer_len, 0, Blake2sBlockSize - state->buffer_len);
    Blake2sCompress(state, state->buffer);

    std::uint8_t full_hash[Blake2sHashSize]{};
    for (std::size_t i = 0; i < 8; ++i) {
        StoreLe32(full_hash + (i * 4), state->h[i]);
    }
    std::memcpy(out, full_hash, state->out_len);
    secure_clear(full_hash, sizeof(full_hash));
    secure_clear(state, sizeof(*state));
    return true;
}

bool blake2s(
    void *out,
    std::size_t out_len,
    const void *data,
    std::size_t data_len,
    const void *key,
    std::size_t key_len) {
    blake2s_state state{};
    if (!blake2s_init(&state, out_len, key, key_len)) {
        return false;
    }
    blake2s_update(&state, data, data_len);
    return blake2s_final(&state, out, out_len);
}

void chacha20_block(
    std::uint8_t out[ChaCha20BlockSize],
    const std::uint8_t key[ChaCha20KeySize],
    std::uint32_t counter,
    const std::uint8_t nonce[ChaCha20NonceSize]) {
    static_cast<void>(crypto_chacha20_ietf(out, nullptr, ChaCha20BlockSize, key, nonce, counter));
}

void chacha20_xor(
    std::uint8_t *dst,
    const std::uint8_t *src,
    std::size_t size,
    const std::uint8_t key[ChaCha20KeySize],
    std::uint32_t counter,
    const std::uint8_t nonce[ChaCha20NonceSize]) {
    static_cast<void>(crypto_chacha20_ietf(dst, src, size, key, nonce, counter));
}

void poly1305_auth(
    std::uint8_t tag[Poly1305TagSize],
    const std::uint8_t *message,
    std::size_t message_size,
    const std::uint8_t key[Poly1305KeySize]) {
    crypto_poly1305(tag, message, message_size, key);
}

bool chacha20poly1305_encrypt(
    std::uint8_t *ciphertext,
    std::uint8_t tag[Poly1305TagSize],
    const std::uint8_t *plaintext,
    std::size_t plaintext_size,
    const std::uint8_t *aad,
    std::size_t aad_size,
    const std::uint8_t key[ChaCha20KeySize],
    const std::uint8_t nonce[ChaCha20NonceSize]) {
    if (ciphertext == nullptr || tag == nullptr || key == nullptr || nonce == nullptr ||
        (plaintext == nullptr && plaintext_size != 0) || (aad == nullptr && aad_size != 0)) {
        return false;
    }

    crypto_aead_ctx ctx{};
    crypto_aead_init_ietf(&ctx, key, nonce);
    crypto_aead_write(&ctx, ciphertext, tag, aad, aad_size, plaintext, plaintext_size);
    secure_clear(&ctx, sizeof(ctx));
    return true;
}

bool chacha20poly1305_decrypt(
    std::uint8_t *plaintext,
    const std::uint8_t *ciphertext,
    std::size_t ciphertext_size,
    const std::uint8_t tag[Poly1305TagSize],
    const std::uint8_t *aad,
    std::size_t aad_size,
    const std::uint8_t key[ChaCha20KeySize],
    const std::uint8_t nonce[ChaCha20NonceSize]) {
    if (plaintext == nullptr || ciphertext == nullptr || tag == nullptr || key == nullptr || nonce == nullptr ||
        (aad == nullptr && aad_size != 0)) {
        return false;
    }

    crypto_aead_ctx ctx{};
    crypto_aead_init_ietf(&ctx, key, nonce);
    const bool ok = crypto_aead_read(&ctx, plaintext, tag, aad, aad_size, ciphertext, ciphertext_size) == 0;
    secure_clear(&ctx, sizeof(ctx));
    return ok;
}

bool xchacha20poly1305_encrypt(
    std::uint8_t *ciphertext,
    std::uint8_t tag[Poly1305TagSize],
    const std::uint8_t *plaintext,
    std::size_t plaintext_size,
    const std::uint8_t *aad,
    std::size_t aad_size,
    const std::uint8_t key[ChaCha20KeySize],
    const std::uint8_t nonce[XChaCha20NonceSize]) {
    if (ciphertext == nullptr || tag == nullptr || key == nullptr || nonce == nullptr ||
        (plaintext == nullptr && plaintext_size != 0) || (aad == nullptr && aad_size != 0)) {
        return false;
    }

    crypto_aead_ctx ctx{};
    crypto_aead_init_x(&ctx, key, nonce);
    crypto_aead_write(&ctx, ciphertext, tag, aad, aad_size, plaintext, plaintext_size);
    secure_clear(&ctx, sizeof(ctx));
    return true;
}

bool xchacha20poly1305_decrypt(
    std::uint8_t *plaintext,
    const std::uint8_t *ciphertext,
    std::size_t ciphertext_size,
    const std::uint8_t tag[Poly1305TagSize],
    const std::uint8_t *aad,
    std::size_t aad_size,
    const std::uint8_t key[ChaCha20KeySize],
    const std::uint8_t nonce[XChaCha20NonceSize]) {
    if (plaintext == nullptr || ciphertext == nullptr || tag == nullptr || key == nullptr || nonce == nullptr ||
        (aad == nullptr && aad_size != 0)) {
        return false;
    }

    crypto_aead_ctx ctx{};
    crypto_aead_init_x(&ctx, key, nonce);
    const bool ok = crypto_aead_read(&ctx, plaintext, tag, aad, aad_size, ciphertext, ciphertext_size) == 0;
    secure_clear(&ctx, sizeof(ctx));
    return ok;
}

bool x25519(
    std::uint8_t out[X25519KeySize],
    const std::uint8_t scalar[X25519KeySize],
    const std::uint8_t point[X25519KeySize]) {
    if (out == nullptr || scalar == nullptr || point == nullptr) {
        return false;
    }

    crypto_x25519(out, scalar, point);
    return true;
}

bool x25519_public_key(
    std::uint8_t out[X25519KeySize],
    const std::uint8_t private_key[X25519KeySize]) {
    if (out == nullptr || private_key == nullptr) {
        return false;
    }

    crypto_x25519_public_key(out, private_key);
    return true;
}

bool RunPrimitiveSelfTest() {
    return TestBlake2sVector() &&
           TestChaCha20BlockVector() &&
           TestPoly1305Vector() &&
           TestChaCha20Poly1305Vector() &&
           TestXChaCha20Poly1305Vector() &&
           TestX25519Vector();
}

} // namespace wgnx::wireguard::crypto
