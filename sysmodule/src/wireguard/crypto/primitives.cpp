#include "wireguard/crypto/primitives.hpp"

#include "wireguard/crypto/monocypher.h"
#include "wireguard/crypto/third_party/blake2/blake2.h"

#include <vapours/crypto.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>

namespace wgnx::wireguard::crypto {

namespace {

static_assert(alignof(::blake2s_state) <= alignof(std::max_align_t));

bool DecodeHex(std::uint8_t* out, std::size_t out_size, const char* hex) {
    if (out == nullptr || hex == nullptr) {
        return false;
    }

    std::size_t produced = 0;
    int high_nybble = -1;
    for (const char* cursor = hex; *cursor != '\0'; ++cursor) {
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
    // RFC 7693, Appendix A ("abc"). The keyed vector is from the official
    // BLAKE2 KAT corpus at the pinned vendor revision.
    static constexpr std::uint8_t ExpectedAbc[Blake2sHashSize] = {
        0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2, 0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb, 0x45, 0x2f,
        0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29, 0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67, 0x59, 0x82,
    };
    static constexpr std::uint8_t ExpectedKeyedEmpty[Blake2sHashSize] = {
        0x48, 0xa8, 0x99, 0x7d, 0xa4, 0x07, 0x87, 0x6b, 0x3d, 0x79, 0xc0, 0xd9, 0x23, 0x25, 0xad, 0x3b,
        0x89, 0xcb, 0xb7, 0x54, 0xd8, 0x6a, 0xb7, 0x1a, 0xee, 0x04, 0x7a, 0xd3, 0x45, 0xfd, 0x2c, 0x49,
    };
    static constexpr std::uint8_t ExpectedKeyed65[Blake2sHashSize] = {
        0x21, 0xfe, 0x0c, 0xeb, 0x00, 0x52, 0xbe, 0x7f, 0xb0, 0xf0, 0x04, 0x18, 0x7c, 0xac, 0xd7, 0xde,
        0x67, 0xfa, 0x6e, 0xb0, 0x93, 0x8d, 0x92, 0x76, 0x77, 0xf2, 0x39, 0x8c, 0x13, 0x23, 0x17, 0xa8,
    };

    std::uint8_t key[Blake2sKeySize]{};
    std::uint8_t block_message[Blake2sBlockSize + 1]{};
    for (std::size_t index = 0; index < sizeof(key); ++index) {
        key[index] = static_cast<std::uint8_t>(index);
    }
    for (std::size_t index = 0; index < sizeof(block_message); ++index) {
        block_message[index] = static_cast<std::uint8_t>(index);
    }

    Blake2sDigest one_shot{};
    Blake2sDigest incremental{};
    Blake2sDigest keyed{};
    Blake2sDigest block_boundary{};
    std::array<std::uint8_t, 16> short_digest{};
    static constexpr std::uint8_t Message[] = {'a', 'b', 'c'};

    const bool one_shot_ok = Blake2sHash(one_shot, Message) && secure_equal(one_shot, ExpectedAbc);
    Blake2sHasher incremental_hasher{};
    const bool incremental_ok = incremental_hasher.Initialize<Blake2sHashSize>() && incremental_hasher.Update(ByteSpan{Message, 1}) &&
                                incremental_hasher.Update(ByteSpan{Message + 1, 2}) && incremental_hasher.Final(incremental) &&
                                secure_equal(incremental, ExpectedAbc);
    const bool keyed_ok = Blake2sHash(keyed, {}, key) && secure_equal(keyed, ExpectedKeyedEmpty);
    Blake2sHasher block_hasher{};
    const bool block_boundary_ok = block_hasher.Initialize<Blake2sHashSize>(key) &&
                                   block_hasher.Update(ByteSpan{block_message, Blake2sBlockSize}) &&
                                   block_hasher.Update(ByteSpan{block_message + Blake2sBlockSize, 1}) &&
                                   block_hasher.Final(block_boundary) && secure_equal(block_boundary, ExpectedKeyed65);
    const bool short_digest_ok = Blake2sHash(short_digest, Message) && short_digest[0] == 0xaa && short_digest[15] == 0xae;

    Blake2sHasher misuse_hasher{};
    const bool misuse_rejected = !misuse_hasher.Update(Message) && misuse_hasher.Initialize<Blake2sHashSize>() &&
                                 misuse_hasher.Update(Message) && misuse_hasher.Final(one_shot) && !misuse_hasher.Update(Message) &&
                                 !misuse_hasher.Final(one_shot) &&
                                 std::ranges::all_of(one_shot, [](std::uint8_t byte) { return byte == 0; });

    secure_clear(MutableByteSpan{key});
    secure_clear(MutableByteSpan{block_message});
    secure_clear(one_shot);
    secure_clear(incremental);
    secure_clear(keyed);
    secure_clear(block_boundary);
    secure_clear(short_digest);
    return one_shot_ok && incremental_ok && keyed_ok && block_boundary_ok && short_digest_ok && misuse_rejected;
}

bool TestBlake2sHmacVector() {
    static constexpr Blake2sKey Key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static constexpr char Message[] = "wireguard-nx milestone 8";
    static constexpr Blake2sDigest Expected = {
        0x43, 0x45, 0x34, 0xe4, 0xa0, 0x73, 0x13, 0xfc, 0x9e, 0xbf, 0xbc, 0xca, 0x17, 0x35, 0x3a, 0xab,
        0xbc, 0xae, 0x36, 0x99, 0x54, 0xfc, 0xd3, 0x6e, 0x7b, 0x30, 0x00, 0xf2, 0x77, 0x58, 0x59, 0xbc,
    };
    Blake2sDigest actual{};
    const bool ok = Blake2sHmac(actual, Key, ByteSpan{reinterpret_cast<const std::uint8_t*>(Message), sizeof(Message) - 1}) &&
                    secure_equal(actual, Expected);
    secure_clear(actual);
    return ok;
}

bool TestChaCha20BlockVector() {
    static constexpr ChaCha20Key Key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static constexpr ChaCha20Nonce Nonce = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    };
    static constexpr std::uint8_t Expected[ChaCha20BlockSize] = {
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0,
        0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05,
        0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    };

    std::uint8_t block[ChaCha20BlockSize]{};
    static_cast<void>(crypto_chacha20_ietf(block, nullptr, sizeof(block), Key.data(), Nonce.data(), 1));
    const bool same = secure_equal(ByteSpan{block}, ByteSpan{Expected});
    secure_clear(MutableByteSpan{block});
    return same;
}

bool TestPoly1305Vector() {
    static constexpr std::uint8_t Key[Poly1305KeySize] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
    };
    static constexpr std::uint8_t Expected[Poly1305TagSize] = {
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
    };
    static constexpr char Message[] = "Cryptographic Forum Research Group";

    std::uint8_t tag[Poly1305TagSize]{};
    crypto_poly1305(tag, reinterpret_cast<const std::uint8_t*>(Message), sizeof(Message) - 1, Key);
    const bool same = secure_equal(ByteSpan{tag}, ByteSpan{Expected});
    secure_clear(MutableByteSpan{tag});
    return same;
}

bool TestChaCha20Poly1305Vector() {
    static constexpr ChaCha20Key Key = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    static constexpr ChaCha20Nonce Nonce = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    };
    static constexpr std::uint8_t Aad[12] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    };
    static constexpr char Plaintext[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    static constexpr std::uint8_t ExpectedCiphertext[114] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed,
        0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9,
        0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05,
        0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3,
        0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7,
        0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
    };
    static constexpr std::uint8_t ExpectedTag[Poly1305TagSize] = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    };

    std::array<std::uint8_t, sizeof(ExpectedCiphertext)> ciphertext{};
    Poly1305Tag tag{};
    std::array<std::uint8_t, sizeof(ExpectedCiphertext)> decrypted{};

    const bool encrypted = chacha20poly1305_encrypt(
        ciphertext, tag, ByteSpan{reinterpret_cast<const std::uint8_t*>(Plaintext), sizeof(Plaintext) - 1}, ByteSpan{Aad}, Key, Nonce);
    if (!encrypted || !secure_equal(ciphertext, ExpectedCiphertext) || !secure_equal(tag, ExpectedTag)) {
        secure_clear(ciphertext);
        secure_clear(tag);
        secure_clear(decrypted);
        return false;
    }

    const bool decrypted_ok = chacha20poly1305_decrypt(decrypted, ciphertext, tag, ByteSpan{Aad}, Key, Nonce);
    const bool same_plaintext = decrypted_ok && secure_equal(ByteSpan{decrypted}, ByteSpan{reinterpret_cast<const std::uint8_t*>(Plaintext),
                                                                                           sizeof(Plaintext) - 1});

    tag[0] ^= 0x80U;
    const bool tamper_rejected = !chacha20poly1305_decrypt(decrypted, ciphertext, tag, ByteSpan{Aad}, Key, Nonce) &&
                                 std::ranges::all_of(decrypted, [](std::uint8_t byte) { return byte == 0; });
    secure_clear(ciphertext);
    secure_clear(tag);
    secure_clear(decrypted);
    return same_plaintext && tamper_rejected;
}

bool TestXChaCha20Poly1305Vector() {
    static constexpr ChaCha20Key Key = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    static constexpr XChaCha20Nonce Nonce = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
        0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    };
    static constexpr std::uint8_t Aad[12] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    };
    static constexpr char Plaintext[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    std::array<std::uint8_t, 130> expected{};
    if (!DecodeHex(expected.data(), expected.size(),
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

    std::array<std::uint8_t, 114> ciphertext{};
    Poly1305Tag tag{};
    std::array<std::uint8_t, 114> decrypted{};
    std::memcpy(tag.data(), expected.data() + ciphertext.size(), tag.size());

    const bool encrypted = xchacha20poly1305_encrypt(
        ciphertext, tag, ByteSpan{reinterpret_cast<const std::uint8_t*>(Plaintext), sizeof(Plaintext) - 1}, ByteSpan{Aad}, Key, Nonce);
    const bool same_ciphertext = encrypted && secure_equal(ByteSpan{ciphertext}, ByteSpan{expected}.first(ciphertext.size())) &&
                                 secure_equal(ByteSpan{tag}, ByteSpan{expected}.subspan(ciphertext.size(), tag.size()));
    if (!same_ciphertext) {
        secure_clear(expected);
        secure_clear(ciphertext);
        secure_clear(tag);
        secure_clear(decrypted);
        return false;
    }

    const bool decrypted_ok = xchacha20poly1305_decrypt(decrypted, ciphertext, tag, ByteSpan{Aad}, Key, Nonce);
    const bool same_plaintext = decrypted_ok && secure_equal(ByteSpan{decrypted}, ByteSpan{reinterpret_cast<const std::uint8_t*>(Plaintext),
                                                                                           sizeof(Plaintext) - 1});

    tag[0] ^= 0x80U;
    const bool tamper_rejected = !xchacha20poly1305_decrypt(decrypted, ciphertext, tag, ByteSpan{Aad}, Key, Nonce) &&
                                 std::ranges::all_of(decrypted, [](std::uint8_t byte) { return byte == 0; });
    secure_clear(expected);
    secure_clear(ciphertext);
    secure_clear(tag);
    secure_clear(decrypted);
    return same_plaintext && tamper_rejected;
}

bool TestX25519Vector() {
    X25519Key expected{};
    const bool decoded = DecodeHex(expected.data(), expected.size(), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    static constexpr X25519Key Scalar = {9};
    X25519Key result{};
    const bool computed = decoded && x25519(result, Scalar, Scalar);
    const X25519Key low_order{};
    const bool same = computed && secure_equal(result, expected) && !x25519(result, Scalar, low_order);
    secure_clear(result);
    secure_clear(expected);
    return same;
}

} // namespace

void secure_clear(MutableByteSpan bytes) {
    if (!bytes.empty()) {
        ams::crypto::ClearMemory(bytes.data(), bytes.size());
    }
}

void secure_clear(std::span<char> bytes) {
    if (!bytes.empty()) {
        ams::crypto::ClearMemory(bytes.data(), bytes.size());
    }
}

bool secure_equal(ByteSpan lhs, ByteSpan rhs) {
    return lhs.size() == rhs.size() && (lhs.empty() || ams::crypto::IsSameBytes(lhs.data(), rhs.data(), lhs.size()));
}

Blake2sHasher::~Blake2sHasher() {
    Reset();
}

void Blake2sHasher::Reset() {
    if (backend_constructed_) {
        std::destroy_at(reinterpret_cast<::blake2s_state*>(backend_storage_.data()));
        backend_constructed_ = false;
    }
    secure_clear(MutableByteSpan{reinterpret_cast<std::uint8_t*>(backend_storage_.data()), backend_storage_.size()});
    digest_size_ = 0;
    initialized_ = false;
    finalized_ = false;
}

bool Blake2sHasher::InitializeDigest(std::size_t digest_size, ByteSpan key) {
    static_assert(sizeof(::blake2s_state) <= BackendStorageSize);

    Reset();
    if (digest_size == 0 || digest_size > Blake2sHashSize || key.size() > Blake2sKeySize || (!key.empty() && key.data() == nullptr)) {
        return false;
    }

    auto* const backend = std::construct_at(reinterpret_cast<::blake2s_state*>(backend_storage_.data()));
    backend_constructed_ = true;
    const int result =
        key.empty() ? ::blake2s_init(backend, digest_size) : ::blake2s_init_key(backend, digest_size, key.data(), key.size());
    if (result != 0) {
        Reset();
        return false;
    }

    digest_size_ = digest_size;
    initialized_ = true;
    return true;
}

bool Blake2sHasher::Update(ByteSpan data) {
    if (!initialized_ || finalized_ || (!data.empty() && data.data() == nullptr)) {
        return false;
    }
    auto* const backend = reinterpret_cast<::blake2s_state*>(backend_storage_.data());
    return ::blake2s_update(backend, data.data(), data.size()) == 0;
}

bool Blake2sHasher::FinalDigest(MutableByteSpan output) {
    if (!initialized_ || finalized_ || output.size() != digest_size_ || output.data() == nullptr) {
        return false;
    }

    auto* const backend = reinterpret_cast<::blake2s_state*>(backend_storage_.data());
    const bool ok = ::blake2s_final(backend, output.data(), output.size()) == 0;
    Reset();
    finalized_ = true;
    return ok;
}

bool Blake2sHmac(Blake2sDigest& output, ByteSpan key, ByteSpan data) {
    SensitiveBuffer<Blake2sBlockSize> normalized_key{};
    SensitiveBuffer<Blake2sHashSize> inner_hash{};
    SensitiveBuffer<Blake2sBlockSize> inner_pad{};
    SensitiveBuffer<Blake2sBlockSize> outer_pad{};
    if (key.size() > normalized_key.bytes().size()) {
        Blake2sDigest normalized_hash{};
        if (!Blake2sHash(normalized_hash, key)) {
            secure_clear(output);
            return false;
        }
        std::ranges::copy(normalized_hash, normalized_key.bytes().begin());
        secure_clear(normalized_hash);
    } else if (!key.empty()) {
        std::ranges::copy(key, normalized_key.bytes().begin());
    }
    for (std::size_t index = 0; index < normalized_key.bytes().size(); ++index) {
        inner_pad.bytes()[index] = normalized_key.bytes()[index] ^ 0x36U;
        outer_pad.bytes()[index] = normalized_key.bytes()[index] ^ 0x5cU;
    }
    Blake2sHasher inner{};
    Blake2sHasher outer{};
    const bool ok = inner.Initialize<Blake2sHashSize>() && inner.Update(inner_pad.span()) && inner.Update(data) &&
                    inner.Final(inner_hash.bytes()) && outer.Initialize<Blake2sHashSize>() && outer.Update(outer_pad.span()) &&
                    outer.Update(inner_hash.span()) && outer.Final(output);
    if (!ok)
        secure_clear(output);
    return ok;
}

bool chacha20poly1305_encrypt(MutableByteSpan ciphertext, Poly1305Tag& tag, ByteSpan plaintext, ByteSpan aad, const ChaCha20Key& key,
                              const ChaCha20Nonce& nonce) {
    if (ciphertext.size() != plaintext.size()) {
        return false;
    }

    crypto_aead_ctx ctx{};
    crypto_aead_init_ietf(&ctx, key.data(), nonce.data());
    crypto_aead_write(&ctx, ciphertext.data(), tag.data(), aad.data(), aad.size(), plaintext.data(), plaintext.size());
    secure_clear(MutableByteSpan{reinterpret_cast<std::uint8_t*>(&ctx), sizeof(ctx)});
    return true;
}

bool chacha20poly1305_decrypt(MutableByteSpan plaintext, ByteSpan ciphertext, const Poly1305Tag& tag, ByteSpan aad, const ChaCha20Key& key,
                              const ChaCha20Nonce& nonce) {
    if (plaintext.size() != ciphertext.size()) {
        return false;
    }

    crypto_aead_ctx ctx{};
    crypto_aead_init_ietf(&ctx, key.data(), nonce.data());
    const bool ok = crypto_aead_read(&ctx, plaintext.data(), tag.data(), aad.data(), aad.size(), ciphertext.data(), ciphertext.size()) == 0;
    secure_clear(MutableByteSpan{reinterpret_cast<std::uint8_t*>(&ctx), sizeof(ctx)});
    if (!ok)
        secure_clear(plaintext);
    return ok;
}

bool xchacha20poly1305_encrypt(MutableByteSpan ciphertext, Poly1305Tag& tag, ByteSpan plaintext, ByteSpan aad, const ChaCha20Key& key,
                               const XChaCha20Nonce& nonce) {
    if (ciphertext.size() != plaintext.size()) {
        return false;
    }

    crypto_aead_ctx ctx{};
    crypto_aead_init_x(&ctx, key.data(), nonce.data());
    crypto_aead_write(&ctx, ciphertext.data(), tag.data(), aad.data(), aad.size(), plaintext.data(), plaintext.size());
    secure_clear(MutableByteSpan{reinterpret_cast<std::uint8_t*>(&ctx), sizeof(ctx)});
    return true;
}

bool xchacha20poly1305_decrypt(MutableByteSpan plaintext, ByteSpan ciphertext, const Poly1305Tag& tag, ByteSpan aad, const ChaCha20Key& key,
                               const XChaCha20Nonce& nonce) {
    if (plaintext.size() != ciphertext.size()) {
        return false;
    }

    crypto_aead_ctx ctx{};
    crypto_aead_init_x(&ctx, key.data(), nonce.data());
    const bool ok = crypto_aead_read(&ctx, plaintext.data(), tag.data(), aad.data(), aad.size(), ciphertext.data(), ciphertext.size()) == 0;
    secure_clear(MutableByteSpan{reinterpret_cast<std::uint8_t*>(&ctx), sizeof(ctx)});
    if (!ok)
        secure_clear(plaintext);
    return ok;
}

bool x25519(X25519Key& out, const X25519Key& scalar, const X25519Key& point) {
    crypto_x25519(out.data(), scalar.data(), point.data());
    if (std::ranges::all_of(out, [](std::uint8_t byte) { return byte == 0; })) {
        secure_clear(out);
        return false;
    }
    return true;
}

bool x25519_public_key(X25519Key& out, const X25519Key& private_key) {
    crypto_x25519_public_key(out.data(), private_key.data());
    return true;
}

bool RunPrimitiveSelfTest() {
    return TestBlake2sVector() && TestBlake2sHmacVector() && TestChaCha20BlockVector() && TestPoly1305Vector() &&
           TestChaCha20Poly1305Vector() && TestXChaCha20Poly1305Vector() && TestX25519Vector();
}

} // namespace wgnx::wireguard::crypto
