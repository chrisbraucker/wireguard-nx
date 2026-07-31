#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace wgnx::wireguard::crypto {

constexpr inline std::size_t Blake2sBlockSize = 64;
constexpr inline std::size_t Blake2sHashSize = 32;
constexpr inline std::size_t Blake2sKeySize = 32;
constexpr inline std::size_t ChaCha20KeySize = 32;
constexpr inline std::size_t ChaCha20BlockSize = 64;
constexpr inline std::size_t ChaCha20NonceSize = 12;
constexpr inline std::size_t XChaCha20NonceSize = 24;
constexpr inline std::size_t Poly1305KeySize = 32;
constexpr inline std::size_t Poly1305TagSize = 16;
constexpr inline std::size_t X25519KeySize = 32;

using ByteSpan = std::span<const std::uint8_t>;
using MutableByteSpan = std::span<std::uint8_t>;
using Blake2sDigest = std::array<std::uint8_t, Blake2sHashSize>;
using Blake2sKey = std::array<std::uint8_t, Blake2sKeySize>;
using ChaCha20Key = std::array<std::uint8_t, ChaCha20KeySize>;
using ChaCha20Nonce = std::array<std::uint8_t, ChaCha20NonceSize>;
using XChaCha20Nonce = std::array<std::uint8_t, XChaCha20NonceSize>;
using Poly1305Tag = std::array<std::uint8_t, Poly1305TagSize>;
using X25519Key = std::array<std::uint8_t, X25519KeySize>;

void secure_clear(MutableByteSpan bytes);
void secure_clear(std::span<char> bytes);
bool secure_equal(ByteSpan lhs, ByteSpan rhs);

template <std::size_t Size> void secure_clear(std::array<std::uint8_t, Size>& bytes) {
    secure_clear(MutableByteSpan{bytes});
}

template <std::size_t Size> void secure_clear(std::uint8_t (&bytes)[Size]) {
    secure_clear(MutableByteSpan{bytes, Size});
}

template <std::size_t Size> void secure_clear(std::array<char, Size>& bytes) {
    secure_clear(std::span<char>{bytes});
}

template <std::size_t Size> bool secure_equal(const std::array<std::uint8_t, Size>& lhs, const std::array<std::uint8_t, Size>& rhs) {
    return secure_equal(ByteSpan{lhs}, ByteSpan{rhs});
}

template <std::size_t Size> bool secure_equal(const std::uint8_t (&lhs)[Size], const std::uint8_t (&rhs)[Size]) {
    return secure_equal(ByteSpan{lhs, Size}, ByteSpan{rhs, Size});
}

/*
 * Owns sensitive stack-local material and clears it on every exit path. Long-
 * lived protocol keys use their dedicated move-only session types instead.
 */
template <std::size_t Size> class SensitiveBuffer final {
  public:
    SensitiveBuffer() = default;
    ~SensitiveBuffer() {
        secure_clear(bytes_);
    }

    SensitiveBuffer(const SensitiveBuffer&) = delete;
    SensitiveBuffer& operator=(const SensitiveBuffer&) = delete;
    SensitiveBuffer(SensitiveBuffer&&) = delete;
    SensitiveBuffer& operator=(SensitiveBuffer&&) = delete;

    std::array<std::uint8_t, Size>& bytes() {
        return bytes_;
    }
    const std::array<std::uint8_t, Size>& bytes() const {
        return bytes_;
    }
    MutableByteSpan mutable_span() {
        return bytes_;
    }
    ByteSpan span() const {
        return bytes_;
    }

  private:
    std::array<std::uint8_t, Size> bytes_{};
};

class Blake2sHasher final {
  public:
    Blake2sHasher() = default;
    ~Blake2sHasher();

    Blake2sHasher(const Blake2sHasher&) = delete;
    Blake2sHasher& operator=(const Blake2sHasher&) = delete;
    Blake2sHasher(Blake2sHasher&&) = delete;
    Blake2sHasher& operator=(Blake2sHasher&&) = delete;

    template <std::size_t DigestSize> bool Initialize(ByteSpan key = {}) {
        static_assert(DigestSize > 0 && DigestSize <= Blake2sHashSize);
        return InitializeDigest(DigestSize, key);
    }
    bool Update(ByteSpan data);

    template <std::size_t DigestSize> bool Final(std::array<std::uint8_t, DigestSize>& output) {
        static_assert(DigestSize > 0 && DigestSize <= Blake2sHashSize);
        const bool ok = FinalDigest(MutableByteSpan{output});
        if (!ok)
            secure_clear(output);
        return ok;
    }

  private:
    void Reset();
    bool InitializeDigest(std::size_t digest_size, ByteSpan key);
    bool FinalDigest(MutableByteSpan output);

    static constexpr std::size_t BackendStorageSize = 160;

    alignas(std::max_align_t) std::array<std::byte, BackendStorageSize> backend_storage_{};
    std::size_t digest_size_{0};
    bool backend_constructed_{false};
    bool initialized_{false};
    bool finalized_{false};
};

template <std::size_t DigestSize> bool Blake2sHash(std::array<std::uint8_t, DigestSize>& output, ByteSpan data, ByteSpan key = {}) {
    static_assert(DigestSize > 0 && DigestSize <= Blake2sHashSize);
    Blake2sHasher hasher{};
    const bool ok = hasher.Initialize<DigestSize>(key) && hasher.Update(data) && hasher.Final(output);
    if (!ok)
        secure_clear(output);
    return ok;
}

bool Blake2sHmac(Blake2sDigest& output, ByteSpan key, ByteSpan data);

bool chacha20poly1305_encrypt(
    MutableByteSpan ciphertext, Poly1305Tag& tag, ByteSpan plaintext, ByteSpan aad, const ChaCha20Key& key, const ChaCha20Nonce& nonce
);
bool chacha20poly1305_decrypt(
    MutableByteSpan plaintext, ByteSpan ciphertext, const Poly1305Tag& tag, ByteSpan aad, const ChaCha20Key& key, const ChaCha20Nonce& nonce
);
bool xchacha20poly1305_encrypt(
    MutableByteSpan ciphertext, Poly1305Tag& tag, ByteSpan plaintext, ByteSpan aad, const ChaCha20Key& key, const XChaCha20Nonce& nonce
);
bool xchacha20poly1305_decrypt(
    MutableByteSpan plaintext,
    ByteSpan ciphertext,
    const Poly1305Tag& tag,
    ByteSpan aad,
    const ChaCha20Key& key,
    const XChaCha20Nonce& nonce
);

bool x25519(X25519Key& out, const X25519Key& scalar, const X25519Key& point);
bool x25519_public_key(X25519Key& out, const X25519Key& private_key);

} // namespace wgnx::wireguard::crypto
