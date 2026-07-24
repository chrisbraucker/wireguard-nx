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

void secure_clear(void *mem, std::size_t size);
bool secure_equal(const void *lhs, const void *rhs, std::size_t size);

using ByteSpan = std::span<const std::uint8_t>;
using MutableByteSpan = std::span<std::uint8_t>;

class Blake2sHasher final {
public:
    Blake2sHasher() = default;
    ~Blake2sHasher();

    Blake2sHasher(const Blake2sHasher &) = delete;
    Blake2sHasher &operator=(const Blake2sHasher &) = delete;
    Blake2sHasher(Blake2sHasher &&) = delete;
    Blake2sHasher &operator=(Blake2sHasher &&) = delete;

    bool Initialize(std::size_t digest_size, ByteSpan key = {});
    bool Update(ByteSpan data);
    bool Final(MutableByteSpan output);

private:
    void Reset();

    static constexpr std::size_t BackendStorageSize = 160;

    alignas(std::max_align_t) std::array<std::byte, BackendStorageSize> backend_storage_{};
    std::size_t digest_size_{0};
    bool initialized_{false};
    bool finalized_{false};
};

bool Blake2sHash(MutableByteSpan output, ByteSpan data, ByteSpan key = {});

void chacha20_block(
    std::uint8_t out[ChaCha20BlockSize],
    const std::uint8_t key[ChaCha20KeySize],
    std::uint32_t counter,
    const std::uint8_t nonce[ChaCha20NonceSize]);
void chacha20_xor(
    std::uint8_t *dst,
    const std::uint8_t *src,
    std::size_t size,
    const std::uint8_t key[ChaCha20KeySize],
    std::uint32_t counter,
    const std::uint8_t nonce[ChaCha20NonceSize]);

void poly1305_auth(
    std::uint8_t tag[Poly1305TagSize],
    const std::uint8_t *message,
    std::size_t message_size,
    const std::uint8_t key[Poly1305KeySize]);

bool chacha20poly1305_encrypt(
    std::uint8_t *ciphertext,
    std::uint8_t tag[Poly1305TagSize],
    const std::uint8_t *plaintext,
    std::size_t plaintext_size,
    const std::uint8_t *aad,
    std::size_t aad_size,
    const std::uint8_t key[ChaCha20KeySize],
    const std::uint8_t nonce[ChaCha20NonceSize]);
bool chacha20poly1305_decrypt(
    std::uint8_t *plaintext,
    const std::uint8_t *ciphertext,
    std::size_t ciphertext_size,
    const std::uint8_t tag[Poly1305TagSize],
    const std::uint8_t *aad,
    std::size_t aad_size,
    const std::uint8_t key[ChaCha20KeySize],
    const std::uint8_t nonce[ChaCha20NonceSize]);
bool xchacha20poly1305_encrypt(
    std::uint8_t *ciphertext,
    std::uint8_t tag[Poly1305TagSize],
    const std::uint8_t *plaintext,
    std::size_t plaintext_size,
    const std::uint8_t *aad,
    std::size_t aad_size,
    const std::uint8_t key[ChaCha20KeySize],
    const std::uint8_t nonce[XChaCha20NonceSize]);
bool xchacha20poly1305_decrypt(
    std::uint8_t *plaintext,
    const std::uint8_t *ciphertext,
    std::size_t ciphertext_size,
    const std::uint8_t tag[Poly1305TagSize],
    const std::uint8_t *aad,
    std::size_t aad_size,
    const std::uint8_t key[ChaCha20KeySize],
    const std::uint8_t nonce[XChaCha20NonceSize]);

bool x25519(
    std::uint8_t out[X25519KeySize],
    const std::uint8_t scalar[X25519KeySize],
    const std::uint8_t point[X25519KeySize]);
bool x25519_public_key(
    std::uint8_t out[X25519KeySize],
    const std::uint8_t private_key[X25519KeySize]);

bool RunPrimitiveSelfTest();

} // namespace wgnx::wireguard::crypto
