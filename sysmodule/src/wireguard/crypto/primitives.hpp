#pragma once

#include <cstddef>
#include <cstdint>

namespace wgnx::wireguard::crypto {

constexpr inline std::size_t Blake2sBlockSize = 64;
constexpr inline std::size_t Blake2sHashSize = 32;
constexpr inline std::size_t ChaCha20KeySize = 32;
constexpr inline std::size_t ChaCha20BlockSize = 64;
constexpr inline std::size_t ChaCha20NonceSize = 12;
constexpr inline std::size_t XChaCha20NonceSize = 24;
constexpr inline std::size_t Poly1305KeySize = 32;
constexpr inline std::size_t Poly1305TagSize = 16;
constexpr inline std::size_t X25519KeySize = 32;

struct blake2s_state {
    std::uint32_t h[8]{};
    std::uint32_t t[2]{};
    std::uint32_t f[2]{};
    std::uint8_t buffer[Blake2sBlockSize]{};
    std::size_t buffer_len{0};
    std::size_t out_len{0};
};

void secure_clear(void *mem, std::size_t size);
bool secure_equal(const void *lhs, const void *rhs, std::size_t size);

bool blake2s_init(
    blake2s_state *state,
    std::size_t out_len,
    const void *key,
    std::size_t key_len);
void blake2s_update(blake2s_state *state, const void *data, std::size_t size);
bool blake2s_final(blake2s_state *state, void *out, std::size_t out_len);
bool blake2s(
    void *out,
    std::size_t out_len,
    const void *data,
    std::size_t data_len,
    const void *key,
    std::size_t key_len);

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
