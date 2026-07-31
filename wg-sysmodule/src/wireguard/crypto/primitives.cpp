#include "wireguard/crypto/primitives.hpp"

#include "wireguard/crypto/monocypher.h"
#include "wireguard/crypto/third_party/blake2/blake2.h"

#include <vapours/crypto.hpp>

#include <algorithm>
#include <memory>

namespace wgnx::wireguard::crypto {

static_assert(alignof(::blake2s_state) <= alignof(std::max_align_t));

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

bool chacha20poly1305_encrypt(
    MutableByteSpan ciphertext, Poly1305Tag& tag, ByteSpan plaintext, ByteSpan aad, const ChaCha20Key& key, const ChaCha20Nonce& nonce
) {
    if (ciphertext.size() != plaintext.size()) {
        return false;
    }

    crypto_aead_ctx ctx{};
    crypto_aead_init_ietf(&ctx, key.data(), nonce.data());
    crypto_aead_write(&ctx, ciphertext.data(), tag.data(), aad.data(), aad.size(), plaintext.data(), plaintext.size());
    secure_clear(MutableByteSpan{reinterpret_cast<std::uint8_t*>(&ctx), sizeof(ctx)});
    return true;
}

bool chacha20poly1305_decrypt(
    MutableByteSpan plaintext, ByteSpan ciphertext, const Poly1305Tag& tag, ByteSpan aad, const ChaCha20Key& key, const ChaCha20Nonce& nonce
) {
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

bool xchacha20poly1305_encrypt(
    MutableByteSpan ciphertext, Poly1305Tag& tag, ByteSpan plaintext, ByteSpan aad, const ChaCha20Key& key, const XChaCha20Nonce& nonce
) {
    if (ciphertext.size() != plaintext.size()) {
        return false;
    }

    crypto_aead_ctx ctx{};
    crypto_aead_init_x(&ctx, key.data(), nonce.data());
    crypto_aead_write(&ctx, ciphertext.data(), tag.data(), aad.data(), aad.size(), plaintext.data(), plaintext.size());
    secure_clear(MutableByteSpan{reinterpret_cast<std::uint8_t*>(&ctx), sizeof(ctx)});
    return true;
}

bool xchacha20poly1305_decrypt(
    MutableByteSpan plaintext,
    ByteSpan ciphertext,
    const Poly1305Tag& tag,
    ByteSpan aad,
    const ChaCha20Key& key,
    const XChaCha20Nonce& nonce
) {
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

} // namespace wgnx::wireguard::crypto
