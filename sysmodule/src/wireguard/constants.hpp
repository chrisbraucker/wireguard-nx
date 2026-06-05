#pragma once

#include <cstddef>
#include <cstdint>

namespace wgnx::wireguard {

enum class MessageType : std::uint32_t {
    Invalid = 0,
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    CookieReply = 3,
    TransportData = 4,
};

constexpr inline std::size_t MessageTypeSize = sizeof(std::uint32_t);
constexpr inline std::size_t MessageSenderIndexSize = sizeof(std::uint32_t);
constexpr inline std::size_t MessageReceiverIndexSize = sizeof(std::uint32_t);
constexpr inline std::size_t MessageCounterSize = sizeof(std::uint64_t);

constexpr inline std::size_t NoisePublicKeySize = 32;
constexpr inline std::size_t NoiseMacSize = 16;
constexpr inline std::size_t NoiseTagSize = 16;
constexpr inline std::size_t TAI64NTimestampSize = 12;
constexpr inline std::size_t CookieNonceSize = 24;
constexpr inline std::size_t CookieValueSize = 16;

constexpr inline std::size_t EncryptedStaticSize = NoisePublicKeySize + NoiseTagSize;
constexpr inline std::size_t EncryptedTimestampSize = TAI64NTimestampSize + NoiseTagSize;
constexpr inline std::size_t EncryptedNothingSize = NoiseTagSize;
constexpr inline std::size_t EncryptedCookieSize = CookieValueSize + NoiseTagSize;

} // namespace wgnx::wireguard
