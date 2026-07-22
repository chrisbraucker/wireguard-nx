#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>

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

// WireGuard protocol limits, matching wireguard-go/device/constants.go.
constexpr inline std::uint64_t RekeyAfterMessages = std::uint64_t{1} << 60U;
constexpr inline std::uint64_t RejectAfterMessages =
    std::numeric_limits<std::uint64_t>::max() - (std::uint64_t{1} << 13U);
constexpr inline auto RekeyAfterTime = std::chrono::seconds{120};
constexpr inline auto RekeyAttemptTime = std::chrono::seconds{90};
constexpr inline auto RekeyTimeout = std::chrono::seconds{5};
constexpr inline auto KeepaliveTimeout = std::chrono::seconds{10};
constexpr inline auto HandshakeInitiationRate = std::chrono::milliseconds{20};
constexpr inline std::uint32_t MaxTimerHandshakes =
    static_cast<std::uint32_t>(RekeyAttemptTime / RekeyTimeout);
constexpr inline std::uint32_t RekeyTimeoutJitterMaxMs = 334;
constexpr inline auto RejectAfterTime = std::chrono::seconds{180};
constexpr inline auto ZeroKeyMaterialAfterTime = RejectAfterTime * 3;

} // namespace wgnx::wireguard
