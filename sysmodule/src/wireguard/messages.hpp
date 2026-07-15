#pragma once

#include "wireguard/constants.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace wgnx::wireguard {

struct message_macs {
    std::array<std::uint8_t, NoiseMacSize> mac1{};
    std::array<std::uint8_t, NoiseMacSize> mac2{};
};

struct message_handshake_initiation {
    std::uint32_t type{0};
    std::uint32_t sender_index{0};
    std::array<std::uint8_t, NoisePublicKeySize> unencrypted_ephemeral{};
    std::array<std::uint8_t, EncryptedStaticSize> encrypted_static{};
    std::array<std::uint8_t, EncryptedTimestampSize> encrypted_timestamp{};
    message_macs macs;
};

struct message_handshake_response {
    std::uint32_t type{0};
    std::uint32_t sender_index{0};
    std::uint32_t receiver_index{0};
    std::array<std::uint8_t, NoisePublicKeySize> unencrypted_ephemeral{};
    std::array<std::uint8_t, EncryptedNothingSize> encrypted_nothing{};
    message_macs macs;
};

struct message_handshake_cookie {
    std::uint32_t type{0};
    std::uint32_t receiver_index{0};
    std::array<std::uint8_t, CookieNonceSize> nonce{};
    std::array<std::uint8_t, EncryptedCookieSize> encrypted_cookie{};
};

struct message_transport_data {
    std::uint32_t type{0};
    std::uint32_t receiver_index{0};
    std::uint64_t counter{0};
};

enum class ParseError : std::uint8_t {
    None = 0,
    MissingType,
    UnknownType,
    InvalidLength,
    InvalidArgument,
    InsufficientCapacity,
};

struct ParseResult {
    bool success{false};
    ParseError error{ParseError::None};
    MessageType type{MessageType::Invalid};
};

constexpr inline std::size_t HandshakeInitiationSize = sizeof(message_handshake_initiation);
constexpr inline std::size_t HandshakeResponseSize = sizeof(message_handshake_response);
constexpr inline std::size_t HandshakeCookieSize = sizeof(message_handshake_cookie);
constexpr inline std::size_t TransportDataHeaderSize = sizeof(message_transport_data);

const char *GetMessageTypeName(MessageType type);
const char *GetParseErrorName(ParseError error);

ParseResult InspectMessageType(std::span<const std::uint8_t> packet);
void SetMessageType(std::uint32_t &field, MessageType type);
MessageType GetMessageType(std::uint32_t field);

ParseResult ParseHandshakeInitiation(
    std::span<const std::uint8_t> packet,
    message_handshake_initiation &out_message);
ParseResult ParseHandshakeResponse(
    std::span<const std::uint8_t> packet,
    message_handshake_response &out_message);
ParseResult ParseHandshakeCookie(
    std::span<const std::uint8_t> packet,
    message_handshake_cookie &out_message);
ParseResult ParseTransportDataHeader(
    std::span<const std::uint8_t> packet,
    message_transport_data &out_message);

ParseError SerializeHandshakeInitiation(
    std::span<std::uint8_t> output,
    const message_handshake_initiation &message);
ParseError SerializeHandshakeResponse(
    std::span<std::uint8_t> output,
    const message_handshake_response &message);
ParseError SerializeHandshakeCookie(
    std::span<std::uint8_t> output,
    const message_handshake_cookie &message);
ParseError SerializeTransportDataHeader(
    std::span<std::uint8_t> output,
    const message_transport_data &message);

static_assert(sizeof(message_macs) == 32);
static_assert(sizeof(message_handshake_initiation) == 148);
static_assert(sizeof(message_handshake_response) == 92);
static_assert(sizeof(message_handshake_cookie) == 64);
static_assert(sizeof(message_transport_data) == 16);

} // namespace wgnx::wireguard
