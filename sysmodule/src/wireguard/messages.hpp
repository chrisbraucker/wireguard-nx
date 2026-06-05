#pragma once

#include "wgnx/platform/packet.hpp"

#include "wireguard/constants.hpp"

#include <cstddef>
#include <cstdint>

namespace wgnx::wireguard {

struct message_macs {
    std::uint8_t mac1[NoiseMacSize];
    std::uint8_t mac2[NoiseMacSize];
};

struct message_handshake_initiation {
    std::uint32_t type;
    std::uint32_t sender_index;
    std::uint8_t unencrypted_ephemeral[NoisePublicKeySize];
    std::uint8_t encrypted_static[EncryptedStaticSize];
    std::uint8_t encrypted_timestamp[EncryptedTimestampSize];
    message_macs macs;
};

struct message_handshake_response {
    std::uint32_t type;
    std::uint32_t sender_index;
    std::uint32_t receiver_index;
    std::uint8_t unencrypted_ephemeral[NoisePublicKeySize];
    std::uint8_t encrypted_nothing[EncryptedNothingSize];
    message_macs macs;
};

struct message_handshake_cookie {
    std::uint32_t type;
    std::uint32_t receiver_index;
    std::uint8_t nonce[CookieNonceSize];
    std::uint8_t encrypted_cookie[EncryptedCookieSize];
};

struct message_transport_data {
    std::uint32_t type;
    std::uint32_t receiver_index;
    std::uint64_t counter;
};

enum class ParseError : std::uint8_t {
    None = 0,
    NullPacket,
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

ParseResult InspectMessageType(const wgnx::platform::packet_buffer *packet, MessageType *out_type);
void SetMessageType(std::uint32_t *field, MessageType type);
MessageType GetMessageType(std::uint32_t field);

ParseResult ParseHandshakeInitiation(
    const wgnx::platform::packet_buffer *packet,
    message_handshake_initiation *out_message);
ParseResult ParseHandshakeResponse(
    const wgnx::platform::packet_buffer *packet,
    message_handshake_response *out_message);
ParseResult ParseHandshakeCookie(
    const wgnx::platform::packet_buffer *packet,
    message_handshake_cookie *out_message);
ParseResult ParseTransportDataHeader(
    const wgnx::platform::packet_buffer *packet,
    message_transport_data *out_message);

ParseError SerializeHandshakeInitiation(
    wgnx::platform::packet_buffer *packet,
    const message_handshake_initiation &message);
ParseError SerializeHandshakeResponse(
    wgnx::platform::packet_buffer *packet,
    const message_handshake_response &message);
ParseError SerializeHandshakeCookie(
    wgnx::platform::packet_buffer *packet,
    const message_handshake_cookie &message);
ParseError SerializeTransportDataHeader(
    wgnx::platform::packet_buffer *packet,
    const message_transport_data &message);

static_assert(sizeof(message_macs) == 32);
static_assert(sizeof(message_handshake_initiation) == 148);
static_assert(sizeof(message_handshake_response) == 92);
static_assert(sizeof(message_handshake_cookie) == 64);
static_assert(sizeof(message_transport_data) == 16);

} // namespace wgnx::wireguard
