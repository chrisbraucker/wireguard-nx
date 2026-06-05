#include "wireguard/messages.hpp"

#include "wireguard/endian.hpp"

#include <cstring>

namespace wgnx::wireguard {

namespace {

ParseResult MakeFailure(ParseError error, MessageType type = MessageType::Invalid) {
    return ParseResult{
        .success = false,
        .error = error,
        .type = type,
    };
}

ParseResult MakeSuccess(MessageType type) {
    return ParseResult{
        .success = true,
        .error = ParseError::None,
        .type = type,
    };
}

ParseResult ValidateExactPacket(
    const wgnx::platform::packet_buffer *packet,
    MessageType expected_type,
    std::size_t exact_size) {
    if (packet == nullptr || packet->data == nullptr) {
        return MakeFailure(ParseError::NullPacket);
    }

    MessageType actual_type = MessageType::Invalid;
    const ParseResult type_result = InspectMessageType(packet, &actual_type);
    if (!type_result.success) {
        return type_result;
    }
    if (actual_type != expected_type) {
        return MakeFailure(ParseError::UnknownType, actual_type);
    }
    if (packet->len != exact_size) {
        return MakeFailure(ParseError::InvalidLength, actual_type);
    }

    return MakeSuccess(actual_type);
}

ParseResult ValidateMinimumPacket(
    const wgnx::platform::packet_buffer *packet,
    MessageType expected_type,
    std::size_t minimum_size) {
    if (packet == nullptr || packet->data == nullptr) {
        return MakeFailure(ParseError::NullPacket);
    }

    MessageType actual_type = MessageType::Invalid;
    const ParseResult type_result = InspectMessageType(packet, &actual_type);
    if (!type_result.success) {
        return type_result;
    }
    if (actual_type != expected_type) {
        return MakeFailure(ParseError::UnknownType, actual_type);
    }
    if (packet->len < minimum_size) {
        return MakeFailure(ParseError::InvalidLength, actual_type);
    }

    return MakeSuccess(actual_type);
}

ParseError ValidateSerializeTarget(
    wgnx::platform::packet_buffer *packet,
    std::size_t required_size,
    MessageType actual_type,
    MessageType expected_type) {
    if (packet == nullptr || packet->data == nullptr) {
        return ParseError::NullPacket;
    }
    if (packet->capacity < required_size) {
        return ParseError::InsufficientCapacity;
    }
    if (actual_type != expected_type) {
        return ParseError::InvalidArgument;
    }

    return ParseError::None;
}

} // namespace

const char *GetMessageTypeName(MessageType type) {
    switch (type) {
        case MessageType::Invalid:
            return "invalid";
        case MessageType::HandshakeInitiation:
            return "handshake_initiation";
        case MessageType::HandshakeResponse:
            return "handshake_response";
        case MessageType::CookieReply:
            return "cookie_reply";
        case MessageType::TransportData:
            return "transport_data";
    }

    return "unknown";
}

const char *GetParseErrorName(ParseError error) {
    switch (error) {
        case ParseError::None:
            return "none";
        case ParseError::NullPacket:
            return "null_packet";
        case ParseError::MissingType:
            return "missing_type";
        case ParseError::UnknownType:
            return "unknown_type";
        case ParseError::InvalidLength:
            return "invalid_length";
        case ParseError::InvalidArgument:
            return "invalid_argument";
        case ParseError::InsufficientCapacity:
            return "insufficient_capacity";
    }

    return "unknown";
}

ParseResult InspectMessageType(const wgnx::platform::packet_buffer *packet, MessageType *out_type) {
    if (packet == nullptr || packet->data == nullptr) {
        return MakeFailure(ParseError::NullPacket);
    }
    if (out_type == nullptr) {
        return MakeFailure(ParseError::InvalidArgument);
    }
    if (packet->len < MessageTypeSize) {
        *out_type = MessageType::Invalid;
        return MakeFailure(ParseError::MissingType);
    }

    const auto type = static_cast<MessageType>(LoadLe32(packet->data));
    *out_type = type;
    switch (type) {
        case MessageType::HandshakeInitiation:
        case MessageType::HandshakeResponse:
        case MessageType::CookieReply:
        case MessageType::TransportData:
            return MakeSuccess(type);
        case MessageType::Invalid:
            break;
    }

    return MakeFailure(ParseError::UnknownType, type);
}

void SetMessageType(std::uint32_t *field, MessageType type) {
    if (field == nullptr) {
        return;
    }

    *field = static_cast<std::uint32_t>(type);
}

MessageType GetMessageType(std::uint32_t field) {
    return static_cast<MessageType>(field);
}

ParseResult ParseHandshakeInitiation(
    const wgnx::platform::packet_buffer *packet,
    message_handshake_initiation *out_message) {
    if (out_message == nullptr) {
        return MakeFailure(ParseError::InvalidArgument);
    }

    const ParseResult result = ValidateExactPacket(packet, MessageType::HandshakeInitiation, sizeof(message_handshake_initiation));
    if (!result.success) {
        return result;
    }

    const std::uint8_t *in = packet->data;
    out_message->type = LoadLe32(in);
    in += sizeof(std::uint32_t);
    out_message->sender_index = LoadLe32(in);
    in += sizeof(std::uint32_t);
    std::memcpy(out_message->unencrypted_ephemeral, in, sizeof(out_message->unencrypted_ephemeral));
    in += sizeof(out_message->unencrypted_ephemeral);
    std::memcpy(out_message->encrypted_static, in, sizeof(out_message->encrypted_static));
    in += sizeof(out_message->encrypted_static);
    std::memcpy(out_message->encrypted_timestamp, in, sizeof(out_message->encrypted_timestamp));
    in += sizeof(out_message->encrypted_timestamp);
    std::memcpy(&out_message->macs, in, sizeof(out_message->macs));
    return result;
}

ParseResult ParseHandshakeResponse(
    const wgnx::platform::packet_buffer *packet,
    message_handshake_response *out_message) {
    if (out_message == nullptr) {
        return MakeFailure(ParseError::InvalidArgument);
    }

    const ParseResult result = ValidateExactPacket(packet, MessageType::HandshakeResponse, sizeof(message_handshake_response));
    if (!result.success) {
        return result;
    }

    const std::uint8_t *in = packet->data;
    out_message->type = LoadLe32(in);
    in += sizeof(std::uint32_t);
    out_message->sender_index = LoadLe32(in);
    in += sizeof(std::uint32_t);
    out_message->receiver_index = LoadLe32(in);
    in += sizeof(std::uint32_t);
    std::memcpy(out_message->unencrypted_ephemeral, in, sizeof(out_message->unencrypted_ephemeral));
    in += sizeof(out_message->unencrypted_ephemeral);
    std::memcpy(out_message->encrypted_nothing, in, sizeof(out_message->encrypted_nothing));
    in += sizeof(out_message->encrypted_nothing);
    std::memcpy(&out_message->macs, in, sizeof(out_message->macs));
    return result;
}

ParseResult ParseHandshakeCookie(
    const wgnx::platform::packet_buffer *packet,
    message_handshake_cookie *out_message) {
    if (out_message == nullptr) {
        return MakeFailure(ParseError::InvalidArgument);
    }

    const ParseResult result = ValidateExactPacket(packet, MessageType::CookieReply, sizeof(message_handshake_cookie));
    if (!result.success) {
        return result;
    }

    const std::uint8_t *in = packet->data;
    out_message->type = LoadLe32(in);
    in += sizeof(std::uint32_t);
    out_message->receiver_index = LoadLe32(in);
    in += sizeof(std::uint32_t);
    std::memcpy(out_message->nonce, in, sizeof(out_message->nonce));
    in += sizeof(out_message->nonce);
    std::memcpy(out_message->encrypted_cookie, in, sizeof(out_message->encrypted_cookie));
    return result;
}

ParseResult ParseTransportDataHeader(
    const wgnx::platform::packet_buffer *packet,
    message_transport_data *out_message) {
    if (out_message == nullptr) {
        return MakeFailure(ParseError::InvalidArgument);
    }

    const ParseResult result = ValidateMinimumPacket(packet, MessageType::TransportData, sizeof(message_transport_data));
    if (!result.success) {
        return result;
    }

    const std::uint8_t *in = packet->data;
    out_message->type = LoadLe32(in);
    in += sizeof(std::uint32_t);
    out_message->receiver_index = LoadLe32(in);
    in += sizeof(std::uint32_t);
    out_message->counter = LoadLe64(in);
    return result;
}

ParseError SerializeHandshakeInitiation(
    wgnx::platform::packet_buffer *packet,
    const message_handshake_initiation &message) {
    ParseError error = ValidateSerializeTarget(packet, sizeof(message_handshake_initiation), GetMessageType(message.type), MessageType::HandshakeInitiation);
    if (error != ParseError::None) {
        return error;
    }

    std::uint8_t *out = packet->data;
    StoreLe32(out, message.type);
    out += sizeof(std::uint32_t);
    StoreLe32(out, message.sender_index);
    out += sizeof(std::uint32_t);
    std::memcpy(out, message.unencrypted_ephemeral, sizeof(message.unencrypted_ephemeral));
    out += sizeof(message.unencrypted_ephemeral);
    std::memcpy(out, message.encrypted_static, sizeof(message.encrypted_static));
    out += sizeof(message.encrypted_static);
    std::memcpy(out, message.encrypted_timestamp, sizeof(message.encrypted_timestamp));
    out += sizeof(message.encrypted_timestamp);
    std::memcpy(out, &message.macs, sizeof(message.macs));
    packet->len = sizeof(message_handshake_initiation);
    return ParseError::None;
}

ParseError SerializeHandshakeResponse(
    wgnx::platform::packet_buffer *packet,
    const message_handshake_response &message) {
    ParseError error = ValidateSerializeTarget(packet, sizeof(message_handshake_response), GetMessageType(message.type), MessageType::HandshakeResponse);
    if (error != ParseError::None) {
        return error;
    }

    std::uint8_t *out = packet->data;
    StoreLe32(out, message.type);
    out += sizeof(std::uint32_t);
    StoreLe32(out, message.sender_index);
    out += sizeof(std::uint32_t);
    StoreLe32(out, message.receiver_index);
    out += sizeof(std::uint32_t);
    std::memcpy(out, message.unencrypted_ephemeral, sizeof(message.unencrypted_ephemeral));
    out += sizeof(message.unencrypted_ephemeral);
    std::memcpy(out, message.encrypted_nothing, sizeof(message.encrypted_nothing));
    out += sizeof(message.encrypted_nothing);
    std::memcpy(out, &message.macs, sizeof(message.macs));
    packet->len = sizeof(message_handshake_response);
    return ParseError::None;
}

ParseError SerializeHandshakeCookie(
    wgnx::platform::packet_buffer *packet,
    const message_handshake_cookie &message) {
    ParseError error = ValidateSerializeTarget(packet, sizeof(message_handshake_cookie), GetMessageType(message.type), MessageType::CookieReply);
    if (error != ParseError::None) {
        return error;
    }

    std::uint8_t *out = packet->data;
    StoreLe32(out, message.type);
    out += sizeof(std::uint32_t);
    StoreLe32(out, message.receiver_index);
    out += sizeof(std::uint32_t);
    std::memcpy(out, message.nonce, sizeof(message.nonce));
    out += sizeof(message.nonce);
    std::memcpy(out, message.encrypted_cookie, sizeof(message.encrypted_cookie));
    packet->len = sizeof(message_handshake_cookie);
    return ParseError::None;
}

ParseError SerializeTransportDataHeader(
    wgnx::platform::packet_buffer *packet,
    const message_transport_data &message) {
    ParseError error = ValidateSerializeTarget(packet, sizeof(message_transport_data), GetMessageType(message.type), MessageType::TransportData);
    if (error != ParseError::None) {
        return error;
    }

    std::uint8_t *out = packet->data;
    StoreLe32(out, message.type);
    out += sizeof(std::uint32_t);
    StoreLe32(out, message.receiver_index);
    out += sizeof(std::uint32_t);
    StoreLe64(out, message.counter);
    packet->len = sizeof(message_transport_data);
    return ParseError::None;
}

} // namespace wgnx::wireguard
