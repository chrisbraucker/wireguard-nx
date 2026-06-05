#include "wireguard/messages.hpp"

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

ParseResult InspectPacketTypeAndLength(
    const wgnx::platform::packet_buffer *packet,
    MessageType expected_type,
    std::size_t exact_size,
    void *out_message) {
    if (packet == nullptr || packet->data == nullptr) {
        return MakeFailure(ParseError::NullPacket);
    }
    if (out_message == nullptr) {
        return MakeFailure(ParseError::InvalidArgument);
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

    std::memcpy(out_message, packet->data, exact_size);
    return MakeSuccess(actual_type);
}

ParseResult InspectPacketTypeAndMinimumLength(
    const wgnx::platform::packet_buffer *packet,
    MessageType expected_type,
    std::size_t minimum_size,
    void *out_message,
    std::size_t copy_size) {
    if (packet == nullptr || packet->data == nullptr) {
        return MakeFailure(ParseError::NullPacket);
    }
    if (out_message == nullptr) {
        return MakeFailure(ParseError::InvalidArgument);
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

    if (copy_size > packet->len) {
        return MakeFailure(ParseError::InvalidLength, actual_type);
    }

    std::memcpy(out_message, packet->data, copy_size);
    return MakeSuccess(actual_type);
}

template<typename Message>
ParseError SerializeFixedMessage(
    wgnx::platform::packet_buffer *packet,
    const Message &message,
    MessageType expected_type) {
    if (packet == nullptr || packet->data == nullptr) {
        return ParseError::NullPacket;
    }
    if (packet->capacity < sizeof(Message)) {
        return ParseError::InsufficientCapacity;
    }
    if (static_cast<MessageType>(message.type) != expected_type) {
        return ParseError::InvalidArgument;
    }

    std::memcpy(packet->data, &message, sizeof(Message));
    packet->len = sizeof(Message);
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

    std::uint32_t raw_type = 0;
    std::memcpy(&raw_type, packet->data, sizeof(raw_type));
    const auto type = static_cast<MessageType>(raw_type);
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

ParseResult ParseHandshakeInitiation(
    const wgnx::platform::packet_buffer *packet,
    message_handshake_initiation *out_message) {
    return InspectPacketTypeAndLength(packet, MessageType::HandshakeInitiation, sizeof(message_handshake_initiation),
        out_message);
}

ParseResult ParseHandshakeResponse(
    const wgnx::platform::packet_buffer *packet,
    message_handshake_response *out_message) {
    return InspectPacketTypeAndLength(packet, MessageType::HandshakeResponse, sizeof(message_handshake_response),
        out_message);
}

ParseResult ParseHandshakeCookie(
    const wgnx::platform::packet_buffer *packet,
    message_handshake_cookie *out_message) {
    return InspectPacketTypeAndLength(packet, MessageType::CookieReply, sizeof(message_handshake_cookie),
        out_message);
}

ParseResult ParseTransportDataHeader(
    const wgnx::platform::packet_buffer *packet,
    message_transport_data *out_message) {
    return InspectPacketTypeAndMinimumLength(packet, MessageType::TransportData, sizeof(message_transport_data),
        out_message, sizeof(message_transport_data));
}

ParseError SerializeHandshakeInitiation(
    wgnx::platform::packet_buffer *packet,
    const message_handshake_initiation &message) {
    return SerializeFixedMessage(packet, message, MessageType::HandshakeInitiation);
}

ParseError SerializeHandshakeResponse(
    wgnx::platform::packet_buffer *packet,
    const message_handshake_response &message) {
    return SerializeFixedMessage(packet, message, MessageType::HandshakeResponse);
}

ParseError SerializeHandshakeCookie(
    wgnx::platform::packet_buffer *packet,
    const message_handshake_cookie &message) {
    return SerializeFixedMessage(packet, message, MessageType::CookieReply);
}

ParseError SerializeTransportDataHeader(
    wgnx::platform::packet_buffer *packet,
    const message_transport_data &message) {
    return SerializeFixedMessage(packet, message, MessageType::TransportData);
}

} // namespace wgnx::wireguard
