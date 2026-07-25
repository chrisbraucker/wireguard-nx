#include "wireguard/messages.hpp"

#include "wireguard/endian.hpp"

#include <algorithm>
#include <array>
#include <span>

namespace wgnx::wireguard {

namespace {

ParseResult MakeFailure(ParseError error, MessageType type = MessageType::Invalid) {
    return {.success = false, .error = error, .type = type};
}

ParseResult MakeSuccess(MessageType type) {
    return {.success = true, .error = ParseError::None, .type = type};
}

class PacketReader {
  public:
    explicit PacketReader(std::span<const std::uint8_t> input) : m_input(input) {}

    bool ReadLe32(std::uint32_t& value) {
        if (!CanRead(sizeof(value))) {
            return false;
        }
        value = LoadLe32(m_input.data() + m_offset);
        m_offset += sizeof(value);
        return true;
    }

    bool ReadLe64(std::uint64_t& value) {
        if (!CanRead(sizeof(value))) {
            return false;
        }
        value = LoadLe64(m_input.data() + m_offset);
        m_offset += sizeof(value);
        return true;
    }

    template <std::size_t Size> bool Read(std::array<std::uint8_t, Size>& value) {
        if (!CanRead(Size)) {
            return false;
        }
        std::ranges::copy(m_input.subspan(m_offset, Size), value.begin());
        m_offset += Size;
        return true;
    }

  private:
    bool CanRead(std::size_t size) const {
        return size <= m_input.size() - m_offset;
    }

    std::span<const std::uint8_t> m_input;
    std::size_t m_offset{0};
};

class PacketWriter {
  public:
    explicit PacketWriter(std::span<std::uint8_t> output) : m_output(output) {}

    bool WriteLe32(std::uint32_t value) {
        if (!CanWrite(sizeof(value))) {
            return false;
        }
        StoreLe32(m_output.data() + m_offset, value);
        m_offset += sizeof(value);
        return true;
    }

    bool WriteLe64(std::uint64_t value) {
        if (!CanWrite(sizeof(value))) {
            return false;
        }
        StoreLe64(m_output.data() + m_offset, value);
        m_offset += sizeof(value);
        return true;
    }

    template <std::size_t Size> bool Write(const std::array<std::uint8_t, Size>& value) {
        if (!CanWrite(Size)) {
            return false;
        }
        std::ranges::copy(value, m_output.begin() + static_cast<std::ptrdiff_t>(m_offset));
        m_offset += Size;
        return true;
    }

  private:
    bool CanWrite(std::size_t size) const {
        return size <= m_output.size() - m_offset;
    }

    std::span<std::uint8_t> m_output;
    std::size_t m_offset{0};
};

ParseResult ValidatePacket(std::span<const std::uint8_t> packet, MessageType expected_type, std::size_t required_size, bool exact_size) {
    const ParseResult type_result = InspectMessageType(packet);
    if (!type_result.success) {
        return type_result;
    }
    if (type_result.type != expected_type) {
        return MakeFailure(ParseError::UnknownType, type_result.type);
    }
    if ((exact_size && packet.size() != required_size) || (!exact_size && packet.size() < required_size)) {
        return MakeFailure(ParseError::InvalidLength, type_result.type);
    }
    return MakeSuccess(type_result.type);
}

ParseError ValidateSerializeTarget(std::span<std::uint8_t> output, std::size_t required_size, MessageType actual_type,
                                   MessageType expected_type) {
    if (output.size() < required_size) {
        return ParseError::InsufficientCapacity;
    }
    return actual_type == expected_type ? ParseError::None : ParseError::InvalidArgument;
}

} // namespace

const char* GetMessageTypeName(MessageType type) {
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

const char* GetParseErrorName(ParseError error) {
    switch (error) {
    case ParseError::None:
        return "none";
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

ParseResult InspectMessageType(std::span<const std::uint8_t> packet) {
    if (packet.size() < MessageTypeSize) {
        return MakeFailure(ParseError::MissingType);
    }

    const auto type = static_cast<MessageType>(LoadLe32(packet.data()));
    switch (type) {
    case MessageType::HandshakeInitiation:
    case MessageType::HandshakeResponse:
    case MessageType::CookieReply:
    case MessageType::TransportData:
        return MakeSuccess(type);
    case MessageType::Invalid:
        return MakeFailure(ParseError::UnknownType, type);
    }
    return MakeFailure(ParseError::UnknownType, type);
}

void SetMessageType(std::uint32_t& field, MessageType type) {
    field = static_cast<std::uint32_t>(type);
}

MessageType GetMessageType(std::uint32_t field) {
    return static_cast<MessageType>(field);
}

ParseResult ParseHandshakeInitiation(std::span<const std::uint8_t> packet, message_handshake_initiation& out_message) {
    const ParseResult result = ValidatePacket(packet, MessageType::HandshakeInitiation, HandshakeInitiationSize, true);
    if (!result.success) {
        return result;
    }
    PacketReader reader(packet);
    const bool parsed = reader.ReadLe32(out_message.type) && reader.ReadLe32(out_message.sender_index) &&
                        reader.Read(out_message.unencrypted_ephemeral) && reader.Read(out_message.encrypted_static) &&
                        reader.Read(out_message.encrypted_timestamp) && reader.Read(out_message.macs.mac1) &&
                        reader.Read(out_message.macs.mac2);
    return parsed ? result : MakeFailure(ParseError::InvalidLength, result.type);
}

ParseResult ParseHandshakeResponse(std::span<const std::uint8_t> packet, message_handshake_response& out_message) {
    const ParseResult result = ValidatePacket(packet, MessageType::HandshakeResponse, HandshakeResponseSize, true);
    if (!result.success) {
        return result;
    }
    PacketReader reader(packet);
    const bool parsed = reader.ReadLe32(out_message.type) && reader.ReadLe32(out_message.sender_index) &&
                        reader.ReadLe32(out_message.receiver_index) && reader.Read(out_message.unencrypted_ephemeral) &&
                        reader.Read(out_message.encrypted_nothing) && reader.Read(out_message.macs.mac1) &&
                        reader.Read(out_message.macs.mac2);
    return parsed ? result : MakeFailure(ParseError::InvalidLength, result.type);
}

ParseResult ParseHandshakeCookie(std::span<const std::uint8_t> packet, message_handshake_cookie& out_message) {
    const ParseResult result = ValidatePacket(packet, MessageType::CookieReply, HandshakeCookieSize, true);
    if (!result.success) {
        return result;
    }
    PacketReader reader(packet);
    const bool parsed = reader.ReadLe32(out_message.type) && reader.ReadLe32(out_message.receiver_index) &&
                        reader.Read(out_message.nonce) && reader.Read(out_message.encrypted_cookie);
    return parsed ? result : MakeFailure(ParseError::InvalidLength, result.type);
}

ParseResult ParseTransportDataHeader(std::span<const std::uint8_t> packet, message_transport_data& out_message) {
    const ParseResult result = ValidatePacket(packet, MessageType::TransportData, TransportDataHeaderSize, false);
    if (!result.success) {
        return result;
    }
    PacketReader reader(packet);
    const bool parsed =
        reader.ReadLe32(out_message.type) && reader.ReadLe32(out_message.receiver_index) && reader.ReadLe64(out_message.counter);
    return parsed ? result : MakeFailure(ParseError::InvalidLength, result.type);
}

ParseError SerializeHandshakeInitiation(std::span<std::uint8_t> output, const message_handshake_initiation& message) {
    const ParseError error =
        ValidateSerializeTarget(output, HandshakeInitiationSize, GetMessageType(message.type), MessageType::HandshakeInitiation);
    if (error != ParseError::None) {
        return error;
    }
    PacketWriter writer(output.first(HandshakeInitiationSize));
    return writer.WriteLe32(message.type) && writer.WriteLe32(message.sender_index) && writer.Write(message.unencrypted_ephemeral) &&
                   writer.Write(message.encrypted_static) && writer.Write(message.encrypted_timestamp) && writer.Write(message.macs.mac1) &&
                   writer.Write(message.macs.mac2)
               ? ParseError::None
               : ParseError::InsufficientCapacity;
}

ParseError SerializeHandshakeResponse(std::span<std::uint8_t> output, const message_handshake_response& message) {
    const ParseError error =
        ValidateSerializeTarget(output, HandshakeResponseSize, GetMessageType(message.type), MessageType::HandshakeResponse);
    if (error != ParseError::None) {
        return error;
    }
    PacketWriter writer(output.first(HandshakeResponseSize));
    return writer.WriteLe32(message.type) && writer.WriteLe32(message.sender_index) && writer.WriteLe32(message.receiver_index) &&
                   writer.Write(message.unencrypted_ephemeral) && writer.Write(message.encrypted_nothing) &&
                   writer.Write(message.macs.mac1) && writer.Write(message.macs.mac2)
               ? ParseError::None
               : ParseError::InsufficientCapacity;
}

ParseError SerializeHandshakeCookie(std::span<std::uint8_t> output, const message_handshake_cookie& message) {
    const ParseError error = ValidateSerializeTarget(output, HandshakeCookieSize, GetMessageType(message.type), MessageType::CookieReply);
    if (error != ParseError::None) {
        return error;
    }
    PacketWriter writer(output.first(HandshakeCookieSize));
    return writer.WriteLe32(message.type) && writer.WriteLe32(message.receiver_index) && writer.Write(message.nonce) &&
                   writer.Write(message.encrypted_cookie)
               ? ParseError::None
               : ParseError::InsufficientCapacity;
}

ParseError SerializeTransportDataHeader(std::span<std::uint8_t> output, const message_transport_data& message) {
    const ParseError error =
        ValidateSerializeTarget(output, TransportDataHeaderSize, GetMessageType(message.type), MessageType::TransportData);
    if (error != ParseError::None) {
        return error;
    }
    PacketWriter writer(output.first(TransportDataHeaderSize));
    return writer.WriteLe32(message.type) && writer.WriteLe32(message.receiver_index) && writer.WriteLe64(message.counter)
               ? ParseError::None
               : ParseError::InsufficientCapacity;
}

} // namespace wgnx::wireguard
