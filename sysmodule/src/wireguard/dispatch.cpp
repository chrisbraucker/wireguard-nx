#include "wireguard/dispatch.hpp"

namespace wgnx::wireguard {

ParseResult DispatchPacket(
    const wgnx::platform::packet_buffer *packet,
    const PacketDispatchHandlers &handlers) {
    MessageType type = MessageType::Invalid;
    ParseResult result = InspectMessageType(packet, &type);
    if (!result.success) {
        return result;
    }

    switch (type) {
        case MessageType::HandshakeInitiation: {
            message_handshake_initiation message = {};
            result = ParseHandshakeInitiation(packet, &message);
            if (result.success && handlers.handshake_initiation != nullptr) {
                handlers.handshake_initiation(handlers.context, message);
            }
            return result;
        }
        case MessageType::HandshakeResponse: {
            message_handshake_response message = {};
            result = ParseHandshakeResponse(packet, &message);
            if (result.success && handlers.handshake_response != nullptr) {
                handlers.handshake_response(handlers.context, message);
            }
            return result;
        }
        case MessageType::CookieReply: {
            message_handshake_cookie message = {};
            result = ParseHandshakeCookie(packet, &message);
            if (result.success && handlers.cookie_reply != nullptr) {
                handlers.cookie_reply(handlers.context, message);
            }
            return result;
        }
        case MessageType::TransportData: {
            message_transport_data message = {};
            result = ParseTransportDataHeader(packet, &message);
            if (result.success && handlers.transport_data != nullptr) {
                const std::uint8_t *payload = packet->data + TransportDataHeaderSize;
                const std::size_t payload_size = packet->len - TransportDataHeaderSize;
                handlers.transport_data(handlers.context, message, payload, payload_size);
            }
            return result;
        }
        case MessageType::Invalid:
            break;
    }

    return ParseResult{
        .success = false,
        .error = ParseError::UnknownType,
        .type = type,
    };
}

} // namespace wgnx::wireguard
