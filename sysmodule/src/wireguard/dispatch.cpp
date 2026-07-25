#include "wireguard/dispatch.hpp"

namespace wgnx::wireguard {

ParseResult DispatchPacket(std::span<const std::uint8_t> packet, const PacketDispatchHandlers& handlers) {
    ParseResult result = InspectMessageType(packet);
    if (!result.success) {
        return result;
    }

    switch (result.type) {
    case MessageType::HandshakeInitiation: {
        message_handshake_initiation message = {};
        result = ParseHandshakeInitiation(packet, message);
        if (result.success && handlers.handshake_initiation != nullptr) {
            handlers.handshake_initiation(handlers.context, message);
        }
        return result;
    }
    case MessageType::HandshakeResponse: {
        message_handshake_response message = {};
        result = ParseHandshakeResponse(packet, message);
        if (result.success && handlers.handshake_response != nullptr) {
            handlers.handshake_response(handlers.context, message);
        }
        return result;
    }
    case MessageType::CookieReply: {
        message_handshake_cookie message = {};
        result = ParseHandshakeCookie(packet, message);
        if (result.success && handlers.cookie_reply != nullptr) {
            handlers.cookie_reply(handlers.context, message);
        }
        return result;
    }
    case MessageType::TransportData: {
        message_transport_data message = {};
        result = ParseTransportDataHeader(packet, message);
        if (result.success && handlers.transport_data != nullptr) {
            handlers.transport_data(handlers.context, message, packet.subspan(TransportDataHeaderSize));
        }
        return result;
    }
    case MessageType::Invalid:
        break;
    }

    return ParseResult{
        .success = false,
        .error = ParseError::UnknownType,
        .type = result.type,
    };
}

} // namespace wgnx::wireguard
