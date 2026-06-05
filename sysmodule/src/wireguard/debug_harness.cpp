#include "wireguard/debug_harness.hpp"

#include "logger.hpp"
#include "wireguard/messages.hpp"

#include <cstring>

namespace wgnx::wireguard {

namespace {

template<typename Message>
bool RoundTripExact(
    const Message &source,
    ParseError (*serialize)(wgnx::platform::packet_buffer *, const Message &),
    ParseResult (*parse)(const wgnx::platform::packet_buffer *, Message *)) {
    wgnx::platform::static_packet_buffer<256> buffer;
    if (serialize(&buffer.packet, source) != ParseError::None) {
        return false;
    }

    Message parsed = {};
    const ParseResult result = parse(&buffer.packet, &parsed);
    if (!result.success) {
        return false;
    }

    return std::memcmp(&source, &parsed, sizeof(Message)) == 0;
}

bool TestHandshakeInitiation() {
    message_handshake_initiation message = {};
    message.type = static_cast<std::uint32_t>(MessageType::HandshakeInitiation);
    message.sender_index = 0x11223344U;
    for (std::size_t i = 0; i < sizeof(message.unencrypted_ephemeral); ++i) {
        message.unencrypted_ephemeral[i] = static_cast<std::uint8_t>(i);
    }
    for (std::size_t i = 0; i < sizeof(message.encrypted_static); ++i) {
        message.encrypted_static[i] = static_cast<std::uint8_t>(0x80U + i);
    }
    for (std::size_t i = 0; i < sizeof(message.encrypted_timestamp); ++i) {
        message.encrypted_timestamp[i] = static_cast<std::uint8_t>(0x40U + i);
    }
    for (std::size_t i = 0; i < sizeof(message.macs.mac1); ++i) {
        message.macs.mac1[i] = static_cast<std::uint8_t>(0xA0U + i);
        message.macs.mac2[i] = static_cast<std::uint8_t>(0xB0U + i);
    }

    return RoundTripExact(message, SerializeHandshakeInitiation, ParseHandshakeInitiation);
}

bool TestHandshakeResponse() {
    message_handshake_response message = {};
    message.type = static_cast<std::uint32_t>(MessageType::HandshakeResponse);
    message.sender_index = 0x01020304U;
    message.receiver_index = 0x55667788U;
    for (std::size_t i = 0; i < sizeof(message.unencrypted_ephemeral); ++i) {
        message.unencrypted_ephemeral[i] = static_cast<std::uint8_t>(0x10U + i);
    }
    for (std::size_t i = 0; i < sizeof(message.encrypted_nothing); ++i) {
        message.encrypted_nothing[i] = static_cast<std::uint8_t>(0x20U + i);
    }
    for (std::size_t i = 0; i < sizeof(message.macs.mac1); ++i) {
        message.macs.mac1[i] = static_cast<std::uint8_t>(0xC0U + i);
        message.macs.mac2[i] = static_cast<std::uint8_t>(0xD0U + i);
    }

    return RoundTripExact(message, SerializeHandshakeResponse, ParseHandshakeResponse);
}

bool TestHandshakeCookie() {
    message_handshake_cookie message = {};
    message.type = static_cast<std::uint32_t>(MessageType::CookieReply);
    message.receiver_index = 0xAABBCCDDU;
    for (std::size_t i = 0; i < sizeof(message.nonce); ++i) {
        message.nonce[i] = static_cast<std::uint8_t>(0x30U + i);
    }
    for (std::size_t i = 0; i < sizeof(message.encrypted_cookie); ++i) {
        message.encrypted_cookie[i] = static_cast<std::uint8_t>(0x60U + i);
    }

    return RoundTripExact(message, SerializeHandshakeCookie, ParseHandshakeCookie);
}

bool TestTransportDataHeader() {
    message_transport_data message = {};
    message.type = static_cast<std::uint32_t>(MessageType::TransportData);
    message.receiver_index = 0xCAFEBABEU;
    message.counter = 0x0102030405060708ULL;

    wgnx::platform::static_packet_buffer<256> buffer;
    if (SerializeTransportDataHeader(&buffer.packet, message) != ParseError::None) {
        return false;
    }

    const std::uint8_t payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    std::memcpy(buffer.storage.data() + buffer.packet.len, payload, sizeof(payload));
    buffer.packet.len += sizeof(payload);

    message_transport_data parsed = {};
    const ParseResult result = ParseTransportDataHeader(&buffer.packet, &parsed);
    if (!result.success) {
        return false;
    }

    return std::memcmp(&message, &parsed, sizeof(message)) == 0;
}

bool TestUnknownTypeRejected() {
    wgnx::platform::static_packet_buffer<16> buffer;
    const std::uint32_t unknown_type = 99;
    std::memcpy(buffer.storage.data(), &unknown_type, sizeof(unknown_type));
    buffer.packet.len = sizeof(unknown_type);

    MessageType type = MessageType::Invalid;
    const ParseResult result = InspectMessageType(&buffer.packet, &type);
    return !result.success && result.error == ParseError::UnknownType;
}

bool TestMalformedLengthRejected() {
    message_handshake_initiation message = {};
    message.type = static_cast<std::uint32_t>(MessageType::HandshakeInitiation);

    wgnx::platform::static_packet_buffer<256> buffer;
    if (SerializeHandshakeInitiation(&buffer.packet, message) != ParseError::None) {
        return false;
    }
    --buffer.packet.len;

    message_handshake_initiation parsed = {};
    const ParseResult result = ParseHandshakeInitiation(&buffer.packet, &parsed);
    return !result.success && result.error == ParseError::InvalidLength;
}

} // namespace

bool RunMessageSelfTest() {
    const bool ok =
        TestHandshakeInitiation() &&
        TestHandshakeResponse() &&
        TestHandshakeCookie() &&
        TestTransportDataHeader() &&
        TestUnknownTypeRejected() &&
        TestMalformedLengthRejected();

    if (ok) {
        wgnx::sysmodule::logger::Log("WireGuard message self-test passed");
    } else {
        wgnx::sysmodule::logger::Log("WireGuard message self-test failed");
    }

    return ok;
}

} // namespace wgnx::wireguard
