#include "wireguard/debug_harness.hpp"

#include "wireguard/device.hpp"
#include "wireguard/handshake.hpp"
#include "logger.hpp"
#include "wireguard/messages.hpp"
#include "wireguard/timers.hpp"

#include <cstdio>
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

bool TestDeviceAndPeerSkeleton() {
    wgnx::PeerConfigEntry config = {};
    std::snprintf(config.name, sizeof(config.name), "%s", "harness-peer");
    std::snprintf(config.address, sizeof(config.address), "%s", "10.66.66.2/32");
    std::snprintf(config.endpoint, sizeof(config.endpoint), "%s", "vpn.example.test:51820");
    std::snprintf(config.private_key, sizeof(config.private_key), "%s", "test-private-key");
    std::snprintf(config.public_key, sizeof(config.public_key), "%s", "test-public-key");
    std::snprintf(config.preshared_key, sizeof(config.preshared_key), "%s", "test-preshared-key");
    std::snprintf(config.allowed_ips, sizeof(config.allowed_ips), "%s", "0.0.0.0/0, ::/0");
    std::snprintf(config.dns, sizeof(config.dns), "%s", "1.1.1.1");
    config.listen_port = 51820;
    config.persistent_keepalive = 25;
    config.mtu = 1420;

    wg_device device = {};
    if (!wg_device_init_from_config_entry(&device, config)) {
        return false;
    }
    if (device.peer_count != 1 || !device.has_private_key || !device.has_dns) {
        return false;
    }

    wg_peer *peer = wg_device_first_peer(&device);
    if (peer == nullptr) {
        return false;
    }

    const wgnx::platform::endpoint endpoint = {
        .family = wgnx::platform::address_family::inet,
        .port = 51820,
        .address = {203, 0, 113, 4},
    };
    wg_peer_set_resolved_endpoint(peer, endpoint, "203.0.113.4:51820");
    if (!peer->has_resolved_endpoint) {
        return false;
    }

    noise_handshake_set_local_index(&peer->handshake, 0x12345678U);
    noise_handshake_set_remote_index(&peer->handshake, 0x90ABCDEFU);
    static_cast<void>(noise_handshake_transition(
        &peer->handshake,
        HandshakeState::InitiationCreated,
        peer->name,
        "self-test create initiation"));
    static_cast<void>(noise_handshake_transition(
        &peer->handshake,
        HandshakeState::ResponseReceived,
        peer->name,
        "self-test receive response"));
    static_cast<void>(noise_handshake_transition(
        &peer->handshake,
        HandshakeState::SessionDerived,
        peer->name,
        "self-test derive session"));

    wg_timers_schedule(&peer->timers, TimerHook::RetransmitHandshake, 2000, peer->name);
    wg_timers_schedule(&peer->timers, TimerHook::Rekey, 4000, peer->name);
    if (!wg_timers_any_pending(peer->timers)) {
        return false;
    }
    wg_timers_cancel(&peer->timers, TimerHook::RetransmitHandshake, peer->name);
    wg_timers_cancel_all(&peer->timers, peer->name);
    if (wg_timers_any_pending(peer->timers)) {
        return false;
    }

    return peer->handshake.state == HandshakeState::SessionDerived &&
           peer->handshake.transition_count == 3;
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

bool RunCoreSelfTest() {
    const bool ok = TestDeviceAndPeerSkeleton();

    if (ok) {
        wgnx::sysmodule::logger::Log("WireGuard core skeleton self-test passed");
    } else {
        wgnx::sysmodule::logger::Log("WireGuard core skeleton self-test failed");
    }

    return ok;
}

} // namespace wgnx::wireguard
