#include "wireguard/debug_harness.hpp"

#include "wireguard/device.hpp"
#include "wireguard/dispatch.hpp"
#include "wireguard/endian.hpp"
#include "wireguard/handshake.hpp"
#include "logger.hpp"
#include "wireguard/crypto/primitives.hpp"
#include "wireguard/messages.hpp"
#include "wireguard/session.hpp"
#include "wireguard/timers.hpp"

#include <cstdio>
#include <cstring>

namespace wgnx::wireguard {

namespace {

/*
 * Harness key fixture notes:
 *
 * These constants are just deterministic test fixtures. The current pair was
 * originally seeded from fixed 32-byte values during bring-up, and the public
 * keys were then derived from the private keys via X25519 so the harness could
 * verify real WireGuard key parsing and handshake behavior without any device-
 * side dependency on external tooling.
 *
 * To replace them manually with fresh values, the simplest path is the normal
 * WireGuard tooling:
 *
 *   wg genkey | tee local.key | wg pubkey > local.pub
 *   wg genkey | tee remote.key | wg pubkey > remote.pub
 *   wg genpsk > psk.key
 *
 * Then copy:
 * - the contents of `local.key` into `HarnessLocalPrivateKey`
 * - the contents of `local.pub` into `HarnessLocalPublicKey`
 * - the contents of `remote.key` into `HarnessRemotePrivateKey`
 * - the contents of `remote.pub` into `HarnessRemotePublicKey`
 * - the contents of `psk.key` into `HarnessPresharedKey`
 *
 * If `wg` tooling is unavailable, any method that produces valid WireGuard
 * base64-encoded X25519 private/public keypairs and a 32-byte preshared key is
 * sufficient. `wg` is preferred because it guarantees the exact expected
 * encoding and clamping behavior.
 */
constexpr char HarnessLocalPrivateKey[] = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
constexpr char HarnessRemotePrivateKey[] = "ZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4Q=";
constexpr char HarnessRemotePublicKey[] = "VxR2nRFr92Q2rnS8eT0sMK0ZA8WaxSc4BcfiaYtBDDY=";
constexpr char HarnessPresharedKey[] = "ycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+g=";
constexpr char HarnessLocalPublicKey[] = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=";

struct DispatchTestContext {
    std::uint32_t initiation_count{0};
    std::uint32_t response_count{0};
    std::uint32_t cookie_count{0};
    std::uint32_t transport_count{0};
    std::size_t last_payload_size{0};
};

struct CoreSelfTestStorage {
    wgnx::PeerConfigEntry config{};
    wg_device device{};
};

constinit CoreSelfTestStorage g_core_self_test_storage{};

void ResetCoreSelfTestStorage() {
    g_core_self_test_storage = {};
}

void CountHandshakeInitiation(void *context, const message_handshake_initiation &) {
    static_cast<DispatchTestContext *>(context)->initiation_count++;
}

void CountHandshakeResponse(void *context, const message_handshake_response &) {
    static_cast<DispatchTestContext *>(context)->response_count++;
}

void CountCookieReply(void *context, const message_handshake_cookie &) {
    static_cast<DispatchTestContext *>(context)->cookie_count++;
}

void CountTransportData(
    void *context,
    const message_transport_data &,
    const std::uint8_t *,
    std::size_t payload_size) {
    auto *dispatch_context = static_cast<DispatchTestContext *>(context);
    dispatch_context->transport_count++;
    dispatch_context->last_payload_size = payload_size;
}

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
    SetMessageType(&message.type, MessageType::HandshakeInitiation);
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
    SetMessageType(&message.type, MessageType::HandshakeResponse);
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
    SetMessageType(&message.type, MessageType::CookieReply);
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
    SetMessageType(&message.type, MessageType::TransportData);
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
    StoreLe32(buffer.storage.data(), 99);
    buffer.packet.len = sizeof(std::uint32_t);

    MessageType type = MessageType::Invalid;
    const ParseResult result = InspectMessageType(&buffer.packet, &type);
    return !result.success && result.error == ParseError::UnknownType;
}

bool TestMalformedLengthRejected() {
    message_handshake_initiation message = {};
    SetMessageType(&message.type, MessageType::HandshakeInitiation);

    wgnx::platform::static_packet_buffer<256> buffer;
    if (SerializeHandshakeInitiation(&buffer.packet, message) != ParseError::None) {
        return false;
    }
    --buffer.packet.len;

    message_handshake_initiation parsed = {};
    const ParseResult result = ParseHandshakeInitiation(&buffer.packet, &parsed);
    return !result.success && result.error == ParseError::InvalidLength;
}

bool TestPacketDispatch() {
    message_transport_data message = {};
    SetMessageType(&message.type, MessageType::TransportData);
    message.receiver_index = 0x01020304U;
    message.counter = 0xA0A1A2A3A4A5A6A7ULL;

    wgnx::platform::static_packet_buffer<64> buffer;
    if (SerializeTransportDataHeader(&buffer.packet, message) != ParseError::None) {
        return false;
    }

    const std::uint8_t payload[3] = {0xAA, 0xBB, 0xCC};
    std::memcpy(buffer.storage.data() + buffer.packet.len, payload, sizeof(payload));
    buffer.packet.len += sizeof(payload);

    DispatchTestContext context = {};
    const PacketDispatchHandlers handlers = {
        .context = &context,
        .handshake_initiation = CountHandshakeInitiation,
        .handshake_response = CountHandshakeResponse,
        .cookie_reply = CountCookieReply,
        .transport_data = CountTransportData,
    };
    const ParseResult result = DispatchPacket(&buffer.packet, handlers);
    return result.success &&
           context.transport_count == 1 &&
           context.last_payload_size == sizeof(payload) &&
           context.initiation_count == 0 &&
           context.response_count == 0 &&
           context.cookie_count == 0;
}

bool TestTransportFixedVector() {
    message_transport_data message = {};
    SetMessageType(&message.type, MessageType::TransportData);
    message.receiver_index = 0xCAFEBABEU;
    message.counter = 0x0102030405060708ULL;

    wgnx::platform::static_packet_buffer<32> buffer;
    if (SerializeTransportDataHeader(&buffer.packet, message) != ParseError::None) {
        return false;
    }

    const std::uint8_t expected[TransportDataHeaderSize] = {
        0x04, 0x00, 0x00, 0x00,
        0xBE, 0xBA, 0xFE, 0xCA,
        0x08, 0x07, 0x06, 0x05,
        0x04, 0x03, 0x02, 0x01,
    };
    if (buffer.packet.len != sizeof(expected)) {
        return false;
    }
    if (std::memcmp(buffer.storage.data(), expected, sizeof(expected)) != 0) {
        return false;
    }

    message_transport_data parsed = {};
    const ParseResult result = ParseTransportDataHeader(&buffer.packet, &parsed);
    return result.success &&
           GetMessageType(parsed.type) == MessageType::TransportData &&
           parsed.receiver_index == message.receiver_index &&
           parsed.counter == message.counter;
}

bool TestDeviceAndPeerSkeleton() {
    ResetCoreSelfTestStorage();
    wgnx::PeerConfigEntry &config = g_core_self_test_storage.config;
    std::snprintf(config.name, sizeof(config.name), "%s", "harness-peer");
    std::snprintf(config.address, sizeof(config.address), "%s", "10.66.66.2/32");
    std::snprintf(config.endpoint, sizeof(config.endpoint), "%s", "vpn.example.test:51820");
    std::snprintf(config.private_key, sizeof(config.private_key), "%s", HarnessLocalPrivateKey);
    std::snprintf(config.public_key, sizeof(config.public_key), "%s", HarnessRemotePublicKey);
    std::snprintf(config.preshared_key, sizeof(config.preshared_key), "%s", HarnessPresharedKey);
    std::snprintf(config.allowed_ips, sizeof(config.allowed_ips), "%s", "0.0.0.0/0, ::/0");
    std::snprintf(config.dns, sizeof(config.dns), "%s", "1.1.1.1");
    config.listen_port = 51820;
    config.persistent_keepalive = 25;
    config.mtu = 1420;

    wg_device &device = g_core_self_test_storage.device;
    if (!wg_device_init_from_config_entry(&device, config)) {
        return false;
    }
    if (device.peer_count != 1 || !device.has_private_key || !device.has_dns) {
        return false;
    }
    const std::uint32_t first_index = wg_device_allocate_index(&device);
    const std::uint32_t second_index = wg_device_allocate_index(&device);
    if (first_index == 0 || second_index != first_index + 1) {
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
    noise_static_identity_reset(&peer->static_identity);
    noise_handshake_material_reset(&peer->handshake_material);
    if (peer->static_identity.static_private.valid ||
        peer->handshake_material.chaining_key.valid) {
        return false;
    }

    noise_handshake_set_local_index(&peer->handshake, first_index);
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

bool TestStaticIdentityParsing() {
    noise_static_identity identity{};
    if (!noise_static_identity_init(
            &identity,
            HarnessLocalPrivateKey,
            HarnessRemotePublicKey,
            HarnessPresharedKey)) {
        return false;
    }

    noise_public_key expected_local_public{};
    if (!noise_parse_public_key(&expected_local_public, HarnessLocalPublicKey)) {
        return false;
    }

    const bool ok = identity.static_private.valid &&
                    identity.static_public.valid &&
                    identity.remote_static.valid &&
                    identity.preshared_key.valid &&
                    std::memcmp(
                        identity.static_public.bytes,
                        expected_local_public.bytes,
                        sizeof(identity.static_public.bytes)) == 0;
    noise_static_identity_reset(&identity);
    return ok;
}

bool TestHandshakeInitiationCreation() {
    ResetCoreSelfTestStorage();
    wgnx::PeerConfigEntry &config = g_core_self_test_storage.config;
    std::snprintf(config.name, sizeof(config.name), "%s", "handshake-peer");
    std::snprintf(config.address, sizeof(config.address), "%s", "10.66.66.2/32");
    std::snprintf(config.endpoint, sizeof(config.endpoint), "%s", "vpn.example.test:51820");
    std::snprintf(config.private_key, sizeof(config.private_key), "%s", HarnessLocalPrivateKey);
    std::snprintf(config.public_key, sizeof(config.public_key), "%s", HarnessRemotePublicKey);
    std::snprintf(config.preshared_key, sizeof(config.preshared_key), "%s", HarnessPresharedKey);
    std::snprintf(config.allowed_ips, sizeof(config.allowed_ips), "%s", "0.0.0.0/0, ::/0");

    wg_device &device = g_core_self_test_storage.device;
    if (!wg_device_init_from_config_entry(&device, config)) {
        return false;
    }

    wg_peer *peer = wg_device_first_peer(&device);
    if (peer == nullptr) {
        return false;
    }

    noise_handshake_set_local_index(&peer->handshake, 0x01020304U);
    if (!noise_handshake_create_initiation(&peer->last_initiation, peer)) {
        return false;
    }

    wgnx::platform::static_packet_buffer<HandshakeInitiationSize> buffer;
    if (SerializeHandshakeInitiation(&buffer.packet, peer->last_initiation) != ParseError::None) {
        return false;
    }

    message_handshake_initiation parsed{};
    const ParseResult parsed_result = ParseHandshakeInitiation(&buffer.packet, &parsed);
    if (!parsed_result.success) {
        return false;
    }

    std::uint8_t zero_block[NoisePublicKeySize]{};
    std::uint8_t zero_mac[NoiseMacSize]{};
    return peer->has_last_initiation &&
           peer->handshake.state == HandshakeState::InitiationCreated &&
           GetMessageType(parsed.type) == MessageType::HandshakeInitiation &&
           parsed.sender_index == 0x01020304U &&
           std::memcmp(parsed.unencrypted_ephemeral, zero_block, sizeof(parsed.unencrypted_ephemeral)) != 0 &&
           std::memcmp(parsed.encrypted_static, zero_block, sizeof(parsed.unencrypted_ephemeral)) != 0 &&
           std::memcmp(parsed.macs.mac1, zero_mac, sizeof(parsed.macs.mac1)) != 0 &&
           std::memcmp(parsed.macs.mac2, zero_mac, sizeof(parsed.macs.mac2)) == 0;
}

bool TestHandshakeResponseAndSessionDerivation() {
    ResetCoreSelfTestStorage();
    wgnx::PeerConfigEntry &initiator_config = g_core_self_test_storage.config;
    std::snprintf(initiator_config.name, sizeof(initiator_config.name), "%s", "initiator-peer");
    std::snprintf(initiator_config.address, sizeof(initiator_config.address), "%s", "10.66.66.2/32");
    std::snprintf(initiator_config.endpoint, sizeof(initiator_config.endpoint), "%s", "vpn.example.test:51820");
    std::snprintf(initiator_config.private_key, sizeof(initiator_config.private_key), "%s", HarnessLocalPrivateKey);
    std::snprintf(initiator_config.public_key, sizeof(initiator_config.public_key), "%s", HarnessRemotePublicKey);
    std::snprintf(initiator_config.preshared_key, sizeof(initiator_config.preshared_key), "%s", HarnessPresharedKey);
    std::snprintf(initiator_config.allowed_ips, sizeof(initiator_config.allowed_ips), "%s", "0.0.0.0/0, ::/0");

    wg_device &initiator_device = g_core_self_test_storage.device;
    if (!wg_device_init_from_config_entry(&initiator_device, initiator_config)) {
        return false;
    }
    wg_peer *initiator = wg_device_first_peer(&initiator_device);
    if (initiator == nullptr) {
        return false;
    }

    wgnx::PeerConfigEntry responder_config{};
    std::snprintf(responder_config.name, sizeof(responder_config.name), "%s", "responder-peer");
    std::snprintf(responder_config.address, sizeof(responder_config.address), "%s", "10.66.66.1/32");
    std::snprintf(responder_config.endpoint, sizeof(responder_config.endpoint), "%s", "0.0.0.0:0");
    std::snprintf(responder_config.private_key, sizeof(responder_config.private_key), "%s", HarnessRemotePrivateKey);
    std::snprintf(responder_config.public_key, sizeof(responder_config.public_key), "%s", HarnessLocalPublicKey);
    std::snprintf(responder_config.preshared_key, sizeof(responder_config.preshared_key), "%s", HarnessPresharedKey);
    std::snprintf(responder_config.allowed_ips, sizeof(responder_config.allowed_ips), "%s", "10.66.66.2/32");

    wg_device responder_device{};
    if (!wg_device_init_from_config_entry(&responder_device, responder_config)) {
        return false;
    }
    wg_peer *responder = wg_device_first_peer(&responder_device);
    if (responder == nullptr) {
        return false;
    }

    noise_handshake_set_local_index(&initiator->handshake, 0x01020304U);
    noise_handshake_set_local_index(&responder->handshake, 0xA1A2A3A4U);

    message_handshake_initiation initiation{};
    if (!noise_handshake_create_initiation(&initiation, initiator)) {
        return false;
    }
    if (!noise_handshake_consume_initiation(&initiation, responder)) {
        return false;
    }

    message_handshake_response response{};
    if (!noise_handshake_create_response(&response, responder)) {
        return false;
    }

    wg_peer initiator_copy = *initiator;
    const message_handshake_response tampered_response = [&response] {
        message_handshake_response tampered = response;
        tampered.encrypted_nothing[0] ^= 0x80U;
        return tampered;
    }();
    if (noise_handshake_consume_response(&tampered_response, &initiator_copy)) {
        return false;
    }
    if (!noise_handshake_consume_response(&response, initiator)) {
        return false;
    }

    if (!noise_handshake_begin_session(initiator) || !noise_handshake_begin_session(responder)) {
        return false;
    }

    return initiator->current_keypair.valid &&
           responder->current_keypair.valid &&
           initiator->handshake.state == HandshakeState::SessionDerived &&
           responder->handshake.state == HandshakeState::SessionDerived &&
           initiator->current_keypair.local_index == 0x01020304U &&
           initiator->current_keypair.remote_index == 0xA1A2A3A4U &&
           responder->current_keypair.local_index == 0xA1A2A3A4U &&
           responder->current_keypair.remote_index == 0x01020304U &&
           initiator->current_keypair.sending_key.valid &&
           initiator->current_keypair.receiving_key.valid &&
           responder->current_keypair.sending_key.valid &&
           responder->current_keypair.receiving_key.valid &&
           std::memcmp(
               initiator->current_keypair.sending_key.bytes,
               responder->current_keypair.receiving_key.bytes,
               sizeof(initiator->current_keypair.sending_key.bytes)) == 0 &&
           std::memcmp(
               initiator->current_keypair.receiving_key.bytes,
               responder->current_keypair.sending_key.bytes,
               sizeof(initiator->current_keypair.receiving_key.bytes)) == 0;
}

} // namespace

bool RunMessageSelfTest() {
    const bool ok =
        TestHandshakeInitiation() &&
        TestHandshakeResponse() &&
        TestHandshakeCookie() &&
        TestTransportDataHeader() &&
        TestUnknownTypeRejected() &&
        TestMalformedLengthRejected() &&
        TestPacketDispatch() &&
        TestTransportFixedVector();

    if (ok) {
        wgnx::sysmodule::logger::Log("WireGuard message self-test passed");
    } else {
        wgnx::sysmodule::logger::Log("WireGuard message self-test failed");
    }

    return ok;
}

bool RunPrimitiveSelfTest() {
    const bool ok = crypto::RunPrimitiveSelfTest();

    if (ok) {
        wgnx::sysmodule::logger::Log("WireGuard primitive self-test passed");
    } else {
        wgnx::sysmodule::logger::Log("WireGuard primitive self-test failed");
    }

    return ok;
}

bool RunCoreSelfTest() {
    const bool ok =
        TestDeviceAndPeerSkeleton() &&
        TestStaticIdentityParsing() &&
        TestHandshakeInitiationCreation() &&
        TestHandshakeResponseAndSessionDerivation();
    ResetCoreSelfTestStorage();

    if (ok) {
        wgnx::sysmodule::logger::Log("WireGuard core skeleton self-test passed");
    } else {
        wgnx::sysmodule::logger::Log("WireGuard core skeleton self-test failed");
    }

    return ok;
}

} // namespace wgnx::wireguard
