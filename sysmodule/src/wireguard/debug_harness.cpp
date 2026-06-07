#include "wireguard/debug_harness.hpp"

#include "wireguard/data.hpp"
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
    wgnx::PeerConfigEntry secondary_config{};
    wg_device secondary_device{};
    wg_peer peer_copy{};
    wg_peer responder_copy{};
    message_handshake_response response{};
    message_handshake_response tampered_response{};
    message_handshake_cookie cookie{};
    wgnx::platform::static_packet_buffer<HandshakeResponseSize> response_buffer{};
    wgnx::platform::static_packet_buffer<HandshakeResponseSize> tampered_buffer{};
    wgnx::platform::static_packet_buffer<HandshakeCookieSize> cookie_buffer{};
    wgnx::platform::static_packet_buffer<TransportDataHeaderSize + NoiseTagSize> keepalive_buffer{};
    wgnx::platform::static_packet_buffer<256> payload_buffer{};
    wgnx::platform::static_packet_buffer<256> mismatch_buffer{};
    wgnx::platform::static_packet_buffer<256> tampered_payload_buffer{};
    std::uint8_t payload_plaintext[128]{};
    std::uint8_t decrypted_payload[128]{};
};

CoreSelfTestStorage g_core_self_test_storage{};

void ResetCoreSelfTestStorage() {
    g_core_self_test_storage = {};
    wgnx::platform::packet_init(
        &g_core_self_test_storage.response_buffer.packet,
        g_core_self_test_storage.response_buffer.storage.data(),
        g_core_self_test_storage.response_buffer.storage.size());
    wgnx::platform::packet_init(
        &g_core_self_test_storage.tampered_buffer.packet,
        g_core_self_test_storage.tampered_buffer.storage.data(),
        g_core_self_test_storage.tampered_buffer.storage.size());
    wgnx::platform::packet_init(
        &g_core_self_test_storage.cookie_buffer.packet,
        g_core_self_test_storage.cookie_buffer.storage.data(),
        g_core_self_test_storage.cookie_buffer.storage.size());
    wgnx::platform::packet_init(
        &g_core_self_test_storage.keepalive_buffer.packet,
        g_core_self_test_storage.keepalive_buffer.storage.data(),
        g_core_self_test_storage.keepalive_buffer.storage.size());
    wgnx::platform::packet_init(
        &g_core_self_test_storage.payload_buffer.packet,
        g_core_self_test_storage.payload_buffer.storage.data(),
        g_core_self_test_storage.payload_buffer.storage.size());
    wgnx::platform::packet_init(
        &g_core_self_test_storage.mismatch_buffer.packet,
        g_core_self_test_storage.mismatch_buffer.storage.data(),
        g_core_self_test_storage.mismatch_buffer.storage.size());
    wgnx::platform::packet_init(
        &g_core_self_test_storage.tampered_payload_buffer.packet,
        g_core_self_test_storage.tampered_payload_buffer.storage.data(),
        g_core_self_test_storage.tampered_payload_buffer.storage.size());
}

bool ComputeHarnessCookieKey(
    std::uint8_t out_key[32],
    const noise_public_key &remote_static) {
    if (out_key == nullptr || !remote_static.valid) {
        return false;
    }

    static constexpr char CookieKeyLabel[] = "cookie--";
    crypto::blake2s_state state{};
    if (!crypto::blake2s_init(&state, 32, nullptr, 0)) {
        return false;
    }
    crypto::blake2s_update(&state, CookieKeyLabel, sizeof(CookieKeyLabel) - 1);
    crypto::blake2s_update(&state, remote_static.bytes, sizeof(remote_static.bytes));
    return crypto::blake2s_final(&state, out_key, 32);
}

bool BuildHarnessCookieReply(
    message_handshake_cookie *out_cookie,
    const wg_peer &initiator,
    const wg_peer &responder) {
    if (out_cookie == nullptr || !initiator.cookie.has_last_mac1 || !responder.static_identity.static_public.valid) {
        return false;
    }

    static constexpr std::uint8_t CookieValue[CookieValueSize] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };

    std::uint8_t cookie_key[32]{};
    std::uint8_t tag[NoiseTagSize]{};
    if (!ComputeHarnessCookieKey(cookie_key, responder.static_identity.static_public)) {
        return false;
    }

    *out_cookie = {};
    SetMessageType(&out_cookie->type, MessageType::CookieReply);
    out_cookie->receiver_index = initiator.handshake.local_index;
    for (std::size_t i = 0; i < sizeof(out_cookie->nonce); ++i) {
        out_cookie->nonce[i] = static_cast<std::uint8_t>(0x90U + i);
    }
    if (!crypto::xchacha20poly1305_encrypt(
            out_cookie->encrypted_cookie,
            tag,
            CookieValue,
            sizeof(CookieValue),
            initiator.cookie.last_mac1,
            sizeof(initiator.cookie.last_mac1),
            cookie_key,
            out_cookie->nonce)) {
        crypto::secure_clear(cookie_key, sizeof(cookie_key));
        crypto::secure_clear(tag, sizeof(tag));
        return false;
    }

    std::memcpy(out_cookie->encrypted_cookie + CookieValueSize, tag, sizeof(tag));
    crypto::secure_clear(cookie_key, sizeof(cookie_key));
    crypto::secure_clear(tag, sizeof(tag));
    return true;
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
    static constexpr std::uint8_t ZeroMac[NoiseMacSize] = {};

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

    wgnx::PeerConfigEntry &responder_config = g_core_self_test_storage.secondary_config;
    std::snprintf(responder_config.name, sizeof(responder_config.name), "%s", "responder-peer");
    std::snprintf(responder_config.address, sizeof(responder_config.address), "%s", "10.66.66.1/32");
    std::snprintf(responder_config.endpoint, sizeof(responder_config.endpoint), "%s", "0.0.0.0:0");
    std::snprintf(responder_config.private_key, sizeof(responder_config.private_key), "%s", HarnessRemotePrivateKey);
    std::snprintf(responder_config.public_key, sizeof(responder_config.public_key), "%s", HarnessLocalPublicKey);
    std::snprintf(responder_config.preshared_key, sizeof(responder_config.preshared_key), "%s", HarnessPresharedKey);
    std::snprintf(responder_config.allowed_ips, sizeof(responder_config.allowed_ips), "%s", "10.66.66.2/32");

    wg_device &responder_device = g_core_self_test_storage.secondary_device;
    if (!wg_device_init_from_config_entry(&responder_device, responder_config)) {
        return false;
    }
    wg_peer *responder = wg_device_first_peer(&responder_device);
    if (responder == nullptr) {
        return false;
    }

    noise_handshake_set_local_index(&initiator->handshake, 0x01020304U);
    noise_handshake_set_local_index(&responder->handshake, 0xA1A2A3A4U);
    wg_device_register_handshake_index(&initiator_device, initiator->handshake.local_index);
    wg_device_register_handshake_index(&responder_device, responder->handshake.local_index);

    message_handshake_initiation initiation{};
    if (!noise_handshake_create_initiation(&initiation, initiator)) {
        return false;
    }
    if (!noise_handshake_consume_initiation(&initiation, responder)) {
        return false;
    }

    message_handshake_response &response = g_core_self_test_storage.response;
    if (!noise_handshake_create_response(&response, responder)) {
        return false;
    }

    wg_peer &initiator_copy = g_core_self_test_storage.peer_copy;
    initiator_copy = *initiator;
    message_handshake_response &tampered_response = g_core_self_test_storage.tampered_response;
    tampered_response = response;
    tampered_response.encrypted_nothing[0] ^= 0x80U;
    auto &tampered_buffer = g_core_self_test_storage.tampered_buffer;
    if (SerializeHandshakeResponse(&tampered_buffer.packet, tampered_response) != ParseError::None) {
        return false;
    }
    if (noise_handshake_consume_incoming_packet(&tampered_buffer.packet, &initiator_device, &initiator_copy) != HandshakePacketOutcome::Invalid) {
        return false;
    }

    auto &response_buffer = g_core_self_test_storage.response_buffer;
    if (SerializeHandshakeResponse(&response_buffer.packet, response) != ParseError::None) {
        return false;
    }
    if (noise_handshake_consume_incoming_packet(&response_buffer.packet, &initiator_device, initiator) != HandshakePacketOutcome::ResponseConsumed) {
        return false;
    }

    if (!noise_handshake_begin_session(&initiator_device, initiator) ||
        !noise_handshake_begin_session(&responder_device, responder)) {
        return false;
    }

    if (noise_handshake_consume_incoming_packet(&response_buffer.packet, &initiator_device, initiator) != HandshakePacketOutcome::Invalid) {
        return false;
    }

    message_handshake_cookie &cookie = g_core_self_test_storage.cookie;
    if (!BuildHarnessCookieReply(&cookie, *initiator, *responder)) {
        return false;
    }
    auto &cookie_buffer = g_core_self_test_storage.cookie_buffer;
    if (SerializeHandshakeCookie(&cookie_buffer.packet, cookie) != ParseError::None) {
        return false;
    }
    if (noise_handshake_consume_incoming_packet(&cookie_buffer.packet, &initiator_device, initiator) != HandshakePacketOutcome::CookieReplyConsumed) {
        return false;
    }

    auto &keepalive_buffer = g_core_self_test_storage.keepalive_buffer;
    if (!noise_create_keepalive_packet(&keepalive_buffer.packet, initiator->current_keypair)) {
        return false;
    }

    TransportDataDecryptResult keepalive_result{};
    const TransportDataError keepalive_error = noise_consume_transport_data_packet(
        &keepalive_buffer.packet,
        &responder->current_keypair,
        nullptr,
        0,
        &keepalive_result);
    if (keepalive_error != TransportDataError::None) {
        return false;
    }
    if (keepalive_buffer.packet.len != (TransportDataHeaderSize + NoiseMacSize) ||
        keepalive_result.header.receiver_index != initiator->current_keypair.remote_index ||
        keepalive_result.header.counter != initiator->current_keypair.send_counter ||
        keepalive_result.payload_size != 0) {
        return false;
    }
    ++initiator->current_keypair.send_counter;

    for (std::size_t i = 0; i < sizeof(g_core_self_test_storage.payload_plaintext); ++i) {
        g_core_self_test_storage.payload_plaintext[i] = static_cast<std::uint8_t>(0x30U + i);
    }

    auto &payload_buffer = g_core_self_test_storage.payload_buffer;
    if (noise_create_transport_data_packet(
            &payload_buffer.packet,
            initiator->current_keypair,
            g_core_self_test_storage.payload_plaintext,
            sizeof(g_core_self_test_storage.payload_plaintext)) != TransportDataError::None) {
        return false;
    }

    g_core_self_test_storage.responder_copy = *responder;

    TransportDataDecryptResult payload_result{};
    const TransportDataError payload_error = noise_consume_transport_data_packet(
        &payload_buffer.packet,
        &responder->current_keypair,
        g_core_self_test_storage.decrypted_payload,
        sizeof(g_core_self_test_storage.decrypted_payload),
        &payload_result);
    if (payload_error != TransportDataError::None) {
        return false;
    }
    if (payload_result.header.receiver_index != initiator->current_keypair.remote_index ||
        payload_result.header.counter != initiator->current_keypair.send_counter ||
        payload_result.payload_size != sizeof(g_core_self_test_storage.payload_plaintext) ||
        std::memcmp(
            g_core_self_test_storage.payload_plaintext,
            g_core_self_test_storage.decrypted_payload,
            sizeof(g_core_self_test_storage.payload_plaintext)) != 0) {
        return false;
    }
    ++initiator->current_keypair.send_counter;

    const TransportDataError replay_error = noise_consume_transport_data_packet(
        &payload_buffer.packet,
        &responder->current_keypair,
        g_core_self_test_storage.decrypted_payload,
        sizeof(g_core_self_test_storage.decrypted_payload),
        nullptr);
    if (replay_error != TransportDataError::ReplayRejected) {
        return false;
    }

    auto &mismatch_buffer = g_core_self_test_storage.mismatch_buffer;
    std::memcpy(
        mismatch_buffer.packet.data,
        payload_buffer.packet.data,
        payload_buffer.packet.len);
    mismatch_buffer.packet.len = payload_buffer.packet.len;
    StoreLe32(
        mismatch_buffer.packet.data + sizeof(std::uint32_t),
        g_core_self_test_storage.responder_copy.current_keypair.local_index ^ 0x00FF00FFU);
    const TransportDataError mismatch_error = noise_consume_transport_data_packet(
        &mismatch_buffer.packet,
        &g_core_self_test_storage.responder_copy.current_keypair,
        g_core_self_test_storage.decrypted_payload,
        sizeof(g_core_self_test_storage.decrypted_payload),
        nullptr);
    if (mismatch_error != TransportDataError::ReceiverIndexMismatch) {
        return false;
    }

    auto &tampered_payload_buffer = g_core_self_test_storage.tampered_payload_buffer;
    std::memcpy(
        tampered_payload_buffer.packet.data,
        payload_buffer.packet.data,
        payload_buffer.packet.len);
    tampered_payload_buffer.packet.len = payload_buffer.packet.len;
    tampered_payload_buffer.packet.data[tampered_payload_buffer.packet.len - 1] ^= 0x80U;
    const TransportDataError tampered_payload_error = noise_consume_transport_data_packet(
        &tampered_payload_buffer.packet,
        &g_core_self_test_storage.responder_copy.current_keypair,
        g_core_self_test_storage.decrypted_payload,
        sizeof(g_core_self_test_storage.decrypted_payload),
        nullptr);
    if (tampered_payload_error != TransportDataError::AuthenticationFailed) {
        return false;
    }

    if (noise_create_transport_data_packet(
            &payload_buffer.packet,
            initiator->current_keypair,
            g_core_self_test_storage.payload_plaintext,
            8) != TransportDataError::None) {
        return false;
    }

    IncomingTransportDataResult incoming_result{};
    const TransportDataError incoming_error = noise_consume_incoming_transport_data_packet(
        &payload_buffer.packet,
        &responder_device,
        &g_core_self_test_storage.responder_copy,
        g_core_self_test_storage.decrypted_payload,
        sizeof(g_core_self_test_storage.decrypted_payload),
        &incoming_result);
    if (incoming_error != TransportDataError::None) {
        return false;
    }
    if (incoming_result.slot != wg_index_slot::CurrentKeypair ||
        incoming_result.decrypt.header.receiver_index != initiator->current_keypair.remote_index ||
        incoming_result.decrypt.header.counter != initiator->current_keypair.send_counter ||
        incoming_result.decrypt.payload_size != 8 ||
        std::memcmp(
            g_core_self_test_storage.payload_plaintext,
            g_core_self_test_storage.decrypted_payload,
            incoming_result.decrypt.payload_size) != 0) {
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
           initiator->cookie.valid &&
           initiator->has_last_initiation &&
           responder->current_keypair.has_receive_counter &&
           responder->current_keypair.receive_counter == payload_result.header.counter &&
           std::memcmp(
               initiator->current_keypair.sending_key.bytes,
               responder->current_keypair.receiving_key.bytes,
               sizeof(initiator->current_keypair.sending_key.bytes)) == 0 &&
           std::memcmp(
               initiator->current_keypair.receiving_key.bytes,
               responder->current_keypair.sending_key.bytes,
               sizeof(initiator->current_keypair.receiving_key.bytes)) == 0 &&
           std::memcmp(
               initiator->last_initiation.macs.mac2,
               ZeroMac,
               NoiseMacSize) != 0;
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
