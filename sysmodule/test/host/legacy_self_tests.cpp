#include "legacy_self_tests.hpp"

#include "wireguard/data.hpp"
#include "wireguard/debug_probe.hpp"
#include "wireguard/device.hpp"
#include "wireguard/dispatch.hpp"
#include "wireguard/endian.hpp"
#include "wireguard/handshake.hpp"
#include "wireguard/inner_packet.hpp"
#include "logger.hpp"
#include "wireguard/crypto/primitives.hpp"
#include "wireguard/messages.hpp"
#include "wireguard/session.hpp"
#include "wireguard/timers.hpp"
#include "wgnx/platform/packet.hpp"

#include <cstdio>
#include <algorithm>
#include <array>
#include <cstring>
#include <span>

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

void SetMessageType(std::uint32_t *field, MessageType type) {
    if (field != nullptr) {
        ::wgnx::wireguard::SetMessageType(*field, type);
    }
}

template<std::size_t PacketSize, typename Message>
ParseError SerializeLegacyPacket(
    wgnx::platform::packet_buffer *packet,
    const Message &message,
    ParseError (*serialize)(std::span<std::uint8_t>, const Message &)) {
    if (packet == nullptr || packet->capacity < PacketSize) {
        return ParseError::InsufficientCapacity;
    }
    const ParseError error = serialize(packet->storage().first(PacketSize), message);
    if (error == ParseError::None) {
        packet->len = PacketSize;
    }
    return error;
}

ParseError SerializeHandshakeInitiation(
    wgnx::platform::packet_buffer *packet,
    const message_handshake_initiation &message) {
    return SerializeLegacyPacket<HandshakeInitiationSize>(
        packet,
        message,
        ::wgnx::wireguard::SerializeHandshakeInitiation);
}

ParseError SerializeHandshakeResponse(
    wgnx::platform::packet_buffer *packet,
    const message_handshake_response &message) {
    return SerializeLegacyPacket<HandshakeResponseSize>(
        packet,
        message,
        ::wgnx::wireguard::SerializeHandshakeResponse);
}

ParseError SerializeHandshakeCookie(
    wgnx::platform::packet_buffer *packet,
    const message_handshake_cookie &message) {
    return SerializeLegacyPacket<HandshakeCookieSize>(
        packet,
        message,
        ::wgnx::wireguard::SerializeHandshakeCookie);
}

ParseError SerializeTransportDataHeader(
    wgnx::platform::packet_buffer *packet,
    const message_transport_data &message) {
    return SerializeLegacyPacket<TransportDataHeaderSize>(
        packet,
        message,
        ::wgnx::wireguard::SerializeTransportDataHeader);
}

template<typename Message>
ParseResult ParseLegacyPacket(
    const wgnx::platform::packet_buffer *packet,
    Message *message,
    ParseResult (*parse)(std::span<const std::uint8_t>, Message &)) {
    if (packet == nullptr || message == nullptr) {
        return {.success = false, .error = ParseError::InvalidArgument};
    }
    return parse(packet->bytes(), *message);
}

ParseResult ParseHandshakeInitiation(
    const wgnx::platform::packet_buffer *packet,
    message_handshake_initiation *message) {
    return ParseLegacyPacket(packet, message, ::wgnx::wireguard::ParseHandshakeInitiation);
}

ParseResult ParseHandshakeResponse(
    const wgnx::platform::packet_buffer *packet,
    message_handshake_response *message) {
    return ParseLegacyPacket(packet, message, ::wgnx::wireguard::ParseHandshakeResponse);
}

ParseResult ParseHandshakeCookie(
    const wgnx::platform::packet_buffer *packet,
    message_handshake_cookie *message) {
    return ParseLegacyPacket(packet, message, ::wgnx::wireguard::ParseHandshakeCookie);
}

ParseResult ParseTransportDataHeader(
    const wgnx::platform::packet_buffer *packet,
    message_transport_data *message) {
    return ParseLegacyPacket(packet, message, ::wgnx::wireguard::ParseTransportDataHeader);
}

ParseResult InspectMessageType(
    const wgnx::platform::packet_buffer *packet,
    MessageType *type) {
    if (packet == nullptr || type == nullptr) {
        return {.success = false, .error = ParseError::InvalidArgument};
    }
    const ParseResult result = ::wgnx::wireguard::InspectMessageType(packet->bytes());
    *type = result.type;
    return result;
}

ParseResult DispatchPacket(
    const wgnx::platform::packet_buffer *packet,
    const PacketDispatchHandlers &handlers) {
    return packet == nullptr
        ? ParseResult{.success = false, .error = ParseError::InvalidArgument}
        : ::wgnx::wireguard::DispatchPacket(packet->bytes(), handlers);
}

TransportDataError noise_create_transport_data_packet(
    wgnx::platform::packet_buffer *packet,
    noise_keypair &keypair,
    std::span<const std::uint8_t> payload) {
    if (packet == nullptr) {
        return TransportDataError::InvalidArgument;
    }
    const TransportDataCreateResult result =
        ::wgnx::wireguard::noise_create_transport_data_packet(
            packet->storage(),
            keypair,
            payload);
    if (result.error == TransportDataError::None) {
        packet->len = result.packet_size;
    }
    return result.error;
}

bool noise_create_keepalive_packet(
    wgnx::platform::packet_buffer *packet,
    noise_keypair &keypair) {
    if (packet == nullptr) {
        return false;
    }
    const TransportDataCreateResult result =
        ::wgnx::wireguard::noise_create_keepalive_packet(packet->storage(), keypair);
    if (result.error == TransportDataError::None) {
        packet->len = result.packet_size;
    }
    return result.error == TransportDataError::None;
}

TransportDataError noise_consume_transport_data_packet(
    const wgnx::platform::packet_buffer *packet,
    noise_keypair *keypair,
    std::span<std::uint8_t> output,
    TransportDataDecryptResult *result) {
    if (packet == nullptr || keypair == nullptr) {
        return TransportDataError::InvalidArgument;
    }
    TransportDataDecryptResult ignored{};
    return ::wgnx::wireguard::noise_consume_transport_data_packet(
        packet->bytes(),
        *keypair,
        output,
        result != nullptr ? *result : ignored);
}

TransportDataError noise_consume_incoming_transport_data_packet(
    const wgnx::platform::packet_buffer *packet,
    wg_device *device,
    wg_peer *peer,
    std::span<std::uint8_t> output,
    IncomingTransportDataResult *result) {
    if (packet == nullptr || device == nullptr || peer == nullptr) {
        return TransportDataError::InvalidArgument;
    }
    IncomingTransportDataResult ignored{};
    return ::wgnx::wireguard::noise_consume_incoming_transport_data_packet(
        packet->bytes(),
        *device,
        *peer,
        output,
        result != nullptr ? *result : ignored);
}

HandshakePacketOutcome noise_handshake_consume_incoming_packet(
    const wgnx::platform::packet_buffer *packet,
    const wg_device *device,
    wg_peer *peer) {
    if (packet == nullptr) {
        return HandshakePacketOutcome::Invalid;
    }
    return ::wgnx::wireguard::noise_handshake_consume_incoming_packet(
        packet->bytes(),
        device,
        peer);
}

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
    crypto::blake2s_update(&state, remote_static.bytes.data(), remote_static.bytes.size());
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
            out_cookie->encrypted_cookie.data(),
            tag,
            CookieValue,
            sizeof(CookieValue),
            initiator.cookie.last_mac1.data(),
            initiator.cookie.last_mac1.size(),
            cookie_key,
            out_cookie->nonce.data())) {
        crypto::secure_clear(cookie_key, sizeof(cookie_key));
        crypto::secure_clear(tag, sizeof(tag));
        return false;
    }

    std::memcpy(out_cookie->encrypted_cookie.data() + CookieValueSize, tag, sizeof(tag));
    crypto::secure_clear(cookie_key, sizeof(cookie_key));
    crypto::secure_clear(tag, sizeof(tag));
    return true;
}

void StoreHarnessBigEndian16(std::uint8_t *dst, std::uint16_t value) {
    if (dst == nullptr) {
        return;
    }

    dst[0] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
    dst[1] = static_cast<std::uint8_t>(value & 0xFFu);
}

std::uint16_t ComputeHarnessInternetChecksum(const std::uint8_t *data, std::size_t size) {
    std::uint32_t sum = 0;
    std::size_t index = 0;
    while ((index + 1) < size) {
        sum += (static_cast<std::uint32_t>(data[index]) << 8) |
               static_cast<std::uint32_t>(data[index + 1]);
        index += 2;
    }

    if (index < size) {
        sum += static_cast<std::uint32_t>(data[index]) << 8;
    }

    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    return static_cast<std::uint16_t>(~sum & 0xFFFFu);
}

bool BuildHarnessDebugProbeReply(
    std::array<std::uint8_t, DebugProbePacketSize> *out_reply,
    wgnx::DebugTriggerAction action,
    std::uint32_t activation_generation,
    std::size_t peer_index) {
    if (out_reply == nullptr) {
        return false;
    }

    *out_reply = {};
    const std::size_t request_size = BuildDebugIcmpEchoRequest(
        *out_reply,
        "10.13.13.2/32",
        action,
        activation_generation,
        peer_index,
        0x11223344U);
    if (request_size != DebugProbePacketSize) {
        return false;
    }

    std::swap((*out_reply)[12], (*out_reply)[16]);
    std::swap((*out_reply)[13], (*out_reply)[17]);
    std::swap((*out_reply)[14], (*out_reply)[18]);
    std::swap((*out_reply)[15], (*out_reply)[19]);
    (*out_reply)[10] = 0;
    (*out_reply)[11] = 0;
    StoreHarnessBigEndian16(
        out_reply->data() + 10,
        ComputeHarnessInternetChecksum(out_reply->data(), DebugProbeIpv4HeaderSize));

    std::uint8_t *icmp = out_reply->data() + DebugProbeIpv4HeaderSize;
    icmp[0] = 0;
    icmp[2] = 0;
    icmp[3] = 0;
    StoreHarnessBigEndian16(
        icmp + 2,
        ComputeHarnessInternetChecksum(icmp, DebugProbeIcmpHeaderSize + DebugProbeIcmpPayloadSize));
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
    std::span<const std::uint8_t> payload) {
    auto *dispatch_context = static_cast<DispatchTestContext *>(context);
    dispatch_context->transport_count++;
    dispatch_context->last_payload_size = payload.size();
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

bool TestInnerIpv4PacketBoundary() {
    std::array<std::uint8_t, 20> packet = {
        0x45, 0x00, 0x00, 0x14,
        0x12, 0x34, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        10, 13, 13, 2,
        10, 13, 13, 1,
    };
    StoreHarnessBigEndian16(
        packet.data() + 10,
        ComputeHarnessInternetChecksum(packet.data(), packet.size()));
    if (ValidateInnerIpv4Packet(packet) != InnerIpv4ValidationError::None) {
        return false;
    }

    auto malformed = packet;
    malformed[0] = 0x65;
    if (ValidateInnerIpv4Packet(malformed) != InnerIpv4ValidationError::InvalidVersion) {
        return false;
    }
    malformed = packet;
    malformed[3] = 0x15;
    if (ValidateInnerIpv4Packet(malformed) != InnerIpv4ValidationError::LengthMismatch) {
        return false;
    }
    malformed = packet;
    malformed[8] ^= 0x01U;
    if (ValidateInnerIpv4Packet(malformed) != InnerIpv4ValidationError::InvalidHeaderChecksum) {
        return false;
    }

    std::size_t packet_size = 0;
    if (ValidatePaddedInnerIpv4Packet(packet, std::addressof(packet_size)) !=
            InnerIpv4ValidationError::None ||
        packet_size != packet.size()) {
        return false;
    }

    std::array<std::uint8_t, 32> padded{};
    std::memcpy(padded.data(), packet.data(), packet.size());
    if (ValidatePaddedInnerIpv4Packet(padded, std::addressof(packet_size)) !=
            InnerIpv4ValidationError::None ||
        packet_size != packet.size()) {
        return false;
    }
    padded.back() = 1;
    if (ValidatePaddedInnerIpv4Packet(padded, std::addressof(packet_size)) !=
        InnerIpv4ValidationError::InvalidPadding) {
        return false;
    }

    std::array<std::uint8_t, 36> excessive_padding{};
    std::memcpy(excessive_padding.data(), packet.data(), packet.size());
    if (ValidatePaddedInnerIpv4Packet(excessive_padding, std::addressof(packet_size)) !=
        InnerIpv4ValidationError::InvalidPadding) {
        return false;
    }

    malformed = packet;
    malformed[3] = 0x15;
    if (ValidatePaddedInnerIpv4Packet(malformed, std::addressof(packet_size)) !=
        InnerIpv4ValidationError::LengthMismatch) {
        return false;
    }
    malformed = packet;
    malformed[3] = 0x13;
    if (ValidatePaddedInnerIpv4Packet(malformed, std::addressof(packet_size)) !=
        InnerIpv4ValidationError::LengthMismatch) {
        return false;
    }

    InnerPacketQueue<2> queue;
    InnerPacketRecord first{};
    first.packet_id = 1;
    InnerPacketRecord second{};
    second.packet_id = 2;
    InnerPacketRecord overflow{};
    overflow.packet_id = 3;
    if (queue.Push(first) != QueuePushResult::Pushed ||
        queue.Push(second) != QueuePushResult::Pushed ||
        queue.Push(overflow) != QueuePushResult::Full ||
        queue.Size() != 2) {
        return false;
    }
    InnerPacketRecord popped{};
    if (!queue.Pop(std::addressof(popped), QueueDisposition::Delivered) || popped.packet_id != 1 ||
        !queue.Pop(std::addressof(popped), QueueDisposition::Delivered) || popped.packet_id != 2 ||
        queue.Pop(std::addressof(popped), QueueDisposition::Delivered)) {
        return false;
    }
    static_cast<void>(queue.Push(first));
    queue.Clear(QueueDisposition::Cleared);
    return queue.Size() == 0 && queue.Front() == nullptr;
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
    std::snprintf(config.name.data(), config.name.size(), "%s", "harness-peer");
    std::snprintf(config.address.data(), config.address.size(), "%s", "10.66.66.2/32");
    std::snprintf(config.endpoint.data(), config.endpoint.size(), "%s", "vpn.example.test:51820");
    std::snprintf(config.private_key.data(), config.private_key.size(), "%s", HarnessLocalPrivateKey);
    std::snprintf(config.public_key.data(), config.public_key.size(), "%s", HarnessRemotePublicKey);
    std::snprintf(config.preshared_key.data(), config.preshared_key.size(), "%s", HarnessPresharedKey);
    std::snprintf(config.allowed_ips.data(), config.allowed_ips.size(), "%s", "0.0.0.0/0, ::/0");
    std::snprintf(config.dns.data(), config.dns.size(), "%s", "1.1.1.1");
    config.listen_port = 51820;
    config.persistent_keepalive = 25;
    config.mtu = 1420;

    wg_device &device = g_core_self_test_storage.device;
    if (!wg_device_init_from_config_entry(&device, config)) {
        return false;
    }
    if (!device.has_peer) {
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

    wg_timers_schedule(
        &peer->timers,
        TimerHook::RetransmitHandshake,
        TimerDeadlineFromJiffies(2000),
        peer->name);
    wg_timers_schedule(
        &peer->timers,
        TimerHook::Rekey,
        TimerDeadlineFromJiffies(4000),
        peer->name);
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
                        identity.static_public.bytes.data(),
                        expected_local_public.bytes.data(),
                        identity.static_public.bytes.size()) == 0;
    noise_static_identity_reset(&identity);
    return ok;
}

bool TestHandshakeInitiationCreation() {
    ResetCoreSelfTestStorage();
    wgnx::PeerConfigEntry &config = g_core_self_test_storage.config;
    std::snprintf(config.name.data(), config.name.size(), "%s", "handshake-peer");
    std::snprintf(config.address.data(), config.address.size(), "%s", "10.66.66.2/32");
    std::snprintf(config.endpoint.data(), config.endpoint.size(), "%s", "vpn.example.test:51820");
    std::snprintf(config.private_key.data(), config.private_key.size(), "%s", HarnessLocalPrivateKey);
    std::snprintf(config.public_key.data(), config.public_key.size(), "%s", HarnessRemotePublicKey);
    std::snprintf(config.preshared_key.data(), config.preshared_key.size(), "%s", HarnessPresharedKey);
    std::snprintf(config.allowed_ips.data(), config.allowed_ips.size(), "%s", "0.0.0.0/0, ::/0");

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
           std::memcmp(parsed.unencrypted_ephemeral.data(), zero_block, parsed.unencrypted_ephemeral.size()) != 0 &&
           std::memcmp(parsed.encrypted_static.data(), zero_block, parsed.unencrypted_ephemeral.size()) != 0 &&
           std::memcmp(parsed.macs.mac1.data(), zero_mac, parsed.macs.mac1.size()) != 0 &&
           std::memcmp(parsed.macs.mac2.data(), zero_mac, parsed.macs.mac2.size()) == 0;
}

bool TestHandshakeResponseAndSessionDerivation() {
    static constexpr std::uint8_t ZeroMac[NoiseMacSize] = {};

    ResetCoreSelfTestStorage();
    wgnx::PeerConfigEntry &initiator_config = g_core_self_test_storage.config;
    std::snprintf(initiator_config.name.data(), initiator_config.name.size(), "%s", "initiator-peer");
    std::snprintf(initiator_config.address.data(), initiator_config.address.size(), "%s", "10.66.66.2/32");
    std::snprintf(initiator_config.endpoint.data(), initiator_config.endpoint.size(), "%s", "vpn.example.test:51820");
    std::snprintf(initiator_config.private_key.data(), initiator_config.private_key.size(), "%s", HarnessLocalPrivateKey);
    std::snprintf(initiator_config.public_key.data(), initiator_config.public_key.size(), "%s", HarnessRemotePublicKey);
    std::snprintf(initiator_config.preshared_key.data(), initiator_config.preshared_key.size(), "%s", HarnessPresharedKey);
    std::snprintf(initiator_config.allowed_ips.data(), initiator_config.allowed_ips.size(), "%s", "0.0.0.0/0, ::/0");

    wg_device &initiator_device = g_core_self_test_storage.device;
    if (!wg_device_init_from_config_entry(&initiator_device, initiator_config)) {
        return false;
    }
    wg_peer *initiator = wg_device_first_peer(&initiator_device);
    if (initiator == nullptr) {
        return false;
    }

    wgnx::PeerConfigEntry &responder_config = g_core_self_test_storage.secondary_config;
    std::snprintf(responder_config.name.data(), responder_config.name.size(), "%s", "responder-peer");
    std::snprintf(responder_config.address.data(), responder_config.address.size(), "%s", "10.66.66.1/32");
    std::snprintf(responder_config.endpoint.data(), responder_config.endpoint.size(), "%s", "0.0.0.0:0");
    std::snprintf(responder_config.private_key.data(), responder_config.private_key.size(), "%s", HarnessRemotePrivateKey);
    std::snprintf(responder_config.public_key.data(), responder_config.public_key.size(), "%s", HarnessLocalPublicKey);
    std::snprintf(responder_config.preshared_key.data(), responder_config.preshared_key.size(), "%s", HarnessPresharedKey);
    std::snprintf(responder_config.allowed_ips.data(), responder_config.allowed_ips.size(), "%s", "10.66.66.2/32");

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

    message_handshake_response &tampered_response = g_core_self_test_storage.tampered_response;
    tampered_response = response;
    tampered_response.encrypted_nothing[0] ^= 0x80U;
    auto &tampered_buffer = g_core_self_test_storage.tampered_buffer;
    if (SerializeHandshakeResponse(&tampered_buffer.packet, tampered_response) != ParseError::None) {
        return false;
    }
    if (noise_handshake_consume_incoming_packet(
            &tampered_buffer.packet,
            &initiator_device,
            initiator) != HandshakePacketOutcome::Invalid) {
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

    auto &keepalive_buffer = g_core_self_test_storage.keepalive_buffer;
    if (!noise_create_keepalive_packet(&keepalive_buffer.packet, initiator->current_keypair)) {
        return false;
    }

    IncomingTransportDataResult keepalive_incoming{};
    const TransportDataError keepalive_error = noise_consume_incoming_transport_data_packet(
        &keepalive_buffer.packet,
        &responder_device,
        responder,
        {},
        &keepalive_incoming);
    if (keepalive_error != TransportDataError::None) {
        return false;
    }
    const TransportDataDecryptResult &keepalive_result = keepalive_incoming.decrypt;
    if (keepalive_buffer.packet.len != (TransportDataHeaderSize + NoiseMacSize) ||
        !keepalive_incoming.promoted_next_keypair ||
        keepalive_result.header.receiver_index != initiator->current_keypair.RemoteIndex() ||
        keepalive_result.header.counter + 1 != initiator->current_keypair.SendCounter() ||
        keepalive_result.payload_size != 0) {
        return false;
    }

    for (std::size_t i = 0; i < sizeof(g_core_self_test_storage.payload_plaintext); ++i) {
        g_core_self_test_storage.payload_plaintext[i] = static_cast<std::uint8_t>(0x30U + i);
    }

    auto &payload_buffer = g_core_self_test_storage.payload_buffer;
    if (noise_create_transport_data_packet(
            &payload_buffer.packet,
            initiator->current_keypair,
            g_core_self_test_storage.payload_plaintext) != TransportDataError::None) {
        return false;
    }

    wg_peer &responder_copy = g_core_self_test_storage.responder_copy;
    responder_copy.current_keypair.Establish(
        responder->current_keypair.LocalIndex(),
        responder->current_keypair.RemoteIndex(),
        responder->current_keypair.BirthTime(),
        responder->current_keypair.SendingKey(),
        responder->current_keypair.ReceivingKey(),
        responder->current_keypair.SendCounter());

    TransportDataDecryptResult payload_result{};
    const TransportDataError payload_error = noise_consume_transport_data_packet(
        &payload_buffer.packet,
        &responder->current_keypair,
        g_core_self_test_storage.decrypted_payload,
        &payload_result);
    if (payload_error != TransportDataError::None) {
        return false;
    }
    if (payload_result.header.receiver_index != initiator->current_keypair.RemoteIndex() ||
        payload_result.header.counter + 1 != initiator->current_keypair.SendCounter() ||
        payload_result.payload_size != sizeof(g_core_self_test_storage.payload_plaintext) ||
        std::memcmp(
            g_core_self_test_storage.payload_plaintext,
            g_core_self_test_storage.decrypted_payload,
            sizeof(g_core_self_test_storage.payload_plaintext)) != 0) {
        return false;
    }

    const TransportDataError replay_error = noise_consume_transport_data_packet(
        &payload_buffer.packet,
        &responder->current_keypair,
        g_core_self_test_storage.decrypted_payload,
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
        responder_copy.current_keypair.LocalIndex() ^ 0x00FF00FFU);
    const TransportDataError mismatch_error = noise_consume_transport_data_packet(
        &mismatch_buffer.packet,
        &responder_copy.current_keypair,
        g_core_self_test_storage.decrypted_payload,
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
        &responder_copy.current_keypair,
        g_core_self_test_storage.decrypted_payload,
        nullptr);
    if (tampered_payload_error != TransportDataError::AuthenticationFailed) {
        return false;
    }

    if (noise_create_transport_data_packet(
            &payload_buffer.packet,
            initiator->current_keypair,
            std::span<const std::uint8_t>(g_core_self_test_storage.payload_plaintext, 8)) != TransportDataError::None) {
        return false;
    }

    IncomingTransportDataResult incoming_result{};
    const TransportDataError incoming_error = noise_consume_incoming_transport_data_packet(
        &payload_buffer.packet,
        &responder_device,
        &responder_copy,
        g_core_self_test_storage.decrypted_payload,
        &incoming_result);
    if (incoming_error != TransportDataError::None) {
        return false;
    }
    if (incoming_result.slot != wg_index_slot::CurrentKeypair ||
        incoming_result.decrypt.header.receiver_index != initiator->current_keypair.RemoteIndex() ||
        incoming_result.decrypt.header.counter + 1 != initiator->current_keypair.SendCounter() ||
        incoming_result.decrypt.payload_size != TransportDataPaddingBlockSize ||
        std::memcmp(
            g_core_self_test_storage.payload_plaintext,
            g_core_self_test_storage.decrypted_payload,
            8) != 0) {
        return false;
    }
    for (std::size_t i = 8; i < incoming_result.decrypt.payload_size; ++i) {
        if (g_core_self_test_storage.decrypted_payload[i] != 0) {
            return false;
        }
    }

    if (payload_buffer.packet.len !=
        TransportDataHeaderSize + TransportDataPaddingBlockSize + NoiseTagSize) {
        return false;
    }

    return initiator->current_keypair.IsValid() &&
           responder->current_keypair.IsValid() &&
           initiator->handshake.state == HandshakeState::SessionDerived &&
           responder->handshake.state == HandshakeState::SessionDerived &&
           initiator->current_keypair.LocalIndex() == 0x01020304U &&
           initiator->current_keypair.RemoteIndex() == 0xA1A2A3A4U &&
           responder->current_keypair.LocalIndex() == 0xA1A2A3A4U &&
           responder->current_keypair.RemoteIndex() == 0x01020304U &&
           initiator->current_keypair.SendingKey().valid &&
           initiator->current_keypair.ReceivingKey().valid &&
           responder->current_keypair.SendingKey().valid &&
           responder->current_keypair.ReceivingKey().valid &&
           initiator->cookie.valid &&
           initiator->has_last_initiation &&
           responder->current_keypair.ReceiveReplayWindow().HasReceivedPacket() &&
           responder->current_keypair.ReceiveReplayWindow().HighestCounter() == payload_result.header.counter &&
           std::memcmp(
               initiator->current_keypair.SendingKey().bytes.data(),
               responder->current_keypair.ReceivingKey().bytes.data(),
               initiator->current_keypair.SendingKey().bytes.size()) == 0 &&
           std::memcmp(
               initiator->current_keypair.ReceivingKey().bytes.data(),
               responder->current_keypair.SendingKey().bytes.data(),
               initiator->current_keypair.ReceivingKey().bytes.size()) == 0 &&
           std::memcmp(
               initiator->last_initiation.macs.mac2.data(),
               ZeroMac,
               NoiseMacSize) != 0;
}

bool TestDebugProbeStatusTransitions() {
    return CanTransitionDebugProbeStatus(wgnx::DebugProbeStatus::None, wgnx::DebugProbeStatus::Queued) &&
           CanTransitionDebugProbeStatus(wgnx::DebugProbeStatus::Queued, wgnx::DebugProbeStatus::Sent) &&
           CanTransitionDebugProbeStatus(wgnx::DebugProbeStatus::Sent, wgnx::DebugProbeStatus::ReplyValidated) &&
           CanTransitionDebugProbeStatus(wgnx::DebugProbeStatus::Sent, wgnx::DebugProbeStatus::ReplyRejected) &&
           CanTransitionDebugProbeStatus(wgnx::DebugProbeStatus::Sent, wgnx::DebugProbeStatus::TimedOut) &&
           CanTransitionDebugProbeStatus(wgnx::DebugProbeStatus::ReplyValidated, wgnx::DebugProbeStatus::Queued) &&
           CanTransitionDebugProbeStatus(wgnx::DebugProbeStatus::BuildFailed, wgnx::DebugProbeStatus::Queued) &&
           !CanTransitionDebugProbeStatus(wgnx::DebugProbeStatus::Queued, wgnx::DebugProbeStatus::ReplyValidated) &&
           !CanTransitionDebugProbeStatus(wgnx::DebugProbeStatus::TimedOut, wgnx::DebugProbeStatus::ReplyValidated) &&
           !CanTransitionDebugProbeStatus(wgnx::DebugProbeStatus::ReplyRejected, wgnx::DebugProbeStatus::TimedOut);
}

bool TestDebugProbeIcmpRoundTrip() {
    std::array<std::uint8_t, DebugProbePacketSize> reply{};
    if (!BuildHarnessDebugProbeReply(
            std::addressof(reply),
            wgnx::DebugTriggerAction::PingTunnelPeer,
            0x01020304U,
            2)) {
        wgnx::sysmodule::logger::Log("Debug probe self-test: failed to build synthetic reply");
        return false;
    }

    DebugProbeReplyInfo info{};
    const DebugProbeReplyValidation validation = ValidateDebugIcmpEchoReply(
        reply,
        "10.13.13.2/32",
        2,
        0x01020304U,
        std::addressof(info));
    if (validation != DebugProbeReplyValidation::Valid) {
        wgnx::sysmodule::logger::Log(
            "Debug probe self-test: unexpected validation=%s",
            GetDebugProbeReplyValidationName(validation));
        return false;
    }
    if (info.action != wgnx::DebugTriggerAction::PingTunnelPeer ||
        info.activation_generation != 0x01020304U ||
        info.peer_index != 2 ||
        info.source_ipv4 != std::array<std::uint8_t, 4>{10, 13, 13, 1} ||
        info.destination_ipv4 != std::array<std::uint8_t, 4>{10, 13, 13, 2}) {
        wgnx::sysmodule::logger::Log(
            "Debug probe self-test: info mismatch action=%s activation=%u peer=%u src=%u.%u.%u.%u dst=%u.%u.%u.%u",
            wgnx::GetDebugTriggerActionName(info.action),
            info.activation_generation,
            static_cast<unsigned int>(info.peer_index),
            static_cast<unsigned int>(info.source_ipv4[0]),
            static_cast<unsigned int>(info.source_ipv4[1]),
            static_cast<unsigned int>(info.source_ipv4[2]),
            static_cast<unsigned int>(info.source_ipv4[3]),
            static_cast<unsigned int>(info.destination_ipv4[0]),
            static_cast<unsigned int>(info.destination_ipv4[1]),
            static_cast<unsigned int>(info.destination_ipv4[2]),
            static_cast<unsigned int>(info.destination_ipv4[3]));
        return false;
    }

    reply[12] ^= 0x01U;
    reply[10] = 0;
    reply[11] = 0;
    StoreHarnessBigEndian16(
        reply.data() + 10,
        ComputeHarnessInternetChecksum(reply.data(), DebugProbeIpv4HeaderSize));
    const DebugProbeReplyValidation mismatch_validation = ValidateDebugIcmpEchoReply(
        reply,
        "10.13.13.2/32",
        2,
        0x01020304U,
        nullptr);
    if (mismatch_validation != DebugProbeReplyValidation::SourceMismatch) {
        wgnx::sysmodule::logger::Log(
            "Debug probe self-test: expected source_mismatch got=%s",
            GetDebugProbeReplyValidationName(mismatch_validation));
        return false;
    }

    return true;
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
        TestInnerIpv4PacketBoundary() &&
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
        TestHandshakeResponseAndSessionDerivation()
        &&
        TestDebugProbeStatusTransitions() &&
        TestDebugProbeIcmpRoundTrip()
        ;
    ResetCoreSelfTestStorage();

    if (ok) {
        wgnx::sysmodule::logger::Log("WireGuard core skeleton self-test passed");
    } else {
        wgnx::sysmodule::logger::Log("WireGuard core skeleton self-test failed");
    }

    return ok;
}

} // namespace wgnx::wireguard
