#include "wireguard/data.hpp"

#include "wireguard/crypto/primitives.hpp"
#include "wireguard/endian.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace wgnx::wireguard {

namespace {

std::array<std::uint8_t, crypto::ChaCha20NonceSize> BuildTransportNonce(
    std::uint64_t counter) {
    std::array<std::uint8_t, crypto::ChaCha20NonceSize> nonce{};
    StoreLe64(nonce.data() + sizeof(std::uint32_t), counter);
    return nonce;
}

TransportDataCreateResult CreateFailure(TransportDataError error) {
    return {.error = error};
}

} // namespace

const char *GetTransportDataErrorName(TransportDataError error) {
    switch (error) {
        case TransportDataError::None: return "none";
        case TransportDataError::InvalidArgument: return "invalid_argument";
        case TransportDataError::InvalidKeypair: return "invalid_keypair";
        case TransportDataError::KeyExpired: return "key_expired";
        case TransportDataError::InsufficientCapacity: return "insufficient_capacity";
        case TransportDataError::InvalidPacket: return "invalid_packet";
        case TransportDataError::ReceiverIndexMismatch: return "receiver_index_mismatch";
        case TransportDataError::CounterExhausted: return "counter_exhausted";
        case TransportDataError::ReplayRejected: return "replay_rejected";
        case TransportDataError::AuthenticationFailed: return "authentication_failed";
    }
    return "unknown";
}

TransportDataCreateResult noise_create_transport_data_packet(
    std::span<std::uint8_t> output,
    noise_keypair &keypair,
    std::span<const std::uint8_t> payload) {
    if (payload.size() >
        std::numeric_limits<std::size_t>::max() - (TransportDataPaddingBlockSize - 1)) {
        return CreateFailure(TransportDataError::InsufficientCapacity);
    }

    const std::size_t padded_payload_size = GetPaddedTransportPayloadSize(payload.size());
    const std::size_t required_size =
        TransportDataHeaderSize + padded_payload_size + NoiseTagSize;
    if (required_size < padded_payload_size || output.size() < required_size) {
        return CreateFailure(TransportDataError::InsufficientCapacity);
    }

    std::uint64_t counter = 0;
    switch (keypair.ReserveSendCounterAt(GetMonotonicTime(), counter)) {
        case KeypairSendState::Ready:
            break;
        case KeypairSendState::Invalid:
            return CreateFailure(TransportDataError::InvalidKeypair);
        case KeypairSendState::Expired:
            return CreateFailure(TransportDataError::KeyExpired);
        case KeypairSendState::CounterExhausted:
            return CreateFailure(TransportDataError::CounterExhausted);
    }

    message_transport_data header{};
    SetMessageType(header.type, MessageType::TransportData);
    header.receiver_index = keypair.RemoteIndex();
    header.counter = counter;
    if (SerializeTransportDataHeader(output.first(TransportDataHeaderSize), header) !=
        ParseError::None) {
        return CreateFailure(TransportDataError::InvalidPacket);
    }

    std::span<std::uint8_t> ciphertext =
        output.subspan(TransportDataHeaderSize, padded_payload_size);
    std::ranges::copy(payload, ciphertext.begin());
    std::ranges::fill(ciphertext.subspan(payload.size()), 0);

    std::array<std::uint8_t, NoiseTagSize> tag{};
    const auto nonce = BuildTransportNonce(counter);
    std::uint8_t empty_payload = 0;
    const std::uint8_t *plaintext = ciphertext.empty() ? &empty_payload : ciphertext.data();
    std::uint8_t *ciphertext_output = ciphertext.empty()
        ? output.data() + TransportDataHeaderSize
        : ciphertext.data();
    const bool encrypted = crypto::chacha20poly1305_encrypt(
        ciphertext_output,
        tag.data(),
        plaintext,
        ciphertext.size(),
        nullptr,
        0,
        keypair.SendingKey().bytes.data(),
        nonce.data());
    crypto::secure_clear(&empty_payload, sizeof(empty_payload));
    if (!encrypted) {
        crypto::secure_clear(tag.data(), tag.size());
        return CreateFailure(TransportDataError::AuthenticationFailed);
    }

    std::ranges::copy(
        tag,
        output.begin() + static_cast<std::ptrdiff_t>(TransportDataHeaderSize + padded_payload_size));
    crypto::secure_clear(tag.data(), tag.size());
    return {
        .error = TransportDataError::None,
        .packet_size = required_size,
        .counter = counter,
    };
}

TransportDataCreateResult noise_create_keepalive_packet(
    std::span<std::uint8_t> output,
    noise_keypair &keypair) {
    return noise_create_transport_data_packet(output, keypair, {});
}

TransportDataError noise_consume_transport_data_packet(
    std::span<const std::uint8_t> packet,
    noise_keypair &keypair,
    std::span<std::uint8_t> out_payload,
    TransportDataDecryptResult &out_result) {
    out_result = {};
    if (!keypair.IsValid()) {
        return TransportDataError::InvalidKeypair;
    }
    if (!keypair.CanReceiveAt(GetMonotonicTime())) {
        return TransportDataError::KeyExpired;
    }

    message_transport_data header{};
    if (!ParseTransportDataHeader(packet, header).success ||
        packet.size() < (TransportDataHeaderSize + NoiseTagSize)) {
        return TransportDataError::InvalidPacket;
    }
    if (header.receiver_index != keypair.LocalIndex()) {
        return TransportDataError::ReceiverIndexMismatch;
    }
    if (header.counter >= RejectAfterMessages) {
        return TransportDataError::CounterExhausted;
    }

    const std::size_t payload_size =
        packet.size() - TransportDataHeaderSize - NoiseTagSize;
    if (payload_size > out_payload.size()) {
        return TransportDataError::InsufficientCapacity;
    }

    ReplayWindow candidate_replay_window = keypair.ReceiveReplayWindow();
    if (!candidate_replay_window.TryAdvance(header.counter)) {
        return TransportDataError::ReplayRejected;
    }

    const std::span<const std::uint8_t> ciphertext =
        packet.subspan(TransportDataHeaderSize, payload_size);
    const std::span<const std::uint8_t, NoiseTagSize> tag{
        packet.data() + TransportDataHeaderSize + payload_size,
        NoiseTagSize};
    const auto nonce = BuildTransportNonce(header.counter);
    std::uint8_t empty_payload = 0;
    std::uint8_t *plaintext = payload_size == 0 ? &empty_payload : out_payload.data();
    const bool authenticated = crypto::chacha20poly1305_decrypt(
        plaintext,
        ciphertext.data(),
        ciphertext.size(),
        tag.data(),
        nullptr,
        0,
        keypair.ReceivingKey().bytes.data(),
        nonce.data());
    crypto::secure_clear(&empty_payload, sizeof(empty_payload));
    if (!authenticated) {
        return TransportDataError::AuthenticationFailed;
    }

    keypair.ReceiveReplayWindow() = candidate_replay_window;
    out_result = {.header = header, .payload_size = payload_size};
    return TransportDataError::None;
}

TransportDataError noise_consume_incoming_transport_data_packet(
    std::span<const std::uint8_t> packet,
    wg_device &device,
    wg_peer &peer,
    std::span<std::uint8_t> out_payload,
    IncomingTransportDataResult &out_result) {
    out_result = {};
    message_transport_data header{};
    if (!ParseTransportDataHeader(packet, header).success) {
        return TransportDataError::InvalidPacket;
    }

    const wg_index_slot slot = wg_device_lookup_index_slot(&device, header.receiver_index);
    noise_keypair *keypair = wg_peer_keypair_for_slot(&peer, slot);
    if (keypair == nullptr) {
        return TransportDataError::ReceiverIndexMismatch;
    }

    TransportDataDecryptResult decrypt{};
    const TransportDataError error = noise_consume_transport_data_packet(
        packet,
        *keypair,
        out_payload,
        decrypt);
    if (error != TransportDataError::None) {
        return error;
    }

    const bool promoted = slot == wg_index_slot::NextKeypair &&
                          wg_device_promote_next_keypair(&device, &peer);
    out_result = {
        .slot = slot,
        .decrypt = decrypt,
        .promoted_next_keypair = promoted,
    };
    return TransportDataError::None;
}

} // namespace wgnx::wireguard
