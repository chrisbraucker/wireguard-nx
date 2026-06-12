#include "wireguard/data.hpp"

#include "wireguard/crypto/primitives.hpp"
#include "wireguard/device.hpp"
#include "wireguard/endian.hpp"

#include <cstring>
#include <limits>

namespace wgnx::wireguard {

namespace {

constexpr std::size_t TransportDataTagSize = crypto::Poly1305TagSize;
constexpr std::size_t ReplayWindowBits = 64;

struct ReceiveCounterState {
    std::uint64_t receive_counter{0};
    std::uint64_t replay_window{0};
    bool has_receive_counter{false};
};

bool IsValidReceiveKeypair(const noise_keypair &keypair) {
    return keypair.valid &&
           keypair.local_index != 0 &&
           keypair.receiving_key.valid;
}

void BuildTransportNonce(std::uint8_t nonce[crypto::ChaCha20NonceSize], std::uint64_t counter) {
    std::memset(nonce, 0, crypto::ChaCha20NonceSize);
    StoreLe64(nonce + sizeof(std::uint32_t), counter);
}

bool AdvanceReceiveCounterState(
    const noise_keypair &keypair,
    std::uint64_t counter,
    ReceiveCounterState *out_state) {
    if (out_state == nullptr) {
        return false;
    }

    *out_state = {
        .receive_counter = keypair.receive_counter,
        .replay_window = keypair.replay_window,
        .has_receive_counter = keypair.has_receive_counter,
    };

    if (!out_state->has_receive_counter) {
        out_state->receive_counter = counter;
        out_state->replay_window = 1U;
        out_state->has_receive_counter = true;
        return true;
    }

    if (counter > out_state->receive_counter) {
        const std::uint64_t shift = counter - out_state->receive_counter;
        out_state->replay_window =
            shift >= ReplayWindowBits ? 0 : (out_state->replay_window << shift);
        out_state->replay_window |= 1U;
        out_state->receive_counter = counter;
        return true;
    }

    const std::uint64_t delta = out_state->receive_counter - counter;
    if (delta >= ReplayWindowBits) {
        return false;
    }

    const std::uint64_t mask = std::uint64_t{1} << delta;
    if ((out_state->replay_window & mask) != 0) {
        return false;
    }

    out_state->replay_window |= mask;
    return true;
}

void CommitReceiveCounterState(noise_keypair *keypair, const ReceiveCounterState &state) {
    if (keypair == nullptr) {
        return;
    }

    keypair->receive_counter = state.receive_counter;
    keypair->replay_window = state.replay_window;
    keypair->has_receive_counter = state.has_receive_counter;
}

} // namespace

const char *GetTransportDataErrorName(TransportDataError error) {
    switch (error) {
        case TransportDataError::None:
            return "none";
        case TransportDataError::InvalidArgument:
            return "invalid_argument";
        case TransportDataError::InvalidKeypair:
            return "invalid_keypair";
        case TransportDataError::InsufficientCapacity:
            return "insufficient_capacity";
        case TransportDataError::InvalidPacket:
            return "invalid_packet";
        case TransportDataError::ReceiverIndexMismatch:
            return "receiver_index_mismatch";
        case TransportDataError::CounterExhausted:
            return "counter_exhausted";
        case TransportDataError::ReplayRejected:
            return "replay_rejected";
        case TransportDataError::AuthenticationFailed:
            return "authentication_failed";
    }

    return "unknown";
}

TransportDataError noise_create_transport_data_packet(
    wgnx::platform::packet_buffer *packet,
    const noise_keypair &keypair,
    std::span<const std::uint8_t> payload) {
    if (packet == nullptr) {
        return TransportDataError::InvalidArgument;
    }
    if (!keypair.valid || !keypair.sending_key.valid || keypair.remote_index == 0) {
        return TransportDataError::InvalidKeypair;
    }
    if (keypair.send_counter == std::numeric_limits<std::uint64_t>::max()) {
        return TransportDataError::CounterExhausted;
    }

    const std::size_t required_size = TransportDataHeaderSize + payload.size() + TransportDataTagSize;
    if (required_size < payload.size() || packet->capacity < required_size) {
        return TransportDataError::InsufficientCapacity;
    }

    message_transport_data header{};
    SetMessageType(&header.type, MessageType::TransportData);
    header.receiver_index = keypair.remote_index;
    header.counter = keypair.send_counter;
    if (SerializeTransportDataHeader(packet, header) != ParseError::None) {
        return TransportDataError::InvalidPacket;
    }

    std::uint8_t nonce[crypto::ChaCha20NonceSize]{};
    std::uint8_t tag[TransportDataTagSize]{};
    std::uint8_t empty_payload = 0;
    std::uint8_t *ciphertext = packet->data + TransportDataHeaderSize;
    const std::uint8_t *plaintext = payload.empty() ? &empty_payload : payload.data();
    BuildTransportNonce(nonce, header.counter);
    if (!crypto::chacha20poly1305_encrypt(
            ciphertext,
            tag,
            plaintext,
            payload.size(),
            nullptr,
            0,
            keypair.sending_key.bytes,
            nonce)) {
        crypto::secure_clear(nonce, sizeof(nonce));
        crypto::secure_clear(tag, sizeof(tag));
        crypto::secure_clear(&empty_payload, sizeof(empty_payload));
        return TransportDataError::AuthenticationFailed;
    }

    std::memcpy(ciphertext + payload.size(), tag, sizeof(tag));
    packet->len = required_size;
    crypto::secure_clear(nonce, sizeof(nonce));
    crypto::secure_clear(tag, sizeof(tag));
    crypto::secure_clear(&empty_payload, sizeof(empty_payload));
    return TransportDataError::None;
}

bool noise_create_keepalive_packet(
    wgnx::platform::packet_buffer *packet,
    const noise_keypair &keypair) {
    return noise_create_transport_data_packet(packet, keypair, {}) ==
           TransportDataError::None;
}

TransportDataError noise_consume_transport_data_packet(
    const wgnx::platform::packet_buffer *packet,
    noise_keypair *keypair,
    std::span<std::uint8_t> out_payload,
    TransportDataDecryptResult *out_result) {
    if (out_result != nullptr) {
        *out_result = {};
    }
    if (packet == nullptr || keypair == nullptr) {
        return TransportDataError::InvalidArgument;
    }
    if (!IsValidReceiveKeypair(*keypair)) {
        return TransportDataError::InvalidKeypair;
    }

    message_transport_data header{};
    if (!ParseTransportDataHeader(packet, &header).success) {
        return TransportDataError::InvalidPacket;
    }
    if (packet->len < (TransportDataHeaderSize + TransportDataTagSize)) {
        return TransportDataError::InvalidPacket;
    }
    if (header.receiver_index != keypair->local_index) {
        return TransportDataError::ReceiverIndexMismatch;
    }

    const std::size_t payload_size = packet->len - TransportDataHeaderSize - TransportDataTagSize;
    if (payload_size > out_payload.size()) {
        return TransportDataError::InsufficientCapacity;
    }
    if (payload_size != 0 && out_payload.empty()) {
        return TransportDataError::InvalidArgument;
    }

    ReceiveCounterState receive_state{};
    if (!AdvanceReceiveCounterState(*keypair, header.counter, &receive_state)) {
        return TransportDataError::ReplayRejected;
    }

    std::uint8_t nonce[crypto::ChaCha20NonceSize]{};
    std::uint8_t empty_payload = 0;
    const std::uint8_t *ciphertext = packet->data + TransportDataHeaderSize;
    const std::uint8_t *tag = ciphertext + payload_size;
    std::uint8_t *plaintext = payload_size != 0 ? out_payload.data() : &empty_payload;
    BuildTransportNonce(nonce, header.counter);
    const bool ok = crypto::chacha20poly1305_decrypt(
        plaintext,
        ciphertext,
        payload_size,
        tag,
        nullptr,
        0,
        keypair->receiving_key.bytes,
        nonce);
    crypto::secure_clear(nonce, sizeof(nonce));
    crypto::secure_clear(&empty_payload, sizeof(empty_payload));
    if (!ok) {
        return TransportDataError::AuthenticationFailed;
    }

    CommitReceiveCounterState(keypair, receive_state);
    if (out_result != nullptr) {
        out_result->header = header;
        out_result->payload_size = payload_size;
    }
    return TransportDataError::None;
}

TransportDataError noise_consume_incoming_transport_data_packet(
    const wgnx::platform::packet_buffer *packet,
    const wg_device *device,
    wg_peer *peer,
    std::span<std::uint8_t> out_payload,
    IncomingTransportDataResult *out_result) {
    if (out_result != nullptr) {
        *out_result = {};
    }
    if (packet == nullptr || device == nullptr || peer == nullptr) {
        return TransportDataError::InvalidArgument;
    }

    message_transport_data header{};
    const ParseResult parse_result = ParseTransportDataHeader(packet, &header);
    if (!parse_result.success) {
        return TransportDataError::InvalidPacket;
    }

    const wg_index_slot slot = wg_device_lookup_index_slot(device, header.receiver_index);
    noise_keypair *keypair = wg_peer_keypair_for_slot(peer, slot);
    if (keypair == nullptr) {
        return TransportDataError::ReceiverIndexMismatch;
    }

    TransportDataDecryptResult decrypt{};
    const TransportDataError error = noise_consume_transport_data_packet(
        packet,
        keypair,
        out_payload,
        &decrypt);
    if (error != TransportDataError::None) {
        return error;
    }

    if (out_result != nullptr) {
        out_result->slot = slot;
        out_result->decrypt = decrypt;
    }
    return TransportDataError::None;
}

} // namespace wgnx::wireguard
