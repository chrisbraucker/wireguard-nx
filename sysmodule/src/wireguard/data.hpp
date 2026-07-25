#pragma once

#include "wireguard/device.hpp"
#include "wireguard/messages.hpp"
#include "wireguard/session.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace wgnx::wireguard {

constexpr inline std::size_t TransportDataPaddingBlockSize = 16;

constexpr std::size_t GetPaddedTransportPayloadSize(std::size_t payload_size) {
    return payload_size == 0
               ? 0
               : ((payload_size + TransportDataPaddingBlockSize - 1) / TransportDataPaddingBlockSize) * TransportDataPaddingBlockSize;
}

enum class TransportDataError : std::uint8_t {
    None = 0,
    InvalidArgument,
    InvalidKeypair,
    KeyExpired,
    InsufficientCapacity,
    InvalidPacket,
    ReceiverIndexMismatch,
    CounterExhausted,
    ReplayRejected,
    AuthenticationFailed,
};

struct TransportDataDecryptResult {
    message_transport_data header{};
    std::size_t payload_size{0};
};

struct TransportDataCreateResult {
    TransportDataError error{TransportDataError::InvalidArgument};
    std::size_t packet_size{0};
    std::uint64_t counter{0};
};

struct IncomingTransportDataResult {
    wg_index_slot slot{wg_index_slot::None};
    TransportDataDecryptResult decrypt{};
    bool promoted_next_keypair{false};
};

const char* GetTransportDataErrorName(TransportDataError error);

TransportDataCreateResult noise_create_transport_data_packet(std::span<std::uint8_t> output, noise_keypair& keypair,
                                                             std::span<const std::uint8_t> payload);
TransportDataCreateResult noise_create_keepalive_packet(std::span<std::uint8_t> output, noise_keypair& keypair);
TransportDataError noise_consume_transport_data_packet(std::span<const std::uint8_t> packet, noise_keypair& keypair,
                                                       std::span<std::uint8_t> out_payload, TransportDataDecryptResult& out_result);
TransportDataError noise_consume_incoming_transport_data_packet(std::span<const std::uint8_t> packet, wg_device& device, wg_peer& peer,
                                                                std::span<std::uint8_t> out_payload,
                                                                IncomingTransportDataResult& out_result);

} // namespace wgnx::wireguard
