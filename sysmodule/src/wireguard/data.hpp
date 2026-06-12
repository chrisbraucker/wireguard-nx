#pragma once

#include "wgnx/platform/packet.hpp"

#include "wireguard/device.hpp"
#include "wireguard/messages.hpp"
#include "wireguard/session.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace wgnx::wireguard {

enum class TransportDataError : std::uint8_t {
    None = 0,
    InvalidArgument,
    InvalidKeypair,
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

struct IncomingTransportDataResult {
    wg_index_slot slot{wg_index_slot::None};
    TransportDataDecryptResult decrypt{};
};

const char *GetTransportDataErrorName(TransportDataError error);

TransportDataError noise_create_transport_data_packet(
    wgnx::platform::packet_buffer *packet,
    const noise_keypair &keypair,
    std::span<const std::uint8_t> payload);
bool noise_create_keepalive_packet(
    wgnx::platform::packet_buffer *packet,
    const noise_keypair &keypair);
TransportDataError noise_consume_transport_data_packet(
    const wgnx::platform::packet_buffer *packet,
    noise_keypair *keypair,
    std::span<std::uint8_t> out_payload,
    TransportDataDecryptResult *out_result);
TransportDataError noise_consume_incoming_transport_data_packet(
    const wgnx::platform::packet_buffer *packet,
    const wg_device *device,
    wg_peer *peer,
    std::span<std::uint8_t> out_payload,
    IncomingTransportDataResult *out_result);

} // namespace wgnx::wireguard
