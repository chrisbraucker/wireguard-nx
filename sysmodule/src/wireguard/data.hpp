#pragma once

#include "wgnx/platform/packet.hpp"

#include "wireguard/messages.hpp"
#include "wireguard/session.hpp"

#include <cstddef>
#include <cstdint>

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

const char *GetTransportDataErrorName(TransportDataError error);

TransportDataError noise_create_transport_data_packet(
    wgnx::platform::packet_buffer *packet,
    const noise_keypair &keypair,
    const std::uint8_t *payload,
    std::size_t payload_size);
bool noise_create_keepalive_packet(
    wgnx::platform::packet_buffer *packet,
    const noise_keypair &keypair);
TransportDataError noise_consume_transport_data_packet(
    const wgnx::platform::packet_buffer *packet,
    noise_keypair *keypair,
    std::uint8_t *out_payload,
    std::size_t out_payload_capacity,
    TransportDataDecryptResult *out_result);

} // namespace wgnx::wireguard
