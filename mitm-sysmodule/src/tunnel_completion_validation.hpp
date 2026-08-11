#pragma once

#include "wgnx/tunnel_protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace wgnx::mitm {

inline bool ValidateTunnelCompletionDrain(
    std::uint32_t count, std::size_t record_capacity, std::span<const wgnx::tunnel::CompletionRecord> records, std::size_t payload_capacity
) {
    if (count > record_capacity || count > records.size()) {
        return false;
    }
    for (const wgnx::tunnel::CompletionRecord& record : records.first(count)) {
        std::size_t maximum_payload_size = 0;
        if (record.type == wgnx::tunnel::CompletionType::InboundUdpDatagram) {
            maximum_payload_size = wgnx::tunnel::MaximumUdpPayloadStorageBytes;
        } else if (record.type == wgnx::tunnel::CompletionType::InboundTcpStream) {
            maximum_payload_size = wgnx::tunnel::MaximumTcpWriteStorageBytes;
        } else {
            continue;
        }
        const std::size_t offset = record.payload_offset;
        const std::size_t size = record.payload_size;
        if (size > maximum_payload_size || offset > payload_capacity || size > payload_capacity - offset) {
            return false;
        }
    }
    return true;
}

} // namespace wgnx::mitm
