#pragma once

#include "wgnx/tunnel_protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace wgnx::tunnel {

template <typename Send>
void DispatchUdpDatagramBatch(
    std::span<const PayloadRange> descriptors, std::span<const std::uint8_t> payload, std::span<PayloadResult> dispositions, Send&& send
) {
    for (std::size_t index = 0; index < descriptors.size(); ++index) {
        const PayloadRange& descriptor = descriptors[index];
        PayloadResult& disposition = dispositions[index];
        disposition = {
            .client_tag = descriptor.client_tag,
            .status = ProtocolStatus::MalformedInput,
            .accepted_bytes = 0,
        };

        const std::size_t offset = descriptor.payload_offset;
        const std::size_t size = descriptor.payload_size;
        if (offset > payload.size() || size > payload.size() - offset) {
            continue;
        }
        disposition.status = send(descriptor, payload.subspan(offset, size));
        if (disposition.status == ProtocolStatus::Success) {
            disposition.accepted_bytes = descriptor.payload_size;
        }
    }
}

} // namespace wgnx::tunnel
