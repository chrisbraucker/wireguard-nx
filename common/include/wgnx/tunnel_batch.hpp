#pragma once

#include "wgnx/tunnel_protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace wgnx::tunnel {

template <typename Send>
void DispatchUdpDatagramBatch(std::span<const DatagramDescriptor> descriptors, std::span<const std::uint8_t> payload,
                              std::span<DatagramDisposition> dispositions, Send&& send) {
    for (std::size_t index = 0; index < descriptors.size(); ++index) {
        const DatagramDescriptor& descriptor = descriptors[index];
        DatagramDisposition& disposition = dispositions[index];
        disposition = {
            .client_tag = descriptor.client_tag,
            .status = ProtocolStatus::MalformedInput,
            .reserved = 0,
        };

        const std::size_t offset = descriptor.payload_offset;
        const std::size_t size = descriptor.payload_size;
        if (offset > payload.size() || size > payload.size() - offset) {
            continue;
        }
        disposition.status = send(descriptor, payload.subspan(offset, size));
    }
}

} // namespace wgnx::tunnel
