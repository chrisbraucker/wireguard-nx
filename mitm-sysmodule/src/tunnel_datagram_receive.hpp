#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace wgnx::mitm {

struct TunnelDatagramReceiveOutcome {
    std::size_t size{};
    bool truncated{};
};

struct TunnelStreamReceiveOutcome {
    std::size_t size{};
    bool complete{};
};

inline TunnelDatagramReceiveOutcome ReceiveTunneledDatagram(
    bool* occupied, std::span<std::uint8_t> output, std::span<const std::uint8_t> input
) {
    const std::size_t copied = std::min(output.size(), input.size());
    std::copy_n(input.begin(), copied, output.begin());
    *occupied = false;
    return {.size = copied, .truncated = copied != input.size()};
}

inline TunnelStreamReceiveOutcome ReceiveTunneledStream(
    bool* occupied, std::size_t* offset, std::span<std::uint8_t> output, std::span<const std::uint8_t> input
) {
    const std::size_t available = input.size() - *offset;
    const std::size_t copied = std::min(output.size(), available);
    std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(*offset), copied, output.begin());
    *offset += copied;
    if (*offset == input.size()) {
        *occupied = false;
    }
    return {.size = copied, .complete = !*occupied};
}

} // namespace wgnx::mitm
