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

inline TunnelDatagramReceiveOutcome ReceiveTunneledDatagram(
    bool* occupied, std::span<std::uint8_t> output, std::span<const std::uint8_t> input
) {
    const std::size_t copied = std::min(output.size(), input.size());
    std::copy_n(input.begin(), copied, output.begin());
    *occupied = false;
    return {.size = copied, .truncated = copied != input.size()};
}

} // namespace wgnx::mitm
