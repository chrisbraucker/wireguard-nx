#pragma once

#include <cstdint>

namespace wgnx::wireguard {

constexpr inline std::uint32_t LoadLe32(const std::uint8_t* data) {
    return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8) | (static_cast<std::uint32_t>(data[2]) << 16) |
           (static_cast<std::uint32_t>(data[3]) << 24);
}

constexpr inline std::uint64_t LoadLe64(const std::uint8_t* data) {
    return static_cast<std::uint64_t>(LoadLe32(data)) | (static_cast<std::uint64_t>(LoadLe32(data + 4)) << 32);
}

constexpr inline void StoreLe32(std::uint8_t* data, std::uint32_t value) {
    data[0] = static_cast<std::uint8_t>(value & 0xFFU);
    data[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFU);
    data[2] = static_cast<std::uint8_t>((value >> 16) & 0xFFU);
    data[3] = static_cast<std::uint8_t>((value >> 24) & 0xFFU);
}

constexpr inline void StoreLe64(std::uint8_t* data, std::uint64_t value) {
    StoreLe32(data, static_cast<std::uint32_t>(value & 0xFFFFFFFFULL));
    StoreLe32(data + 4, static_cast<std::uint32_t>(value >> 32));
}

} // namespace wgnx::wireguard
