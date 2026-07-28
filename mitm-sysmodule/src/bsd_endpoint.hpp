#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>

namespace wgnx::mitm {

inline constexpr std::uint8_t BsdAddressFamilyInet = 2;

struct __attribute__((packed)) BsdSockAddrIn {
    std::uint8_t length{sizeof(BsdSockAddrIn)};
    std::uint8_t family{BsdAddressFamilyInet};
    std::uint16_t port{};
    std::uint8_t address[4]{};
    std::uint8_t padding[8]{};
};

static_assert(sizeof(BsdSockAddrIn) == 16);

struct BsdIpv4Endpoint {
    std::array<std::uint8_t, 4> address{};
    std::uint16_t port{};
};

[[nodiscard]] inline std::uint16_t LoadBigEndian16(const std::uint16_t value) {
    return static_cast<std::uint16_t>((value >> 8U) | (value << 8U));
}

[[nodiscard]] inline std::uint16_t StoreBigEndian16(const std::uint16_t value) {
    return LoadBigEndian16(value);
}

[[nodiscard]] inline bool DecodeBsdIpv4Endpoint(const std::span<const std::uint8_t> address, BsdIpv4Endpoint* out_endpoint) {
    if (address.size() < sizeof(BsdSockAddrIn) || out_endpoint == nullptr) {
        return false;
    }

    BsdSockAddrIn socket_address{};
    std::memcpy(std::addressof(socket_address), address.data(), sizeof(socket_address));
    // libnx callers commonly zero-initialize sockaddr_in and leave sin_len as zero.
    if ((socket_address.length != 0 && socket_address.length < sizeof(BsdSockAddrIn)) || socket_address.family != BsdAddressFamilyInet) {
        return false;
    }

    std::memcpy(out_endpoint->address.data(), socket_address.address, out_endpoint->address.size());
    out_endpoint->port = LoadBigEndian16(socket_address.port);
    return out_endpoint->port != 0;
}

[[nodiscard]] inline bool EncodeBsdIpv4Endpoint(const BsdIpv4Endpoint& endpoint, const std::span<std::uint8_t> out_buffer) {
    if (out_buffer.size() < sizeof(BsdSockAddrIn)) {
        return false;
    }

    BsdSockAddrIn socket_address{};
    socket_address.port = StoreBigEndian16(endpoint.port);
    std::memcpy(socket_address.address, endpoint.address.data(), endpoint.address.size());
    std::memcpy(out_buffer.data(), std::addressof(socket_address), sizeof(socket_address));
    return true;
}

} // namespace wgnx::mitm
