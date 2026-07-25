#pragma once

#include "wgnx/platform/udp.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace wgnx::platform::resolver_serialization {

/*
 * Horizon sfdnsres GetAddrInfoRequest wire ABI, observed on 20.5.0:
 *
 *   addrinfo header (24 bytes, six big-endian u32 fields)
 *   sockaddr bytes (ai_addrlen, or four bytes when zero)
 *   NUL-terminated canonical name
 *
 * Records may be concatenated. Sockaddr fields follow Horizon's BSD layout:
 * length:u8, family:u8, port:be16, then address bytes. The parser does not
 * reinterpret the buffer as either addrinfo or sockaddr, so alignment and
 * host-native layout cannot influence its bounds checks.
 */
constexpr inline std::size_t AddrInfoWireHeaderSize = 24;
constexpr inline std::uint32_t AddrInfoWireMagic = 0xBEEFCAFEu;
constexpr inline std::size_t SockaddrInetWireSize = 16;
constexpr inline std::size_t SockaddrInet6WireSize = 28;
constexpr inline std::size_t HorizonAddrInfoHintsWireSize = AddrInfoWireHeaderSize + sizeof(std::uint32_t) + 1;

using HorizonAddrInfoHints = std::array<std::uint8_t, HorizonAddrInfoHintsWireSize>;

bool serialize_horizon_addrinfo_hints(HorizonAddrInfoHints& output, std::int32_t flags, std::int32_t family, std::int32_t socket_type,
                                      std::int32_t protocol);

// Validates every record in the returned buffer and selects its first usable
// AF_INET or AF_INET6 endpoint. A malformed trailing record invalidates the
// entire result instead of being silently ignored.
bool parse_horizon_addrinfo_result(std::span<const std::uint8_t> input, endpoint& out_endpoint);

} // namespace wgnx::platform::resolver_serialization
