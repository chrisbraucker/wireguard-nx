#include "platform/resolver_serialization.hpp"

#include <algorithm>

namespace wgnx::platform::resolver_serialization {

namespace {

constexpr std::uint32_t HorizonAfInet = 2;
constexpr std::uint32_t HorizonAfInet6 = 28;

bool ReadBe32(std::span<const std::uint8_t> input, std::size_t offset, std::uint32_t& out) {
    if (offset > input.size() || input.size() - offset < sizeof(std::uint32_t)) {
        return false;
    }
    out = (static_cast<std::uint32_t>(input[offset]) << 24U) | (static_cast<std::uint32_t>(input[offset + 1]) << 16U) |
          (static_cast<std::uint32_t>(input[offset + 2]) << 8U) | static_cast<std::uint32_t>(input[offset + 3]);
    return true;
}

bool WriteBe32(std::span<std::uint8_t> output, std::size_t offset, std::uint32_t value) {
    if (offset > output.size() || output.size() - offset < sizeof(std::uint32_t))
        return false;
    output[offset] = static_cast<std::uint8_t>(value >> 24U);
    output[offset + 1] = static_cast<std::uint8_t>(value >> 16U);
    output[offset + 2] = static_cast<std::uint8_t>(value >> 8U);
    output[offset + 3] = static_cast<std::uint8_t>(value);
    return true;
}

bool ReadBe16(std::span<const std::uint8_t> input, std::size_t offset, std::uint16_t& out) {
    if (offset > input.size() || input.size() - offset < sizeof(std::uint16_t))
        return false;
    out = static_cast<std::uint16_t>((static_cast<std::uint16_t>(input[offset]) << 8U) | input[offset + 1]);
    return true;
}

bool ParseSockaddr(std::span<const std::uint8_t> address, std::uint32_t header_family, endpoint& out) {
    if (address.size() < 2 || address[1] != header_family || address[0] > address.size())
        return false;

    std::uint16_t port = 0;
    if (!ReadBe16(address, 2, port))
        return false;

    endpoint parsed{};
    if (header_family == HorizonAfInet) {
        if (address.size() < SockaddrInetWireSize || address[0] < SockaddrInetWireSize)
            return false;
        parsed.family = address_family::inet;
        parsed.port = port;
        std::copy_n(address.begin() + 4, 4, parsed.address.begin());
    } else if (header_family == HorizonAfInet6) {
        if (address.size() < SockaddrInet6WireSize || address[0] < SockaddrInet6WireSize)
            return false;
        parsed.family = address_family::inet6;
        parsed.port = port;
        std::copy_n(address.begin() + 8, 16, parsed.address.begin());
    } else {
        return false;
    }
    out = parsed;
    return true;
}

} // namespace

bool serialize_horizon_addrinfo_hints(HorizonAddrInfoHints& output, std::int32_t flags, std::int32_t family, std::int32_t socket_type,
                                      std::int32_t protocol) {
    constexpr std::size_t EmptyAddrSize = sizeof(std::uint32_t);
    static_assert(HorizonAddrInfoHintsWireSize == AddrInfoWireHeaderSize + EmptyAddrSize + 1);
    if (!WriteBe32(output, 0, AddrInfoWireMagic) || !WriteBe32(output, 4, static_cast<std::uint32_t>(flags)) ||
        !WriteBe32(output, 8, static_cast<std::uint32_t>(family)) || !WriteBe32(output, 12, static_cast<std::uint32_t>(socket_type)) ||
        !WriteBe32(output, 16, static_cast<std::uint32_t>(protocol)) || !WriteBe32(output, 20, 0))
        return false;
    std::fill(output.begin() + AddrInfoWireHeaderSize, output.end(), 0);
    return true;
}

bool parse_horizon_addrinfo_result(std::span<const std::uint8_t> input, endpoint& out_endpoint) {
    out_endpoint = {};

    std::size_t cursor = 0;
    bool found_endpoint = false;
    endpoint selected{};
    while (cursor < input.size()) {
        if (input.size() - cursor < AddrInfoWireHeaderSize)
            return false;
        std::uint32_t magic = 0;
        std::uint32_t family = 0;
        std::uint32_t address_length = 0;
        if (!ReadBe32(input, cursor, magic) || !ReadBe32(input, cursor + 8, family) || !ReadBe32(input, cursor + 20, address_length) ||
            magic != AddrInfoWireMagic)
            return false;
        if (address_length == 0)
            address_length = sizeof(std::uint32_t);
        if (address_length > input.size() - cursor - AddrInfoWireHeaderSize)
            return false;

        const std::size_t address_offset = cursor + AddrInfoWireHeaderSize;
        const std::size_t name_offset = address_offset + address_length;
        const auto name_begin = input.begin() + static_cast<std::ptrdiff_t>(name_offset);
        const auto terminator = std::find(name_begin, input.end(), std::uint8_t{0});
        if (terminator == input.end())
            return false;
        const std::size_t next = static_cast<std::size_t>(std::distance(input.begin(), terminator)) + 1;

        endpoint parsed{};
        if (ParseSockaddr(input.subspan(address_offset, address_length), family, parsed) && !found_endpoint) {
            selected = parsed;
            found_endpoint = true;
        }
        cursor = next;
    }
    if (!found_endpoint)
        return false;
    out_endpoint = selected;
    return true;
}

} // namespace wgnx::platform::resolver_serialization
