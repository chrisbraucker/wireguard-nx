#include "wireguard/inner_packet.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span<const std::uint8_t> packet{data, size};
    wgnx::wireguard::InnerIpVersion version{};
    std::size_t packet_size = 0;

    static_cast<void>(wgnx::wireguard::ValidateInnerIpPacket(packet, &version));
    static_cast<void>(wgnx::wireguard::ValidatePaddedInnerIpPacket(packet, &packet_size, &version));
    static_cast<void>(wgnx::wireguard::ValidateInnerIpv4Packet(packet));
    static_cast<void>(wgnx::wireguard::ValidatePaddedInnerIpv4Packet(packet, &packet_size));
    return 0;
}
