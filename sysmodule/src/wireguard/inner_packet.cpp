#include "wireguard/inner_packet.hpp"

namespace wgnx::wireguard {

namespace {

std::uint16_t LoadBigEndian16(const std::uint8_t *value) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(value[0]) << 8U) |
        static_cast<std::uint16_t>(value[1]));
}

bool HasValidInternetChecksum(std::span<const std::uint8_t> bytes) {
    std::uint32_t sum = 0;
    std::size_t offset = 0;
    while (offset + 1 < bytes.size()) {
        sum += LoadBigEndian16(bytes.data() + offset);
        offset += 2;
    }
    if (offset < bytes.size()) {
        sum += static_cast<std::uint16_t>(bytes[offset]) << 8U;
    }
    while ((sum >> 16U) != 0) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    return static_cast<std::uint16_t>(sum) == 0xFFFFU;
}

} // namespace

InnerIpv4ValidationError ValidateInnerIpv4Packet(std::span<const std::uint8_t> packet) {
    constexpr std::size_t MinimumIpv4HeaderSize = 20;
    if (packet.size() < MinimumIpv4HeaderSize) {
        return InnerIpv4ValidationError::TooShort;
    }
    if (packet.size() > MaxInnerIpv4PacketSize) {
        return InnerIpv4ValidationError::TooLarge;
    }
    if ((packet[0] >> 4U) != 4U) {
        return InnerIpv4ValidationError::InvalidVersion;
    }

    const std::size_t header_size = static_cast<std::size_t>(packet[0] & 0x0FU) * 4U;
    if (header_size < MinimumIpv4HeaderSize || header_size > packet.size()) {
        return InnerIpv4ValidationError::InvalidHeaderLength;
    }
    if (LoadBigEndian16(packet.data() + 2) != packet.size()) {
        return InnerIpv4ValidationError::LengthMismatch;
    }
    if (!HasValidInternetChecksum(packet.first(header_size))) {
        return InnerIpv4ValidationError::InvalidHeaderChecksum;
    }

    return InnerIpv4ValidationError::None;
}

const char *GetInnerIpv4ValidationErrorName(InnerIpv4ValidationError error) {
    switch (error) {
        case InnerIpv4ValidationError::None:
            return "none";
        case InnerIpv4ValidationError::TooShort:
            return "too_short";
        case InnerIpv4ValidationError::TooLarge:
            return "too_large";
        case InnerIpv4ValidationError::InvalidVersion:
            return "invalid_version";
        case InnerIpv4ValidationError::InvalidHeaderLength:
            return "invalid_header_length";
        case InnerIpv4ValidationError::LengthMismatch:
            return "length_mismatch";
        case InnerIpv4ValidationError::InvalidHeaderChecksum:
            return "invalid_header_checksum";
    }

    return "unknown";
}

} // namespace wgnx::wireguard
