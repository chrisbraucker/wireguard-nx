#include "wireguard/inner_packet.hpp"

namespace wgnx::wireguard {

const char *GetQueueDispositionName(QueueDisposition disposition) {
    switch (disposition) {
        case QueueDisposition::Delivered: return "delivered";
        case QueueDisposition::Sent: return "sent";
        case QueueDisposition::Stale: return "stale";
        case QueueDisposition::Unavailable: return "unavailable";
        case QueueDisposition::SendFailed: return "send_failed";
        case QueueDisposition::RetryExhausted: return "retry_exhausted";
        case QueueDisposition::Cleared: return "cleared";
    }
    return "unknown";
}

namespace {

constexpr std::size_t MinimumIpv4HeaderSize = 20;
constexpr std::size_t Ipv6HeaderSize = 40;
constexpr std::size_t MaximumPaddingSize = 15;

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

InnerIpValidationError ValidateInnerIpv6Packet(std::span<const std::uint8_t> packet) {
    if (packet.size() < Ipv6HeaderSize) {
        return InnerIpv4ValidationError::TooShort;
    }
    if (packet.size() > MaxInnerIpPacketSize) {
        return InnerIpv4ValidationError::TooLarge;
    }
    if ((packet[0] >> 4U) != static_cast<std::uint8_t>(InnerIpVersion::Ipv6)) {
        return InnerIpv4ValidationError::InvalidVersion;
    }

    const std::size_t payload_size = LoadBigEndian16(packet.data() + 4);
    if (Ipv6HeaderSize + payload_size != packet.size()) {
        return InnerIpv4ValidationError::LengthMismatch;
    }
    return InnerIpv4ValidationError::None;
}

std::size_t GetUnpaddedPacketSize(std::span<const std::uint8_t> payload) {
    if (payload.empty()) {
        return 0;
    }
    switch (static_cast<InnerIpVersion>(payload[0] >> 4U)) {
        case InnerIpVersion::Ipv4:
            return payload.size() >= 4 ? LoadBigEndian16(payload.data() + 2) : 0;
        case InnerIpVersion::Ipv6:
            return payload.size() >= Ipv6HeaderSize
                ? Ipv6HeaderSize + LoadBigEndian16(payload.data() + 4)
                : 0;
        case InnerIpVersion::Unknown:
            return 0;
    }
    return 0;
}

} // namespace

InnerIpv4ValidationError ValidateInnerIpv4Packet(std::span<const std::uint8_t> packet) {
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

InnerIpValidationError ValidateInnerIpPacket(
    std::span<const std::uint8_t> packet,
    InnerIpVersion *out_version) {
    if (out_version != nullptr) {
        *out_version = InnerIpVersion::Unknown;
    }
    if (packet.empty()) {
        return InnerIpv4ValidationError::TooShort;
    }

    const auto version = static_cast<InnerIpVersion>(packet[0] >> 4U);
    InnerIpv4ValidationError result = InnerIpv4ValidationError::InvalidVersion;
    switch (version) {
        case InnerIpVersion::Ipv4:
            result = ValidateInnerIpv4Packet(packet);
            break;
        case InnerIpVersion::Ipv6:
            result = ValidateInnerIpv6Packet(packet);
            break;
        case InnerIpVersion::Unknown:
            break;
    }
    if (result == InnerIpv4ValidationError::None && out_version != nullptr) {
        *out_version = version;
    }
    return result;
}

InnerIpv4ValidationError ValidatePaddedInnerIpv4Packet(
    std::span<const std::uint8_t> payload,
    std::size_t *out_packet_size) {
    constexpr std::size_t MinimumIpv4HeaderSize = 20;
    constexpr std::size_t MaximumPaddingSize = 15;
    if (out_packet_size == nullptr) {
        return InnerIpv4ValidationError::LengthMismatch;
    }
    *out_packet_size = 0;

    if (payload.size() < MinimumIpv4HeaderSize) {
        return InnerIpv4ValidationError::TooShort;
    }

    const std::size_t packet_size = LoadBigEndian16(payload.data() + 2);
    if (packet_size < MinimumIpv4HeaderSize) {
        return InnerIpv4ValidationError::LengthMismatch;
    }
    if (packet_size > MaxInnerIpv4PacketSize) {
        return InnerIpv4ValidationError::TooLarge;
    }
    if (packet_size > payload.size()) {
        return InnerIpv4ValidationError::LengthMismatch;
    }

    const std::size_t padding_size = payload.size() - packet_size;
    if (padding_size > MaximumPaddingSize) {
        return InnerIpv4ValidationError::InvalidPadding;
    }
    for (const std::uint8_t byte : payload.subspan(packet_size)) {
        if (byte != 0) {
            return InnerIpv4ValidationError::InvalidPadding;
        }
    }

    const auto validation = ValidateInnerIpv4Packet(payload.first(packet_size));
    if (validation != InnerIpv4ValidationError::None) {
        return validation;
    }

    *out_packet_size = packet_size;
    return InnerIpv4ValidationError::None;
}

InnerIpValidationError ValidatePaddedInnerIpPacket(
    std::span<const std::uint8_t> payload,
    std::size_t *out_packet_size,
    InnerIpVersion *out_version) {
    if (out_packet_size == nullptr) {
        return InnerIpv4ValidationError::LengthMismatch;
    }
    *out_packet_size = 0;
    if (out_version != nullptr) {
        *out_version = InnerIpVersion::Unknown;
    }
    if (payload.empty()) {
        return InnerIpv4ValidationError::TooShort;
    }

    switch (static_cast<InnerIpVersion>(payload[0] >> 4U)) {
        case InnerIpVersion::Ipv4:
            if (payload.size() < MinimumIpv4HeaderSize) {
                return InnerIpValidationError::TooShort;
            }
            break;
        case InnerIpVersion::Ipv6:
            if (payload.size() < Ipv6HeaderSize) {
                return InnerIpValidationError::TooShort;
            }
            break;
        case InnerIpVersion::Unknown:
            return InnerIpValidationError::InvalidVersion;
        default:
            return InnerIpValidationError::InvalidVersion;
    }

    const std::size_t packet_size = GetUnpaddedPacketSize(payload);
    if (packet_size == 0) {
        return InnerIpv4ValidationError::LengthMismatch;
    }
    if (packet_size > MaxInnerIpPacketSize) {
        return InnerIpv4ValidationError::TooLarge;
    }
    if (packet_size > payload.size()) {
        return InnerIpv4ValidationError::LengthMismatch;
    }
    if (payload.size() - packet_size > MaximumPaddingSize) {
        return InnerIpv4ValidationError::InvalidPadding;
    }
    for (const std::uint8_t byte : payload.subspan(packet_size)) {
        if (byte != 0) {
            return InnerIpv4ValidationError::InvalidPadding;
        }
    }

    const auto validation = ValidateInnerIpPacket(payload.first(packet_size), out_version);
    if (validation != InnerIpv4ValidationError::None) {
        return validation;
    }
    *out_packet_size = packet_size;
    return InnerIpv4ValidationError::None;
}

const char *GetInnerIpValidationErrorName(InnerIpValidationError error) {
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
        case InnerIpv4ValidationError::InvalidPadding:
            return "invalid_padding";
    }

    return "unknown";
}

} // namespace wgnx::wireguard
