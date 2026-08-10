#include "wireguard/inner_packet.hpp"

#include <algorithm>

namespace wgnx::wireguard {

const char* GetQueueDispositionName(QueueDisposition disposition) {
    switch (disposition) {
    case QueueDisposition::Delivered:
        return "delivered";
    case QueueDisposition::Sent:
        return "sent";
    case QueueDisposition::Stale:
        return "stale";
    case QueueDisposition::Unavailable:
        return "unavailable";
    case QueueDisposition::SendFailed:
        return "send_failed";
    case QueueDisposition::RetryExhausted:
        return "retry_exhausted";
    case QueueDisposition::Cleared:
        return "cleared";
    }
    return "unknown";
}

namespace {

constexpr std::size_t MinimumIpv4HeaderSize = 20;
constexpr std::size_t MinimumTcpHeaderSize = 20;
constexpr std::size_t Ipv6HeaderSize = 40;
constexpr std::size_t MaximumPaddingSize = 15;
constexpr std::uint8_t Ipv4TcpProtocol = 6;

struct AllowedIp {
    std::array<std::uint8_t, 16> address{};
    std::uint8_t size{};
    std::uint8_t prefix{};
};

std::uint16_t LoadBigEndian16(const std::uint8_t* value) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(value[0]) << 8U) | static_cast<std::uint16_t>(value[1]));
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
        return payload.size() >= Ipv6HeaderSize ? Ipv6HeaderSize + LoadBigEndian16(payload.data() + 4) : 0;
    case InnerIpVersion::Unknown:
        return 0;
    }
    return 0;
}

std::string_view Trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return value;
}

bool ParseDecimal(std::string_view value, unsigned int maximum, unsigned int* out) {
    if (out == nullptr || value.empty()) {
        return false;
    }
    unsigned int parsed = 0;
    for (const char character : value) {
        if (character < '0' || character > '9') {
            return false;
        }
        parsed = (parsed * 10U) + static_cast<unsigned int>(character - '0');
        if (parsed > maximum) {
            return false;
        }
    }
    *out = parsed;
    return true;
}

bool ParseIpv4Address(std::string_view value, std::uint8_t* out) {
    if (out == nullptr) {
        return false;
    }
    std::size_t offset = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        const std::size_t delimiter = value.find('.', offset);
        const std::string_view component = value.substr(offset, delimiter == std::string_view::npos ? delimiter : delimiter - offset);
        unsigned int parsed = 0;
        if (!ParseDecimal(component, 255, &parsed)) {
            return false;
        }
        out[index] = static_cast<std::uint8_t>(parsed);
        if (index == 3) {
            return delimiter == std::string_view::npos;
        }
        if (delimiter == std::string_view::npos) {
            return false;
        }
        offset = delimiter + 1;
    }
    return false;
}

bool ParseIpv6Address(std::string_view value, std::uint8_t* out) {
    if (out == nullptr || value.empty()) {
        return false;
    }
    std::array<std::uint16_t, 8> words{};
    std::size_t word_count = 0;
    std::size_t compressed_at = words.size();
    std::size_t offset = 0;
    if (value.front() == ':') {
        if (value.size() < 2 || value[1] != ':') {
            return false;
        }
        compressed_at = 0;
        offset = 2;
    }
    while (offset < value.size()) {
        if (word_count == words.size()) {
            return false;
        }
        const std::size_t delimiter = value.find(':', offset);
        const std::string_view component = value.substr(offset, delimiter == std::string_view::npos ? delimiter : delimiter - offset);
        if (component.empty() || component.size() > 4) {
            return false;
        }
        unsigned int parsed = 0;
        for (const char character : component) {
            const unsigned int digit = character >= '0' && character <= '9'   ? static_cast<unsigned int>(character - '0')
                                       : character >= 'a' && character <= 'f' ? static_cast<unsigned int>(character - 'a' + 10)
                                       : character >= 'A' && character <= 'F' ? static_cast<unsigned int>(character - 'A' + 10)
                                                                              : 16U;
            if (digit == 16U) {
                return false;
            }
            parsed = (parsed << 4U) | digit;
        }
        words[word_count++] = static_cast<std::uint16_t>(parsed);
        if (delimiter == std::string_view::npos) {
            break;
        }
        if (delimiter + 1 < value.size() && value[delimiter + 1] == ':') {
            if (compressed_at != words.size()) {
                return false;
            }
            compressed_at = word_count;
            offset = delimiter + 2;
            continue;
        }
        offset = delimiter + 1;
    }
    if (compressed_at == words.size()) {
        if (word_count != words.size()) {
            return false;
        }
    } else {
        if (word_count >= words.size()) {
            return false;
        }
        std::move_backward(
            words.begin() + static_cast<std::ptrdiff_t>(compressed_at),
            words.begin() + static_cast<std::ptrdiff_t>(word_count),
            words.end()
        );
        std::fill(
            words.begin() + static_cast<std::ptrdiff_t>(compressed_at),
            words.end() - static_cast<std::ptrdiff_t>(word_count - compressed_at),
            0
        );
    }
    for (std::size_t index = 0; index < words.size(); ++index) {
        out[index * 2] = static_cast<std::uint8_t>(words[index] >> 8U);
        out[(index * 2) + 1] = static_cast<std::uint8_t>(words[index] & 0xFFU);
    }
    return true;
}

bool ParseAllowedIp(std::string_view value, AllowedIp* out) {
    if (out == nullptr) {
        return false;
    }
    const std::size_t slash = value.rfind('/');
    if (slash == std::string_view::npos || slash == 0 || slash + 1 == value.size()) {
        return false;
    }
    const std::string_view address = Trim(value.substr(0, slash));
    const bool ipv6 = address.find(':') != std::string_view::npos;
    unsigned int prefix = 0;
    if (!ParseDecimal(Trim(value.substr(slash + 1)), ipv6 ? 128U : 32U, &prefix)) {
        return false;
    }
    *out = {};
    out->size = static_cast<std::uint8_t>(ipv6 ? 16 : 4);
    out->prefix = static_cast<std::uint8_t>(prefix);
    return ipv6 ? ParseIpv6Address(address, out->address.data()) : ParseIpv4Address(address, out->address.data());
}

bool PrefixMatches(const AllowedIp& allowed, const std::uint8_t* source, std::size_t source_size) {
    if (source == nullptr || allowed.size != source_size) {
        return false;
    }
    const std::size_t full_bytes = allowed.prefix / 8U;
    if (!std::equal(allowed.address.begin(), allowed.address.begin() + static_cast<std::ptrdiff_t>(full_bytes), source)) {
        return false;
    }
    const std::size_t remaining_bits = allowed.prefix % 8U;
    if (remaining_bits == 0) {
        return true;
    }
    const std::uint8_t mask = static_cast<std::uint8_t>(0xFFU << (8U - remaining_bits));
    return (allowed.address[full_bytes] & mask) == (source[full_bytes] & mask);
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

bool ParseInnerIpv4TcpTuple(std::span<const std::uint8_t> packet, InnerIpv4TcpTuple* out) {
    if (out == nullptr || ValidateInnerIpv4Packet(packet) != InnerIpv4ValidationError::None) {
        return false;
    }
    const std::size_t ipv4_header_size = static_cast<std::size_t>(packet[0] & 0x0FU) * 4U;
    const std::uint16_t fragment = LoadBigEndian16(packet.data() + 6);
    if (packet[9] != Ipv4TcpProtocol || (fragment & 0x3FFFU) != 0 || packet.size() < ipv4_header_size + MinimumTcpHeaderSize) {
        return false;
    }
    const std::size_t tcp_header_size = static_cast<std::size_t>(packet[ipv4_header_size + 12] >> 4U) * 4U;
    if (tcp_header_size < MinimumTcpHeaderSize || packet.size() < ipv4_header_size + tcp_header_size) {
        return false;
    }
    *out = {
        .source_address = {packet[12], packet[13], packet[14], packet[15]},
        .destination_address = {packet[16], packet[17], packet[18], packet[19]},
        .source_port = LoadBigEndian16(packet.data() + ipv4_header_size),
        .destination_port = LoadBigEndian16(packet.data() + ipv4_header_size + 2),
    };
    return true;
}

InnerIpValidationError ValidateInnerIpPacket(std::span<const std::uint8_t> packet, InnerIpVersion* out_version) {
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

InnerIpv4ValidationError ValidatePaddedInnerIpv4Packet(std::span<const std::uint8_t> payload, std::size_t* out_packet_size) {
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
    std::span<const std::uint8_t> payload, std::size_t* out_packet_size, InnerIpVersion* out_version
) {
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

bool AllowedIpsContainSource(std::span<const std::uint8_t> packet, std::string_view allowed_ips) {
    InnerIpVersion version = InnerIpVersion::Unknown;
    if (ValidateInnerIpPacket(packet, &version) != InnerIpValidationError::None) {
        return false;
    }
    const std::uint8_t* source = version == InnerIpVersion::Ipv4 ? packet.data() + 12 : packet.data() + 8;
    const std::size_t source_size = version == InnerIpVersion::Ipv4 ? 4 : 16;
    while (!allowed_ips.empty()) {
        const std::size_t delimiter = allowed_ips.find(',');
        const std::string_view item = Trim(allowed_ips.substr(0, delimiter));
        AllowedIp allowed{};
        if (ParseAllowedIp(item, &allowed) && PrefixMatches(allowed, source, source_size)) {
            return true;
        }
        if (delimiter == std::string_view::npos) {
            break;
        }
        allowed_ips.remove_prefix(delimiter + 1);
    }
    return false;
}

const char* GetInnerIpValidationErrorName(InnerIpValidationError error) {
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
