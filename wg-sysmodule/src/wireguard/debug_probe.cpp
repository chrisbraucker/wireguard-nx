#include "wireguard/debug_probe.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>

namespace wgnx::wireguard {

namespace {

constexpr std::array<std::uint8_t, 4> DebugTunnelPeerIpv4 = {10, 13, 13, 1};
constexpr std::array<std::uint8_t, 4> DebugPublicDnsIpv4 = {1, 1, 1, 1};

void StoreBigEndian16(std::uint8_t* dst, std::uint16_t value) {
    if (dst == nullptr) {
        return;
    }

    dst[0] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
    dst[1] = static_cast<std::uint8_t>(value & 0xFFu);
}

void StoreBigEndian32(std::uint8_t* dst, std::uint32_t value) {
    if (dst == nullptr) {
        return;
    }

    dst[0] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
    dst[1] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
    dst[2] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
    dst[3] = static_cast<std::uint8_t>(value & 0xFFu);
}

std::uint16_t ComputeInternetChecksum(const std::uint8_t* data, std::size_t size) {
    std::uint32_t sum = 0;
    std::size_t index = 0;
    while ((index + 1) < size) {
        sum += (static_cast<std::uint32_t>(data[index]) << 8) | static_cast<std::uint32_t>(data[index + 1]);
        index += 2;
    }

    if (index < size) {
        sum += static_cast<std::uint32_t>(data[index]) << 8;
    }

    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    return static_cast<std::uint16_t>(~sum & 0xFFFFu);
}

bool ParseIpv4InterfaceAddress(std::array<std::uint8_t, 4>& out, std::string_view address_text) {
    if (address_text.empty()) {
        return false;
    }

    std::array<char, 48> address_copy{};
    const std::size_t copy_size = std::min(address_text.size(), address_copy.size() - 1);
    std::memcpy(address_copy.data(), address_text.data(), copy_size);
    if (char* slash = std::strchr(address_copy.data(), '/'); slash != nullptr) {
        *slash = '\0';
    }

    return ::inet_pton(AF_INET, address_copy.data(), out.data()) == 1;
}

} // namespace

bool IsSupportedDebugTriggerAction(wgnx::DebugTriggerAction action) {
    switch (action) {
    case wgnx::DebugTriggerAction::PingTunnelPeer:
    case wgnx::DebugTriggerAction::PingPublicDns:
        return true;
    case wgnx::DebugTriggerAction::None:
        return false;
    }

    return false;
}

bool CanTransitionDebugProbeStatus(wgnx::DebugProbeStatus from, wgnx::DebugProbeStatus to) {
    switch (to) {
    case wgnx::DebugProbeStatus::None:
        return true;
    case wgnx::DebugProbeStatus::Queued:
        return from == wgnx::DebugProbeStatus::None || from == wgnx::DebugProbeStatus::ReplyValidated ||
               from == wgnx::DebugProbeStatus::ReplyRejected || from == wgnx::DebugProbeStatus::TimedOut ||
               from == wgnx::DebugProbeStatus::StaleActivation || from == wgnx::DebugProbeStatus::InvalidState ||
               from == wgnx::DebugProbeStatus::BuildFailed || from == wgnx::DebugProbeStatus::SendFailed;
    case wgnx::DebugProbeStatus::Sent:
    case wgnx::DebugProbeStatus::BuildFailed:
    case wgnx::DebugProbeStatus::SendFailed:
    case wgnx::DebugProbeStatus::StaleActivation:
    case wgnx::DebugProbeStatus::InvalidState:
        return from == wgnx::DebugProbeStatus::Queued;
    case wgnx::DebugProbeStatus::ReplyValidated:
    case wgnx::DebugProbeStatus::ReplyRejected:
    case wgnx::DebugProbeStatus::TimedOut:
        return from == wgnx::DebugProbeStatus::Sent;
    }

    return false;
}

void CopyDebugTargetIpv4(wgnx::DebugTriggerAction action, std::array<std::uint8_t, 4>& out) {
    switch (action) {
    case wgnx::DebugTriggerAction::PingTunnelPeer:
        out = DebugTunnelPeerIpv4;
        return;
    case wgnx::DebugTriggerAction::PingPublicDns:
        out = DebugPublicDnsIpv4;
        return;
    case wgnx::DebugTriggerAction::None:
        break;
    }

    out.fill(0);
}

void FormatIpv4Text(std::span<const std::uint8_t, 4> address, char* out, std::size_t out_size) {
    if (out == nullptr || out_size == 0) {
        return;
    }

    std::snprintf(out, out_size, "%u.%u.%u.%u", static_cast<unsigned int>(address[0]), static_cast<unsigned int>(address[1]),
                  static_cast<unsigned int>(address[2]), static_cast<unsigned int>(address[3]));
}

const char* GetDebugProbeReplyValidationName(DebugProbeReplyValidation validation) {
    switch (validation) {
    case DebugProbeReplyValidation::NotDebugReply:
        return "not_debug_reply";
    case DebugProbeReplyValidation::InvalidIpv4:
        return "invalid_ipv4";
    case DebugProbeReplyValidation::InvalidIcmp:
        return "invalid_icmp";
    case DebugProbeReplyValidation::InvalidAction:
        return "invalid_action";
    case DebugProbeReplyValidation::ActivationMismatch:
        return "activation_mismatch";
    case DebugProbeReplyValidation::PeerMismatch:
        return "peer_mismatch";
    case DebugProbeReplyValidation::DestinationMismatch:
        return "destination_mismatch";
    case DebugProbeReplyValidation::SourceMismatch:
        return "source_mismatch";
    case DebugProbeReplyValidation::Valid:
        return "valid";
    }

    return "unknown";
}

std::size_t BuildDebugIcmpEchoRequest(std::span<std::uint8_t> payload, std::string_view source_address_text,
                                      wgnx::DebugTriggerAction action, std::uint32_t activation_generation, std::size_t peer_index,
                                      std::uint32_t random_seed) {
    if (payload.size() < DebugProbePacketSize || !IsSupportedDebugTriggerAction(action)) {
        return 0;
    }

    std::array<std::uint8_t, 4> source_ipv4{};
    if (!ParseIpv4InterfaceAddress(source_ipv4, source_address_text)) {
        return 0;
    }

    std::array<std::uint8_t, 4> destination_ipv4{};
    CopyDebugTargetIpv4(action, destination_ipv4);

    payload = payload.first(DebugProbePacketSize);
    std::fill(payload.begin(), payload.end(), std::uint8_t{0});
    payload[0] = 0x45;
    payload[1] = 0x00;
    StoreBigEndian16(payload.data() + 2, static_cast<std::uint16_t>(DebugProbePacketSize));
    StoreBigEndian16(payload.data() + 4, static_cast<std::uint16_t>(random_seed & 0xFFFFu));
    StoreBigEndian16(payload.data() + 6, 0x4000u);
    payload[8] = 64;
    payload[9] = 1;
    std::memcpy(payload.data() + 12, source_ipv4.data(), source_ipv4.size());
    std::memcpy(payload.data() + 16, destination_ipv4.data(), destination_ipv4.size());
    StoreBigEndian16(payload.data() + 10, ComputeInternetChecksum(payload.data(), DebugProbeIpv4HeaderSize));

    std::uint8_t* icmp = payload.data() + DebugProbeIpv4HeaderSize;
    icmp[0] = 8;
    icmp[1] = 0;
    StoreBigEndian16(icmp + 4, static_cast<std::uint16_t>((random_seed >> 16) & 0xFFFFu));
    StoreBigEndian16(icmp + 6, static_cast<std::uint16_t>(activation_generation & 0xFFFFu));

    std::uint8_t* icmp_payload = icmp + DebugProbeIcmpHeaderSize;
    icmp_payload[0] = 'W';
    icmp_payload[1] = 'G';
    icmp_payload[2] = 'N';
    icmp_payload[3] = 'X';
    StoreBigEndian32(icmp_payload + 4, static_cast<std::uint32_t>(action));
    StoreBigEndian32(icmp_payload + 8, activation_generation);
    StoreBigEndian32(icmp_payload + 12, static_cast<std::uint32_t>(peer_index));
    StoreBigEndian16(icmp + 2, ComputeInternetChecksum(icmp, DebugProbeIcmpHeaderSize + DebugProbeIcmpPayloadSize));

    return DebugProbePacketSize;
}

DebugProbeReplyValidation ValidateDebugIcmpEchoReply(std::span<const std::uint8_t> payload, std::string_view local_address_text,
                                                     std::size_t expected_peer_index, std::uint32_t expected_activation_generation,
                                                     DebugProbeReplyInfo* out_info) {
    if (out_info != nullptr) {
        *out_info = {};
    }
    if (payload.size() < (DebugProbeIpv4HeaderSize + DebugProbeIcmpHeaderSize)) {
        return DebugProbeReplyValidation::NotDebugReply;
    }

    const std::uint8_t version = payload[0] >> 4;
    const std::size_t ihl = static_cast<std::size_t>(payload[0] & 0x0Fu) * 4;
    if (version != 4) {
        return DebugProbeReplyValidation::NotDebugReply;
    }
    if (ihl < DebugProbeIpv4HeaderSize || payload.size() < ihl || ComputeInternetChecksum(payload.data(), ihl) != 0) {
        return DebugProbeReplyValidation::InvalidIpv4;
    }

    const std::uint16_t total_length = (static_cast<std::uint16_t>(payload[2]) << 8) | static_cast<std::uint16_t>(payload[3]);
    if (total_length < (ihl + DebugProbeIcmpHeaderSize) || total_length > payload.size()) {
        return DebugProbeReplyValidation::InvalidIpv4;
    }
    if (payload[9] != 1) {
        return DebugProbeReplyValidation::NotDebugReply;
    }

    const std::uint8_t* icmp = payload.data() + ihl;
    const std::size_t icmp_size = total_length - ihl;
    if (icmp_size < (DebugProbeIcmpHeaderSize + DebugProbeIcmpPayloadSize) || ComputeInternetChecksum(icmp, icmp_size) != 0) {
        return DebugProbeReplyValidation::InvalidIcmp;
    }
    if (icmp[0] != 0 || icmp[1] != 0) {
        return DebugProbeReplyValidation::NotDebugReply;
    }

    const std::uint8_t* icmp_payload = icmp + DebugProbeIcmpHeaderSize;
    if (std::memcmp(icmp_payload, "WGNX", 4) != 0) {
        return DebugProbeReplyValidation::NotDebugReply;
    }

    const std::uint32_t encoded_action = (static_cast<std::uint32_t>(icmp_payload[4]) << 24) |
                                         (static_cast<std::uint32_t>(icmp_payload[5]) << 16) |
                                         (static_cast<std::uint32_t>(icmp_payload[6]) << 8) | static_cast<std::uint32_t>(icmp_payload[7]);
    const auto action = static_cast<wgnx::DebugTriggerAction>(encoded_action);
    if (!IsSupportedDebugTriggerAction(action)) {
        return DebugProbeReplyValidation::InvalidAction;
    }

    const std::uint32_t activation_generation =
        (static_cast<std::uint32_t>(icmp_payload[8]) << 24) | (static_cast<std::uint32_t>(icmp_payload[9]) << 16) |
        (static_cast<std::uint32_t>(icmp_payload[10]) << 8) | static_cast<std::uint32_t>(icmp_payload[11]);
    if (activation_generation != expected_activation_generation) {
        return DebugProbeReplyValidation::ActivationMismatch;
    }

    const std::uint32_t peer_index = (static_cast<std::uint32_t>(icmp_payload[12]) << 24) |
                                     (static_cast<std::uint32_t>(icmp_payload[13]) << 16) |
                                     (static_cast<std::uint32_t>(icmp_payload[14]) << 8) | static_cast<std::uint32_t>(icmp_payload[15]);
    if (peer_index != expected_peer_index) {
        return DebugProbeReplyValidation::PeerMismatch;
    }

    std::array<std::uint8_t, 4> expected_destination{};
    if (!ParseIpv4InterfaceAddress(expected_destination, local_address_text)) {
        return DebugProbeReplyValidation::DestinationMismatch;
    }
    if (std::memcmp(payload.data() + 16, expected_destination.data(), expected_destination.size()) != 0) {
        return DebugProbeReplyValidation::DestinationMismatch;
    }

    std::array<std::uint8_t, 4> expected_source{};
    CopyDebugTargetIpv4(action, expected_source);
    if (std::memcmp(payload.data() + 12, expected_source.data(), expected_source.size()) != 0) {
        return DebugProbeReplyValidation::SourceMismatch;
    }

    if (out_info != nullptr) {
        out_info->action = action;
        out_info->activation_generation = activation_generation;
        out_info->peer_index = peer_index;
        out_info->sequence = (static_cast<std::uint16_t>(icmp[6]) << 8) | static_cast<std::uint16_t>(icmp[7]);
        std::memcpy(out_info->source_ipv4.data(), payload.data() + 12, out_info->source_ipv4.size());
        std::memcpy(out_info->destination_ipv4.data(), payload.data() + 16, out_info->destination_ipv4.size());
    }

    return DebugProbeReplyValidation::Valid;
}

} // namespace wgnx::wireguard
