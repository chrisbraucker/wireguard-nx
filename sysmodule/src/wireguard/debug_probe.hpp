#pragma once

#include "wgnx/protocol.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace wgnx::wireguard {

constexpr inline std::size_t DebugProbeIpv4HeaderSize = 20;
constexpr inline std::size_t DebugProbeIcmpHeaderSize = 8;
constexpr inline std::size_t DebugProbeIcmpPayloadSize = 16;
constexpr inline std::size_t DebugProbePacketSize =
    DebugProbeIpv4HeaderSize + DebugProbeIcmpHeaderSize + DebugProbeIcmpPayloadSize;

enum class DebugProbeReplyValidation : std::uint8_t {
    NotDebugReply = 0,
    InvalidIpv4,
    InvalidIcmp,
    InvalidAction,
    ActivationMismatch,
    PeerMismatch,
    DestinationMismatch,
    SourceMismatch,
    Valid,
};

struct DebugProbeReplyInfo {
    wgnx::DebugTriggerAction action{wgnx::DebugTriggerAction::None};
    std::uint32_t activation_generation{0};
    std::uint32_t peer_index{0};
    std::uint16_t sequence{0};
    std::array<std::uint8_t, 4> source_ipv4{};
    std::array<std::uint8_t, 4> destination_ipv4{};
};

bool IsSupportedDebugTriggerAction(wgnx::DebugTriggerAction action);
bool CanTransitionDebugProbeStatus(wgnx::DebugProbeStatus from, wgnx::DebugProbeStatus to);
void CopyDebugTargetIpv4(wgnx::DebugTriggerAction action, std::array<std::uint8_t, 4> &out);
void FormatIpv4Text(std::span<const std::uint8_t, 4> address, char *out, std::size_t out_size);
const char *GetDebugProbeReplyValidationName(DebugProbeReplyValidation validation);

std::size_t BuildDebugIcmpEchoRequest(
    std::span<std::uint8_t> payload,
    std::string_view source_address_text,
    wgnx::DebugTriggerAction action,
    std::uint32_t activation_generation,
    std::size_t peer_index,
    std::uint32_t random_seed);

DebugProbeReplyValidation ValidateDebugIcmpEchoReply(
    std::span<const std::uint8_t> payload,
    std::string_view local_address_text,
    std::size_t expected_peer_index,
    std::uint32_t expected_activation_generation,
    DebugProbeReplyInfo *out_info);

} // namespace wgnx::wireguard
