#pragma once

#include <cstdint>

namespace wgnx::mitm {

constexpr inline std::uint64_t WireGuardProgramId = 0x010000000000EAD0ULL;
constexpr inline std::uint64_t MitmProgramId = 0x010000000000EAD3ULL;

enum class BsdSystemClient : std::uint8_t {
    Unknown,
    Npns,
    Eupld,
    Olsc,
    BsdSockets,
    Ssl,
    Nim,
    SphairaForwarder,
    RequesterForwarder,
};

constexpr std::uint32_t BsdSystemClientMask(BsdSystemClient client) {
    switch (client) {
    case BsdSystemClient::Npns:
    case BsdSystemClient::Eupld:
    case BsdSystemClient::Olsc:
    case BsdSystemClient::BsdSockets:
    case BsdSystemClient::Ssl:
    case BsdSystemClient::Nim:
    case BsdSystemClient::SphairaForwarder:
    case BsdSystemClient::RequesterForwarder:
        return 1U << (static_cast<std::uint32_t>(client) - 1U);
    case BsdSystemClient::Unknown:
        return 0;
    }

    return 0;
}

constexpr bool IsConfigurableBsdSystemClient(std::uint32_t client) {
    return client >= static_cast<std::uint32_t>(BsdSystemClient::Npns) &&
           client <= static_cast<std::uint32_t>(BsdSystemClient::RequesterForwarder);
}

struct BsdSystemPolicy {
    bool enabled{false};
    std::uint32_t enabled_client_mask{0};
};

constexpr bool IsProgramExcludedFromBsdSystemMitm(std::uint64_t program_id) {
    return program_id == WireGuardProgramId || program_id == MitmProgramId;
}

constexpr bool IsBsdSystemClientEnabled(const BsdSystemPolicy& policy, BsdSystemClient client) {
    const std::uint32_t mask = BsdSystemClientMask(client);
    if (mask == 0) {
        return true;
    }

    return (policy.enabled_client_mask & mask) != 0;
}

constexpr bool SetBsdSystemClientEnabled(BsdSystemPolicy& policy, BsdSystemClient client, bool enabled) {
    const std::uint32_t mask = BsdSystemClientMask(client);
    if (mask == 0) {
        return false;
    }

    if (enabled) {
        policy.enabled_client_mask |= mask;
    } else {
        policy.enabled_client_mask &= ~mask;
    }

    return true;
}

constexpr bool ShouldInterceptBsdSystem(const BsdSystemPolicy& policy, std::uint64_t program_id, BsdSystemClient client) {
    return policy.enabled && !IsProgramExcludedFromBsdSystemMitm(program_id) && IsBsdSystemClientEnabled(policy, client);
}

} // namespace wgnx::mitm
