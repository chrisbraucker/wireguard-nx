#pragma once

#include "build_config.hpp"

#include <cstdint>

#if defined(__SWITCH__)
#include <stratosphere.hpp>
#endif

namespace wgnx::mitm {

#if defined(__SWITCH__)
using ProgramId = ams::ncm::ProgramId;
#else
struct ProgramId {
    std::uint64_t value{};

    constexpr auto operator<=>(const ProgramId&) const = default;
};
#endif

constexpr inline ProgramId WireGuardProgramId{0x010000000000EAD0ULL};
constexpr inline ProgramId MitmProgramId{0x010000000000EAD3ULL};
constexpr inline ProgramId ToolboxForwarderProgramId{build_config::ToolboxForwarderProgramId};

enum class BsdSystemClient : std::uint8_t {
    Unknown,
    Npns,
    Eupld,
    Olsc,
    BsdSockets,
    Ssl,
    Nim,
    SphairaForwarder,
    ToolboxForwarder,
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
    case BsdSystemClient::ToolboxForwarder:
        return 1U << (static_cast<std::uint32_t>(client) - 1U);
    case BsdSystemClient::Unknown:
        return 0;
    }

    return 0;
}

constexpr bool IsConfigurableBsdSystemClient(std::uint32_t client) {
    return client >= static_cast<std::uint32_t>(BsdSystemClient::Npns) &&
           client <= static_cast<std::uint32_t>(BsdSystemClient::ToolboxForwarder);
}

struct BsdSystemPolicy {
    bool enabled{false};
    std::uint32_t enabled_client_mask{0};
};

constexpr bool IsProgramExcludedFromBsdSystemMitm(ProgramId program_id) {
    return program_id == WireGuardProgramId || program_id == MitmProgramId;
}

constexpr bool IsToolboxForwarderProgram(ProgramId program_id) {
    return program_id == ToolboxForwarderProgramId;
}

// SM asks whether to MITM a service acquisition before the first CMIF command
// is available, so RegisterClient and StartMonitoring cannot safely select a
// session here. The Toolbox-only experiment admits every Toolbox bsd:s
// session and forwards lifecycle-only sessions through the generic path.
constexpr bool ShouldInterceptToolboxBsdSession() {
    return true;
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

constexpr bool ShouldInterceptBsdSystem(const BsdSystemPolicy& policy, ProgramId program_id, BsdSystemClient client) {
    return policy.enabled && !IsProgramExcludedFromBsdSystemMitm(program_id) && IsBsdSystemClientEnabled(policy, client);
}

} // namespace wgnx::mitm
