#pragma once

#include "wgnx/protocol.hpp"

#include <cstdint>

namespace wgnx::sysmodule::runtime {

constexpr bool IsValidPeerSelection(std::int32_t peer_index, std::uint32_t peer_count) {
    return peer_index >= -1 && peer_index < static_cast<std::int32_t>(peer_count);
}

constexpr std::uint32_t BuildDaemonFlags(bool has_active_peer, bool has_runtime_errors) {
    return wgnx::DaemonFlag_Ready |
           (has_active_peer ? wgnx::DaemonFlag_TunnelActive : 0U) |
           (has_runtime_errors ? wgnx::DaemonFlag_HasErrors : 0U);
}

constexpr std::uint8_t BuildPeerFlags(
    bool is_active,
    bool is_auto_start,
    bool is_established,
    wgnx::PeerRuntimeState runtime_state,
    bool has_resolved_endpoint) {
    const auto flag = [](wgnx::PeerFlags value) {
        return static_cast<std::uint8_t>(value);
    };
    return static_cast<std::uint8_t>(
        (is_active ? flag(wgnx::PeerFlag_Active) : 0U) |
        (is_auto_start ? flag(wgnx::PeerFlag_AutoStart) : 0U) |
        (is_established ? flag(wgnx::PeerFlag_Established) : 0U) |
        (runtime_state == wgnx::PeerRuntimeState::Error ? flag(wgnx::PeerFlag_HasError) : 0U) |
        (has_resolved_endpoint ? flag(wgnx::PeerFlag_HasResolvedEndpoint) : 0U));
}

constexpr bool IsCurrentGeneration(std::uint32_t expected, std::uint32_t observed) {
    return expected != 0 && expected == observed;
}

} // namespace wgnx::sysmodule::runtime
