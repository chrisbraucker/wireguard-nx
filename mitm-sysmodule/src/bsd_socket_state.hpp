#pragma once

#include <cstdint>

namespace wgnx::mitm {

// A retained Horizon descriptor always exists, but only Direct descriptors may
// dispatch payload operations to the original BSD:S service.
enum class BsdSocketRouteState : std::uint8_t {
    Created,
    OpeningTunnel,
    Direct,
    Tunneled,
    Failed,
    Closed,
};

enum class BsdSocketRouteEvent : std::uint8_t {
    BeginTunnelOpen,
    TunnelOpened,
    TunnelBypassed,
    TunnelFailed,
    DirectConnected,
    Close,
};

[[nodiscard]] constexpr BsdSocketRouteState AdvanceBsdSocketRoute(const BsdSocketRouteState state, const BsdSocketRouteEvent event) {
    switch (event) {
    case BsdSocketRouteEvent::BeginTunnelOpen:
        return state == BsdSocketRouteState::Created ? BsdSocketRouteState::OpeningTunnel : state;
    case BsdSocketRouteEvent::TunnelOpened:
        return state == BsdSocketRouteState::OpeningTunnel ? BsdSocketRouteState::Tunneled : state;
    case BsdSocketRouteEvent::TunnelBypassed:
        return state == BsdSocketRouteState::OpeningTunnel ? BsdSocketRouteState::Created : state;
    case BsdSocketRouteEvent::TunnelFailed:
        return state == BsdSocketRouteState::OpeningTunnel ? BsdSocketRouteState::Failed : state;
    case BsdSocketRouteEvent::DirectConnected:
        return state == BsdSocketRouteState::Created ? BsdSocketRouteState::Direct : state;
    case BsdSocketRouteEvent::Close:
        return BsdSocketRouteState::Closed;
    }
    return state;
}

[[nodiscard]] constexpr const char* BsdSocketRouteStateName(const BsdSocketRouteState state) {
    switch (state) {
    case BsdSocketRouteState::Created:
        return "created";
    case BsdSocketRouteState::OpeningTunnel:
        return "opening_tunnel";
    case BsdSocketRouteState::Direct:
        return "direct";
    case BsdSocketRouteState::Tunneled:
        return "tunneled";
    case BsdSocketRouteState::Failed:
        return "failed";
    case BsdSocketRouteState::Closed:
        return "closed";
    }
    return "unknown";
}

[[nodiscard]] constexpr bool CanOpenTunnelFlow(const BsdSocketRouteState state) {
    return state == BsdSocketRouteState::Created;
}

[[nodiscard]] constexpr bool UsesTunnelFlow(const BsdSocketRouteState state) {
    return state == BsdSocketRouteState::Tunneled;
}

[[nodiscard]] constexpr bool CanForwardToUpstreamBsd(const BsdSocketRouteState state) {
    return state == BsdSocketRouteState::Created || state == BsdSocketRouteState::Direct;
}

[[nodiscard]] constexpr bool IsTerminalSocketRoute(const BsdSocketRouteState state) {
    return state == BsdSocketRouteState::Failed || state == BsdSocketRouteState::Closed;
}

} // namespace wgnx::mitm
