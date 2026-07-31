#pragma once

#include <cstdint>

namespace wgnx::mitm {

enum class TunnelFlowResult : std::uint8_t {
    Opened,
    RouteNotCovered,
    TunnelUnavailable,
    BlockedByPolicy,
    SocketError,
    MessageTooLarge,
    QueueFull,
    WouldBlock,
    Closed,
};

} // namespace wgnx::mitm
