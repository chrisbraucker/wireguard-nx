#pragma once

#include "wgnx/tunnel_protocol.hpp"

#include <cstdint>

namespace wgnx::mitm {

enum class TunnelOpenDisposition : std::uint8_t {
    Tunnel,
    Direct,
    Blocked,
    Error,
};

[[nodiscard]] constexpr TunnelOpenDisposition ClassifyTunnelOpenStatus(wgnx::tunnel::ProtocolStatus status) {
    switch (status) {
    case wgnx::tunnel::ProtocolStatus::Success:
        return TunnelOpenDisposition::Tunnel;
    case wgnx::tunnel::ProtocolStatus::RouteNotCovered:
    case wgnx::tunnel::ProtocolStatus::PeerUnavailable:
    case wgnx::tunnel::ProtocolStatus::TransportUnavailable:
        return TunnelOpenDisposition::Direct;
    case wgnx::tunnel::ProtocolStatus::TunnelBlockedByPolicy:
        return TunnelOpenDisposition::Blocked;
    default:
        return TunnelOpenDisposition::Error;
    }
}

} // namespace wgnx::mitm
