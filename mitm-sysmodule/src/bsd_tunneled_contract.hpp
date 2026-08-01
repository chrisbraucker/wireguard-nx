#pragma once

#include "tunnel_flow_result.hpp"

#include <poll.h>

#include <cstdint>

namespace wgnx::mitm {

constexpr std::int32_t BsdFcntlGetFl = 3;
constexpr std::int32_t BsdFcntlSetFl = 4;
// BSD:S returns Linux-numbered errno values on its CMIF wire.
constexpr std::int32_t BsdErrnoIo = 5;
constexpr std::int32_t BsdErrnoAgain = 11;
constexpr std::int32_t BsdErrnoInvalid = 22;
constexpr std::int32_t BsdErrnoMessageSize = 90;
constexpr std::int32_t BsdErrnoOperationNotSupported = 95;
constexpr std::int32_t BsdErrnoNetworkUnreachable = 101;
constexpr std::int32_t BsdErrnoConnectionAborted = 103;
constexpr std::int32_t BsdErrnoIsConnected = 106;
constexpr std::int32_t BsdErrnoAlready = 114;
// Horizon BSD:S encodes O_NONBLOCK as 0x800 on the CMIF wire.
// Do not substitute the sysmodule toolchain's O_NONBLOCK macro here because its ABI value differs.
constexpr std::int32_t BsdFcntlNonBlock = 0x800;
constexpr short BsdTunneledPollEvents = POLLIN | POLLOUT;

[[nodiscard]] constexpr std::int32_t ErrnoForResult(const TunnelFlowResult result) {
    switch (result) {
    case TunnelFlowResult::QueueFull:
    case TunnelFlowResult::WouldBlock:
        return BsdErrnoAgain;
    case TunnelFlowResult::Closed:
        return BsdErrnoConnectionAborted;
    case TunnelFlowResult::SocketError:
        return BsdErrnoIo;
    case TunnelFlowResult::MessageTooLarge:
        return BsdErrnoMessageSize;
    case TunnelFlowResult::BlockedByPolicy:
        return BsdErrnoNetworkUnreachable;
    case TunnelFlowResult::RouteNotCovered:
    case TunnelFlowResult::TunnelUnavailable:
    case TunnelFlowResult::Opened:
        return 0;
    }
    return BsdErrnoIo;
}

[[nodiscard]] constexpr std::int32_t TunneledPollErrno(const TunnelFlowResult result) {
    switch (result) {
    case TunnelFlowResult::Opened:
    case TunnelFlowResult::WouldBlock:
    case TunnelFlowResult::Closed:
        return 0;
    case TunnelFlowResult::QueueFull:
        return BsdErrnoAgain;
    default:
        return BsdErrnoIo;
    }
}

[[nodiscard]] constexpr bool SupportsTunneledMessageFlags(const std::int32_t flags) {
    return flags == 0;
}

[[nodiscard]] constexpr bool SupportsTunneledPoll(const std::int32_t descriptor_count, const short events) {
    return descriptor_count == 1 && (events & static_cast<short>(~BsdTunneledPollEvents)) == 0;
}

[[nodiscard]] constexpr bool SupportsTunneledFcntl(const std::int32_t command, const std::int32_t value) {
    switch (command) {
    case BsdFcntlGetFl:
        return value == 0;
    case BsdFcntlSetFl:
        return value == BsdFcntlNonBlock;
    default:
        return false;
    }
}

[[nodiscard]] constexpr std::int32_t TunneledFcntlResult(const std::int32_t command) {
    return command == BsdFcntlGetFl ? BsdFcntlNonBlock : 0;
}

} // namespace wgnx::mitm
