#pragma once

#include <poll.h>

#include <cstdint>

namespace wgnx::mitm {

constexpr std::int32_t BsdFcntlGetFl = 3;
constexpr std::int32_t BsdFcntlSetFl = 4;
// Horizon BSD:S encodes O_NONBLOCK as 0x800 on the CMIF wire.
// Do not substitute the sysmodule toolchain's O_NONBLOCK macro here because its ABI value differs.
constexpr std::int32_t BsdFcntlNonBlock = 0x800;
constexpr short BsdTunneledPollEvents = POLLIN | POLLOUT;

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
