#pragma once

#include <poll.h>

namespace wgnx::mitm {

struct TunnelFlowReadiness {
    bool inbound_available{};
    bool writable{};
    bool closed{};

    [[nodiscard]] short Revents(const short requested_events) const {
        if (closed) {
            return POLLHUP;
        }

        short revents = 0;
        if (inbound_available && (requested_events & POLLIN) != 0) {
            revents |= POLLIN;
        }
        if (writable && (requested_events & POLLOUT) != 0) {
            revents |= POLLOUT;
        }
        return revents;
    }
};

} // namespace wgnx::mitm
