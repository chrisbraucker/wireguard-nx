#include "tunnel_flow_readiness.hpp"
#include "tunnel_flow_readiness_tests.hpp"

#include <cstdio>
#include <poll.h>

namespace {

bool Check(const bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "failure: %s\n", message);
    }
    return condition;
}

} // namespace

bool RunTunnelFlowReadinessTests() {
    using wgnx::mitm::TunnelFlowReadiness;

    const TunnelFlowReadiness readable{.inbound_available = true, .outbound_admission_available = false, .closed = false};
    const TunnelFlowReadiness writable{.inbound_available = false, .outbound_admission_available = true, .closed = false};
    const TunnelFlowReadiness both{.inbound_available = true, .outbound_admission_available = true, .closed = false};
    const TunnelFlowReadiness closed{.inbound_available = true, .outbound_admission_available = true, .closed = true};

    return Check(readable.Revents(POLLIN) == POLLIN, "inbound data did not report POLLIN") &&
           Check(readable.Revents(POLLOUT) == 0, "inbound data incorrectly reported POLLOUT") &&
           Check(writable.Revents(POLLIN) == 0, "writable flow incorrectly reported POLLIN") &&
           Check(writable.Revents(POLLOUT) == POLLOUT, "writable flow did not report POLLOUT") &&
           Check(both.Revents(POLLIN | POLLOUT) == (POLLIN | POLLOUT), "combined readiness did not preserve both requested events") &&
           Check(closed.Revents(POLLIN | POLLOUT) == POLLHUP, "closed flow did not report only POLLHUP");
}
