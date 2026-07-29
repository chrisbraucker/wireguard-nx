#include "bsd_socket_state.hpp"
#include "bsd_socket_state_tests.hpp"

#include <cstdio>
#include <cstring>

namespace {

bool Check(const bool condition, const char* const message) {
    if (!condition) {
        std::fprintf(stderr, "failure: %s\n", message);
    }
    return condition;
}

} // namespace

bool RunBsdSocketStateTests() {
    using namespace wgnx::mitm;

    return Check(CanOpenTunnelFlow(BsdSocketRouteState::Created), "new socket could not begin tunnel selection") &&
           Check(!CanOpenTunnelFlow(BsdSocketRouteState::Direct), "direct socket could be migrated to the tunnel") &&
           Check(!CanOpenTunnelFlow(BsdSocketRouteState::Tunneled), "tunneled socket could open a second flow") &&
           Check(UsesTunnelFlow(BsdSocketRouteState::Tunneled), "tunneled socket did not own a tunnel flow") &&
           Check(!UsesTunnelFlow(BsdSocketRouteState::OpeningTunnel), "opening socket was treated as active tunnel flow") &&
           Check(CanForwardToUpstreamBsd(BsdSocketRouteState::Created), "new socket could not use upstream BSD") &&
           Check(CanForwardToUpstreamBsd(BsdSocketRouteState::Direct), "direct socket could not use upstream BSD") &&
           Check(!CanForwardToUpstreamBsd(BsdSocketRouteState::Tunneled), "tunneled socket could leak to upstream BSD") &&
           Check(!CanForwardToUpstreamBsd(BsdSocketRouteState::Failed), "failed tunnel socket could leak to upstream BSD") &&
           Check(IsTerminalSocketRoute(BsdSocketRouteState::Failed), "failed socket was not terminal") &&
           Check(IsTerminalSocketRoute(BsdSocketRouteState::Closed), "closed socket was not terminal") &&
           Check(std::strcmp(BsdSocketRouteStateName(BsdSocketRouteState::Tunneled), "tunneled") == 0, "tunneled state name changed");
}
