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

    const BsdSocketRouteState opening = AdvanceBsdSocketRoute(BsdSocketRouteState::Created, BsdSocketRouteEvent::BeginTunnelOpen);
    const BsdSocketRouteState tunneled = AdvanceBsdSocketRoute(opening, BsdSocketRouteEvent::TunnelOpened);
    const BsdSocketRouteState bypassed = AdvanceBsdSocketRoute(opening, BsdSocketRouteEvent::TunnelBypassed);
    const BsdSocketRouteState failed = AdvanceBsdSocketRoute(opening, BsdSocketRouteEvent::TunnelFailed);
    const BsdSocketRouteState direct = AdvanceBsdSocketRoute(bypassed, BsdSocketRouteEvent::DirectConnected);

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
           Check(opening == BsdSocketRouteState::OpeningTunnel, "new socket did not enter tunnel opening") &&
           Check(tunneled == BsdSocketRouteState::Tunneled, "opened tunnel did not become tunneled") &&
           Check(bypassed == BsdSocketRouteState::Created, "bypassed tunnel did not return to direct selection") &&
           Check(failed == BsdSocketRouteState::Failed, "failed tunnel open did not become terminal") &&
           Check(direct == BsdSocketRouteState::Direct, "successful direct connect did not become direct") &&
           Check(
               AdvanceBsdSocketRoute(BsdSocketRouteState::Direct, BsdSocketRouteEvent::BeginTunnelOpen) == BsdSocketRouteState::Direct,
               "direct socket began a second tunnel open"
           ) &&
           Check(
               AdvanceBsdSocketRoute(BsdSocketRouteState::Created, BsdSocketRouteEvent::TunnelOpened) == BsdSocketRouteState::Created,
               "unopened socket became tunneled"
           ) &&
           Check(
               AdvanceBsdSocketRoute(BsdSocketRouteState::Tunneled, BsdSocketRouteEvent::Close) == BsdSocketRouteState::Closed,
               "close did not terminate tunneled socket"
           ) &&
           Check(std::strcmp(BsdSocketRouteStateName(BsdSocketRouteState::Tunneled), "tunneled") == 0, "tunneled state name changed") &&
           Check(std::strcmp(BsdSocketTransportName(BsdSocketTransport::Udp), "udp") == 0, "UDP transport name changed") &&
           Check(std::strcmp(BsdSocketTransportName(BsdSocketTransport::Tcp), "tcp") == 0, "TCP transport name changed");
}
