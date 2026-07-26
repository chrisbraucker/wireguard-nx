#include <stratosphere.hpp>

#include "control_service.hpp"
#include "logger.hpp"
#include "tunnel_discovery_service.hpp"

namespace ams {

void Main() {
    wgnx::mitm::logger::Initialize();
    wgnx::mitm::logger::Log("main entered");
    wgnx::mitm::logger::Log("build: %s-%s", VERSION, BUILD_ID);
    wgnx::mitm::GetTunnelDiscoveryService().Start();
    wgnx::mitm::RunControlServer();
}

} // namespace ams
