#include <stratosphere.hpp>

#include "bsd_mitm_server.hpp"
#include "control_service.hpp"
#include "logger.hpp"
#include "tunnel_discovery_service.hpp"
#include "tunnel_flow_worker.hpp"

namespace ams {

void Main() {
    wgnx::mitm::logger::Initialize();
    wgnx::mitm::logger::Log("main entered");
    wgnx::mitm::logger::Log("build: %s-%s", VERSION, BUILD_ID);
    wgnx::mitm::GetTunnelFlowWorker().Start();
    wgnx::mitm::GetTunnelDiscoveryService().Start();
    if (!wgnx::mitm::StartBsdMitmServer()) {
        wgnx::mitm::logger::Log("bsd:s MITM unavailable; control service remains available");
    }
    if (!wgnx::mitm::StartControlServer()) {
        wgnx::mitm::logger::Log("MITM control service unavailable; shutting down");
        wgnx::mitm::StopBsdMitmServer();
        wgnx::mitm::GetTunnelDiscoveryService().Stop();
        wgnx::mitm::GetTunnelFlowWorker().Stop();
        return;
    }

    wgnx::mitm::WaitForShutdownRequest();
    wgnx::mitm::logger::Log("MITM graceful shutdown begin");
    wgnx::mitm::StopControlServer();
    wgnx::mitm::StopBsdMitmServer();
    wgnx::mitm::GetTunnelDiscoveryService().Stop();
    wgnx::mitm::GetTunnelFlowWorker().Stop();
    wgnx::mitm::logger::Log("MITM graceful shutdown complete");
}

} // namespace ams
