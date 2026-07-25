#include "ipc_service.hpp"

#include "build_id.hpp"
#include "logger.hpp"
#include "runtime/daemon_runtime.hpp"
#include "wgnx/resource_budget.hpp"

#include <algorithm>
#include <cstdio>
#include <span>

namespace wgnx::sysmodule {

namespace {

using ServerManager = ams::sf::hipc::ServerManager<wgnx::resource_budget::IpcServerPorts>;

constinit ams::util::TypedStorage<ServerManager> g_server_manager_storage = {};
constinit ServerManager* g_server_manager = nullptr;
constinit ams::sf::UnmanagedServiceObject<IControlService, ControlService> g_control_service_object;

} // namespace

ams::Result ControlService::GetApiVersion(ams::sf::Out<u32> out) {
    out.SetValue(wgnx::IpcApiVersion);
    R_SUCCEED();
}

ams::Result ControlService::GetDaemonStatus(ams::sf::Out<wgnx::DaemonStatus> out) {
    out.SetValue(runtime::GetDaemonStatus());
    R_SUCCEED();
}

ams::Result ControlService::GetBuildInfo(ams::sf::Out<wgnx::BuildInfo> out) {
    wgnx::BuildInfo info{};
    std::snprintf(info.version, sizeof(info.version), "%s", VERSION);
    std::snprintf(info.build_id, sizeof(info.build_id), "%s", wgnx::BuildId);
    out.SetValue(info);
    R_SUCCEED();
}

ams::Result ControlService::ListPeers(ams::sf::Out<u32> out_count, const ams::sf::OutArray<wgnx::PeerInfo>& out) {
    out_count.SetValue(runtime::CopyPeers({out.GetPointer(), out.GetSize()}));
    R_SUCCEED();
}

ams::Result ControlService::SetActivePeer(const wgnx::PeerSelectionRequest& request) {
    R_RETURN(runtime::SetActivePeer(request.peer_index));
}

ams::Result ControlService::SetAutoStartPeer(const wgnx::PeerSelectionRequest& request) {
    R_RETURN(runtime::SetAutoStartPeer(request.peer_index));
}

ams::Result ControlService::TriggerDebugPayload(const wgnx::DebugTriggerRequest& request) {
    R_RETURN(runtime::TriggerDebugPayload(static_cast<wgnx::DebugTriggerAction>(request.action)));
}

ams::Result ControlService::BumpUdpBinding() {
    R_RETURN(runtime::BumpUdpBinding());
}

ams::Result ControlService::SubmitInnerIpv4Packet(ams::sf::Out<wgnx::PacketSubmissionResult> out, const ams::sf::InBuffer& packet,
                                                  const ams::sf::ClientProcessId& client_pid) {
    out.SetValue(runtime::SubmitInnerIpv4Packet({static_cast<const std::uint8_t*>(packet.GetPointer()), packet.GetSize()},
                                                client_pid.GetValue().value));
    R_SUCCEED();
}

ams::Result ControlService::ReceiveInnerIpv4Packet(ams::sf::Out<wgnx::PacketReceiveResult> out, const ams::sf::OutBuffer& packet,
                                                   const ams::sf::ClientProcessId& client_pid) {
    out.SetValue(
        runtime::ReceiveInnerIpv4Packet({static_cast<std::uint8_t*>(packet.GetPointer()), packet.GetSize()}, client_pid.GetValue().value));
    R_SUCCEED();
}

void RunIpcServer() {
    runtime::Initialize();
    logger::Log("Constructing IPC server");

    g_server_manager = ams::util::ConstructAt(g_server_manager_storage);
    R_ABORT_UNLESS(g_server_manager->RegisterObjectForServer(
        g_control_service_object.GetShared(), ams::sm::ServiceName::Encode(wgnx::ServiceName), wgnx::resource_budget::IpcSessions));
    logger::Log("Registered service '%s'", wgnx::ServiceName);
    logger::Log("Entering server loop");
    g_server_manager->LoopProcess();
}

} // namespace wgnx::sysmodule
