#include "ipc_service.hpp"

#include "build_id.hpp"
#include "ipc_server_lifecycle.hpp"
#include "logger.hpp"
#include "runtime/daemon_runtime.hpp"
#include "tunnel_service.hpp"
#include "wgnx/resource_budget.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <memory>
#include <span>

namespace wgnx::sysmodule {

namespace {

using ServerManager = ams::sf::hipc::ServerManager<wgnx::resource_budget::IpcServerPorts>;

constinit ams::util::TypedStorage<ServerManager> g_server_manager_storage = {};
constinit ServerManager* g_server_manager = nullptr;
constinit ams::sf::UnmanagedServiceObject<IControlService, ControlService> g_control_service_object;
alignas(ams::os::ThreadStackAlignment) constinit std::array<std::byte,
                                                            wgnx::resource_budget::IpcServerThreadStackBytes> g_server_thread_stack{};
constinit ams::os::ThreadType g_server_thread{};
constinit bool g_server_thread_started = false;
constinit std::atomic_bool g_shutdown_requested = false;
constinit IpcServerLifecycle g_server_lifecycle{};

ams::os::Event& ShutdownEvent() {
    static ams::os::Event event{ams::os::EventClearMode_ManualClear};
    return event;
}

void IpcServerThreadMain(void*) {
    logger::Log("IPC server loop entered");
    g_server_manager->LoopProcess();
    logger::Log("IPC server loop exited");
}

void DestroyIpcServerAfterFailedStart() {
    if (g_server_manager != nullptr) {
        ams::util::DestroyAt(g_server_manager_storage);
        g_server_manager = nullptr;
    }
    runtime::Shutdown();
}

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

ams::Result ControlService::Shutdown() {
    const bool already_requested = g_shutdown_requested.exchange(true, std::memory_order_acq_rel);
    logger::Log("Control shutdown requested already_requested=%u", already_requested ? 1U : 0U);
    ShutdownEvent().Signal();
    R_SUCCEED();
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

bool StartIpcServer() {
    runtime::Initialize();
    logger::Log("Constructing IPC server");

    if (!g_server_lifecycle.BeginServing()) {
        logger::Log("IPC server start rejected lifecycle=%u", static_cast<unsigned>(g_server_lifecycle.Phase()));
        runtime::Shutdown();
        return false;
    }

    g_shutdown_requested.store(false, std::memory_order_release);
    ShutdownEvent().Clear();
    g_server_manager = ams::util::ConstructAt(g_server_manager_storage);
    const ams::Result control_register_result = g_server_manager->RegisterObjectForServer(
        g_control_service_object.GetShared(), ams::sm::ServiceName::Encode(wgnx::ServiceName), wgnx::resource_budget::IpcSessions);
    if (R_FAILED(control_register_result)) {
        logger::Log("RegisterObjectForServer(%s) failed rc=0x%08X", wgnx::ServiceName, control_register_result.GetValue());
        DestroyIpcServerAfterFailedStart();
        return false;
    }
    logger::Log("Registered service '%s'", wgnx::ServiceName);
    const ams::Result tunnel_register_result = g_server_manager->RegisterObjectForServer(
        GetTunnelRootServiceObject(), ams::sm::ServiceName::Encode(wgnx::tunnel::ServiceName), wgnx::resource_budget::IpcSessions);
    if (R_FAILED(tunnel_register_result)) {
        logger::Log("RegisterObjectForServer(%s) failed rc=0x%08X", wgnx::tunnel::ServiceName, tunnel_register_result.GetValue());
        DestroyIpcServerAfterFailedStart();
        return false;
    }
    logger::Log("Registered service '%s'", wgnx::tunnel::ServiceName);

    const ams::Result thread_result =
        ams::os::CreateThread(std::addressof(g_server_thread), IpcServerThreadMain, nullptr, g_server_thread_stack.data(),
                              g_server_thread_stack.size(), ams::os::DefaultThreadPriority);
    if (R_FAILED(thread_result)) {
        logger::Log("CreateThread(wgnx-ipc) failed rc=0x%08X", thread_result.GetValue());
        DestroyIpcServerAfterFailedStart();
        return false;
    }

    ams::os::SetThreadNamePointer(std::addressof(g_server_thread), "wgnx-ipc");
    ams::os::StartThread(std::addressof(g_server_thread));
    g_server_thread_started = true;
    logger::Log("IPC server started stack=%zu", g_server_thread_stack.size());
    return true;
}

void WaitForIpcServerShutdownRequest() {
    ShutdownEvent().Wait();
}

void StopIpcServer() {
    if (g_server_manager == nullptr) {
        logger::Log("IPC server shutdown skipped state=not_started");
        return;
    }

    // Lifecycle transitions return bool, unlike Horizon APIs which return ams::Result.
    AMS_ABORT_UNLESS(g_server_lifecycle.BeginStopping());
    logger::Log("IPC server shutdown requesting server-loop stop");
    g_server_manager->RequestStopProcessing();
    if (g_server_thread_started) {
        ams::os::WaitThread(std::addressof(g_server_thread));
        ams::os::DestroyThread(std::addressof(g_server_thread));
        g_server_thread_started = false;
        AMS_ABORT_UNLESS(g_server_lifecycle.MarkServerThreadJoined());
        logger::Log("IPC server shutdown server thread joined");
    }

    const std::uint32_t tunnel_clients = runtime::SignalTunnelClientShutdown();
    logger::Log("IPC server shutdown signaled tunnel clients count=%u", tunnel_clients);

    // ServerManager<2> destruction enters its per-service mutex teardown after the
    // dispatch loop has stopped, which aborts on Horizon in this terminal path.
    // Main returns immediately after this function, so keep the static manager alive
    // until Horizon destroys the process and reclaims its service and IPC handles.
    logger::Log("IPC server shutdown retaining terminal server manager for process exit");
    g_server_manager = nullptr;
    AMS_ABORT_UNLESS(g_server_lifecycle.MarkProcessExitReady());
    runtime::Shutdown();
    logger::Log("IPC graceful shutdown complete");
}

} // namespace wgnx::sysmodule
