#include "control_service.hpp"

#include "bsd_mitm_server.hpp"
#include "logger.hpp"
#include "mitm_policy.hpp"
#include "mitm_runtime_policy.hpp"
#include "terminal_server_lifecycle.hpp"

#include <array>
#include <atomic>
#include <cstddef>

namespace wgnx::mitm {

namespace {

using ServerManager = ams::sf::hipc::ServerManager<1, ams::sf::hipc::DefaultServerManagerOptions, 4>;

constinit ams::util::TypedStorage<ServerManager> g_server_manager_storage = {};
constinit ServerManager* g_server_manager = nullptr;
constinit ams::sf::UnmanagedServiceObject<IMitmControlService, ControlService> g_control_service_object;
alignas(ams::os::ThreadStackAlignment) constinit std::array<std::byte, 16 * 1024> g_server_thread_stack{};
constinit ams::os::ThreadType g_server_thread{};
constinit bool g_server_thread_started = false;
constinit std::atomic_bool g_shutdown_requested = false;
constinit TerminalServerLifecycle g_server_lifecycle{};

ams::os::Event& ShutdownEvent() {
    static ams::os::Event event{ams::os::EventClearMode_ManualClear};
    return event;
}

void ControlServerThreadMain(void*) {
    logger::Log("MITM control server loop entered");
    g_server_manager->LoopProcess();
    logger::Log("MITM control server loop exited");
}

} // namespace

ams::Result ControlService::GetStatus(ams::sf::Out<MitmStatus> out) {
    const bool requested = IsBsdSystemPolicyEnabled();
    out.SetValue({
        .api_version = MitmControlApiVersion,
        .flags = (requested ? MitmStatusFlag_BsdSystemPolicyRequested : 0) |
                 (IsBsdMitmServerRunning() ? MitmStatusFlag_BsdSystemInterceptionInstalled : 0),
        .registered_mitm_servers = IsBsdMitmServerRunning() ? 1U : 0U,
        .enabled_bsd_system_client_mask = GetEnabledBsdSystemClientMask(),
    });
    R_SUCCEED();
}

ams::Result ControlService::SetBsdSystemClientEnabled(std::uint32_t client, bool enabled) {
    R_UNLESS(IsConfigurableBsdSystemClient(client), ams::fs::ResultInvalidArgument());
    R_UNLESS(SetBsdSystemClientEnabledForRuntime(static_cast<BsdSystemClient>(client), enabled), ams::fs::ResultInvalidArgument());

    logger::Log(
        "bsd:s client=%u requested=%u interception_installed=%u",
        static_cast<unsigned>(client),
        static_cast<unsigned>(enabled),
        static_cast<unsigned>(IsBsdMitmServerRunning())
    );
    R_SUCCEED();
}

ams::Result ControlService::SetBsdSystemPolicyEnabled(bool enabled) {
    SetBsdSystemPolicyEnabledForRuntime(enabled);
    logger::Log(
        "bsd:s policy requested=%u interception_installed=%u",
        static_cast<unsigned>(enabled),
        static_cast<unsigned>(IsBsdMitmServerRunning())
    );
    R_SUCCEED();
}

ams::Result ControlService::Shutdown() {
    const bool already_requested = g_shutdown_requested.exchange(true, std::memory_order_acq_rel);
    logger::Log("MITM control shutdown requested already_requested=%u", already_requested ? 1U : 0U);
    ShutdownEvent().Signal();
    R_SUCCEED();
}

bool StartControlServer() {
    logger::Log("constructing MITM control server");
    if (g_server_manager != nullptr) {
        return true;
    }

    g_shutdown_requested.store(false, std::memory_order_release);
    ShutdownEvent().Clear();
    g_server_manager = ams::util::ConstructAt(g_server_manager_storage);
    const ams::Result register_result =
        g_server_manager->RegisterObjectForServer(g_control_service_object.GetShared(), ams::sm::ServiceName::Encode("wgm:ctl"), 4);
    if (R_FAILED(register_result)) {
        logger::Log("RegisterObjectForServer(wgm:ctl) failed rc=0x%08X", register_result.GetValue());
        ams::util::DestroyAt(g_server_manager_storage);
        g_server_manager = nullptr;
        return false;
    }

    logger::Log("registered service 'wgm:ctl'");
    const ams::Result thread_result = ams::os::CreateThread(
        std::addressof(g_server_thread),
        ControlServerThreadMain,
        nullptr,
        g_server_thread_stack.data(),
        g_server_thread_stack.size(),
        ams::os::DefaultThreadPriority
    );
    if (R_FAILED(thread_result)) {
        logger::Log("CreateThread(wgnx-mitm-ctl) failed rc=0x%08X", thread_result.GetValue());
        ams::util::DestroyAt(g_server_manager_storage);
        g_server_manager = nullptr;
        return false;
    }

    ams::os::SetThreadNamePointer(std::addressof(g_server_thread), "wgnx-mitm-ctl");
    AMS_ABORT_UNLESS(g_server_lifecycle.BeginServing());
    ams::os::StartThread(std::addressof(g_server_thread));
    g_server_thread_started = true;
    logger::Log("MITM control server started");
    return true;
}

void WaitForShutdownRequest() {
    ShutdownEvent().Wait();
}

void StopControlServer() {
    if (g_server_manager == nullptr) {
        return;
    }

    AMS_ABORT_UNLESS(g_server_lifecycle.BeginStopping());
    logger::Log("MITM control shutdown requesting server-loop stop");
    g_server_manager->RequestStopProcessing();
    if (g_server_thread_started) {
        ams::os::WaitThread(std::addressof(g_server_thread));
        ams::os::DestroyThread(std::addressof(g_server_thread));
        g_server_thread_started = false;
        AMS_ABORT_UNLESS(g_server_lifecycle.MarkServerThreadJoined());
        logger::Log("MITM control shutdown server thread joined");
    }

    // ServerManager destruction enters Horizon mutex teardown after LoopProcess
    // stops and aborts in this terminal path.
    // Main returns immediately after shutdown, so retain static service state and
    // let Horizon reclaim the service and session handles during process exit.
    logger::Log("MITM control shutdown retaining terminal server manager for process exit");
    g_server_manager = nullptr;
    AMS_ABORT_UNLESS(g_server_lifecycle.RetainForProcessExit());
}

} // namespace wgnx::mitm
