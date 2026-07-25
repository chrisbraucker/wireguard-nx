#include "control_service.hpp"

#include "logger.hpp"
#include "mitm_policy.hpp"

#include <atomic>

namespace wgnx::mitm {

namespace {

using ServerManager = ams::sf::hipc::ServerManager<1, ams::sf::hipc::DefaultServerManagerOptions, 4>;

constinit ams::util::TypedStorage<ServerManager> g_server_manager_storage = {};
constinit ServerManager* g_server_manager = nullptr;
constinit ams::sf::UnmanagedServiceObject<IMitmControlService, ControlService> g_control_service_object;
constinit std::atomic_bool g_bsd_system_policy_requested = false;
constinit std::atomic_uint32_t g_enabled_bsd_system_client_mask = 0;

} // namespace

ams::Result ControlService::GetStatus(ams::sf::Out<MitmStatus> out) {
    const bool requested = g_bsd_system_policy_requested.load(std::memory_order_relaxed);
    out.SetValue({
        .api_version = MitmControlApiVersion,
        .flags = requested ? MitmStatusFlag_BsdSystemPolicyRequested : 0,
        .registered_mitm_servers = 0,
        .enabled_bsd_system_client_mask = g_enabled_bsd_system_client_mask.load(std::memory_order_relaxed),
    });
    R_SUCCEED();
}

ams::Result ControlService::SetBsdSystemClientEnabled(std::uint32_t client, bool enabled) {
    R_UNLESS(IsConfigurableBsdSystemClient(client), ams::fs::ResultInvalidArgument());

    const std::uint32_t mask = BsdSystemClientMask(static_cast<BsdSystemClient>(client));
    if (enabled) {
        g_enabled_bsd_system_client_mask.fetch_or(mask, std::memory_order_relaxed);
    } else {
        g_enabled_bsd_system_client_mask.fetch_and(~mask, std::memory_order_relaxed);
    }

    logger::Log("bsd:s client=%u requested=%u interception_installed=0", static_cast<unsigned>(client), static_cast<unsigned>(enabled));
    R_SUCCEED();
}

ams::Result ControlService::SetBsdSystemPolicyEnabled(bool enabled) {
    g_bsd_system_policy_requested.store(enabled, std::memory_order_relaxed);
    logger::Log("bsd:s policy requested=%u interception_installed=0", static_cast<unsigned>(enabled));
    R_SUCCEED();
}

void RunControlServer() {
    logger::Log("constructing inert MITM control server");
    g_server_manager = ams::util::ConstructAt(g_server_manager_storage);
    R_ABORT_UNLESS(
        g_server_manager->RegisterObjectForServer(g_control_service_object.GetShared(), ams::sm::ServiceName::Encode("wgm:ctl"), 4));
    logger::Log("registered service 'wgm:ctl'");
    logger::Log("bsd:s interception is not registered in this build");
    g_server_manager->LoopProcess();
}

} // namespace wgnx::mitm
