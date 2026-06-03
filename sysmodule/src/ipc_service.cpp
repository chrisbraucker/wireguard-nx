#include "ipc_service.hpp"

#include "config_loader.hpp"
#include "endpoint_resolution.hpp"
#include "logger.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <sys/socket.h>

namespace wgnx::sysmodule {

namespace {

using ServerManager = ams::sf::hipc::ServerManager<1>;

constexpr inline std::size_t ResolverThreadStackSize = 16 * 1024;
constexpr inline s32 ResolverThreadPriority = ams::os::DefaultThreadPriority;

constinit ams::util::TypedStorage<ServerManager> g_server_manager_storage = {};
constinit ServerManager *g_server_manager = nullptr;
constinit ams::sf::UnmanagedServiceObject<wgnx::sysmodule::IControlService, wgnx::sysmodule::ControlService> g_control_service_object;

struct DaemonState {
    std::array<wgnx::PeerConfigEntry, wgnx::MaxPeers> configured_peers{};
    struct PeerRuntimeInfo {
        wgnx::PeerRuntimeState state{wgnx::PeerRuntimeState::Inactive};
        wgnx::PeerErrorStage error_stage{wgnx::PeerErrorStage::None};
        std::uint32_t last_error_code{0};
        std::uint16_t persistent_keepalive_interval{0};
        std::uint32_t state_ticks{0};
        std::uint32_t activation_generation{0};
        std::int32_t last_handshake_seconds{-1};
        std::int32_t last_rx_seconds{-1};
        std::int32_t last_tx_seconds{-1};
        std::uint64_t rx_bytes{0};
        std::uint64_t tx_bytes{0};
        sockaddr_storage resolved_address{};
        socklen_t resolved_address_length{0};
        std::uint8_t resolved_family{0};
        char resolved_endpoint[sizeof(wgnx::PeerInfo::resolved_endpoint)]{};
        bool established{false};
        bool has_resolved_endpoint{false};
    };
    std::array<PeerRuntimeInfo, wgnx::MaxPeers> runtime{};
    std::uint32_t peer_count{0};
    std::uint32_t next_activation_generation{1};
    std::int32_t active_peer_index{-1};
    std::int32_t auto_start_peer_index{-1};
    bool initialized{false};
};

struct ResolveRequest {
    bool pending{false};
    std::size_t peer_index{0};
    std::uint32_t activation_generation{0};
    char endpoint[sizeof(wgnx::PeerConfigEntry::endpoint)]{};
};

constinit DaemonState g_state = {};
ams::os::Mutex g_state_mutex(false);
alignas(ams::os::ThreadStackAlignment) constinit std::uint8_t g_resolver_thread_stack[ResolverThreadStackSize] = {};
constinit ams::os::ThreadType g_resolver_thread = {};
constinit bool g_resolver_thread_started = false;
ams::os::Event g_resolver_event(ams::os::EventClearMode_AutoClear);
ResolveRequest g_resolve_request = {};

void ResetRuntimeMetrics(DaemonState::PeerRuntimeInfo *runtime) {
    if (runtime == nullptr) {
        return;
    }

    runtime->state_ticks = 0;
    runtime->last_handshake_seconds = -1;
    runtime->last_rx_seconds = -1;
    runtime->last_tx_seconds = -1;
    runtime->rx_bytes = 0;
    runtime->tx_bytes = 0;
    runtime->established = false;
}

void ClearResolvedEndpoint(DaemonState::PeerRuntimeInfo *runtime) {
    if (runtime == nullptr) {
        return;
    }

    runtime->resolved_address = {};
    runtime->resolved_address_length = 0;
    runtime->resolved_family = 0;
    runtime->resolved_endpoint[0] = '\0';
    runtime->has_resolved_endpoint = false;
}

void ClearRuntimeError(DaemonState::PeerRuntimeInfo *runtime) {
    if (runtime == nullptr) {
        return;
    }

    runtime->error_stage = wgnx::PeerErrorStage::None;
    runtime->last_error_code = static_cast<std::uint32_t>(wgnx::PeerErrorCode::None);
}

void SetResolvedEndpoint(DaemonState::PeerRuntimeInfo *runtime, const endpoint_resolution::ResolvedEndpoint &resolved) {
    if (runtime == nullptr) {
        return;
    }

    runtime->resolved_address = resolved.address;
    runtime->resolved_address_length = resolved.address_length;
    runtime->resolved_family = resolved.family;
    std::snprintf(runtime->resolved_endpoint, sizeof(runtime->resolved_endpoint), "%s", resolved.endpoint);
    runtime->has_resolved_endpoint = true;
}

void SetPeerInactive(std::size_t peer_index) {
    const auto &config = g_state.configured_peers[peer_index];
    auto &runtime = g_state.runtime[peer_index];
    runtime = {};
    runtime.state = wgnx::PeerRuntimeState::Inactive;
    runtime.persistent_keepalive_interval = config.persistent_keepalive;
    ClearRuntimeError(&runtime);
    ResetRuntimeMetrics(&runtime);
    ClearResolvedEndpoint(&runtime);
}

std::uint32_t AllocateActivationGeneration() {
    const std::uint32_t generation = g_state.next_activation_generation++;
    if (g_state.next_activation_generation == 0) {
        g_state.next_activation_generation = 1;
    }
    return generation;
}

void SetPeerResolving(std::size_t peer_index, std::uint32_t activation_generation) {
    const auto &config = g_state.configured_peers[peer_index];
    auto &runtime = g_state.runtime[peer_index];
    runtime = {};
    runtime.state = wgnx::PeerRuntimeState::ResolvingEndpoint;
    runtime.persistent_keepalive_interval = config.persistent_keepalive;
    runtime.activation_generation = activation_generation;
    ClearRuntimeError(&runtime);
    ResetRuntimeMetrics(&runtime);
    ClearResolvedEndpoint(&runtime);
}

void SetPeerHandshaking(std::size_t peer_index) {
    auto &runtime = g_state.runtime[peer_index];
    runtime.state = wgnx::PeerRuntimeState::Handshaking;
    ClearRuntimeError(&runtime);
    runtime.state_ticks = 0;
    runtime.last_tx_seconds = 0;
}

void SetPeerActive(std::size_t peer_index) {
    auto &runtime = g_state.runtime[peer_index];
    runtime.state = wgnx::PeerRuntimeState::Active;
    ClearRuntimeError(&runtime);
    runtime.state_ticks = 0;
    runtime.established = true;
    runtime.last_handshake_seconds = 0;
    runtime.last_rx_seconds = 0;
    runtime.last_tx_seconds = 0;
}

void SetPeerError(std::size_t peer_index, wgnx::PeerErrorStage stage, wgnx::PeerErrorCode code) {
    auto &runtime = g_state.runtime[peer_index];
    runtime.state = wgnx::PeerRuntimeState::Error;
    runtime.error_stage = stage;
    runtime.last_error_code = static_cast<std::uint32_t>(code);
    runtime.state_ticks = 0;
    runtime.established = false;
}

wgnx::PeerErrorCode ValidatePeerConfiguration(const wgnx::PeerConfigEntry &config) {
    if (config.private_key[0] == '\0' || config.public_key[0] == '\0' || config.allowed_ips[0] == '\0') {
        return wgnx::PeerErrorCode::ConfigInvalid;
    }
    if (config.endpoint[0] == '\0') {
        return wgnx::PeerErrorCode::EndpointMissing;
    }

    return wgnx::PeerErrorCode::None;
}

void QueueEndpointResolve(std::size_t peer_index) {
    const auto &config = g_state.configured_peers[peer_index];
    const auto &runtime = g_state.runtime[peer_index];
    g_resolve_request = {};
    g_resolve_request.pending = true;
    g_resolve_request.peer_index = peer_index;
    g_resolve_request.activation_generation = runtime.activation_generation;
    std::snprintf(g_resolve_request.endpoint, sizeof(g_resolve_request.endpoint), "%s", config.endpoint);
    g_resolver_event.Signal();
}

void StartPeerRuntime(std::size_t peer_index) {
    const auto &config = g_state.configured_peers[peer_index];
    const wgnx::PeerErrorCode config_error = ValidatePeerConfiguration(config);
    if (config_error == wgnx::PeerErrorCode::ConfigInvalid) {
        SetPeerError(peer_index, wgnx::PeerErrorStage::Config, config_error);
        return;
    }
    if (config_error != wgnx::PeerErrorCode::None) {
        SetPeerError(peer_index, wgnx::PeerErrorStage::ResolveEndpoint, config_error);
        return;
    }

    const std::uint32_t activation_generation = AllocateActivationGeneration();
    SetPeerResolving(peer_index, activation_generation);
    QueueEndpointResolve(peer_index);
    logger::Log("Queued endpoint resolution for peer %zu activation=%u endpoint='%s'",
        peer_index, activation_generation, config.endpoint);
}

void AdvanceAges(DaemonState::PeerRuntimeInfo *runtime) {
    if (runtime == nullptr) {
        return;
    }

    if (runtime->last_handshake_seconds >= 0) {
        ++runtime->last_handshake_seconds;
    }
    if (runtime->last_rx_seconds >= 0) {
        ++runtime->last_rx_seconds;
    }
    if (runtime->last_tx_seconds >= 0) {
        ++runtime->last_tx_seconds;
    }
}

wgnx::PeerInfo BuildPeerInfo(std::size_t peer_index) {
    const auto &config = g_state.configured_peers[peer_index];
    const auto &runtime = g_state.runtime[peer_index];

    wgnx::PeerInfo peer = {};
    std::snprintf(peer.name, sizeof(peer.name), "%s", config.name);
    std::snprintf(peer.address, sizeof(peer.address), "%s", config.address);
    std::snprintf(peer.endpoint, sizeof(peer.endpoint), "%s", config.endpoint);
    std::snprintf(peer.resolved_endpoint, sizeof(peer.resolved_endpoint), "%s", runtime.resolved_endpoint);
    peer.last_handshake_seconds = runtime.last_handshake_seconds;
    peer.last_rx_seconds = runtime.last_rx_seconds;
    peer.last_tx_seconds = runtime.last_tx_seconds;
    peer.last_error_code = runtime.last_error_code;
    peer.persistent_keepalive_interval = runtime.persistent_keepalive_interval;
    peer.runtime_state = static_cast<std::uint8_t>(runtime.state);
    peer.error_stage = static_cast<std::uint8_t>(runtime.error_stage);
    peer.resolved_family = runtime.resolved_family;
    peer.rx_bytes = runtime.rx_bytes;
    peer.tx_bytes = runtime.tx_bytes;
    peer.flags = 0;

    if (static_cast<std::int32_t>(peer_index) == g_state.active_peer_index) {
        peer.flags |= wgnx::PeerFlag_Active;
    }
    if (static_cast<std::int32_t>(peer_index) == g_state.auto_start_peer_index) {
        peer.flags |= wgnx::PeerFlag_AutoStart;
    }
    if (runtime.established) {
        peer.flags |= wgnx::PeerFlag_Established;
    }
    if (runtime.state == wgnx::PeerRuntimeState::Error) {
        peer.flags |= wgnx::PeerFlag_HasError;
    }
    if (runtime.has_resolved_endpoint) {
        peer.flags |= wgnx::PeerFlag_HasResolvedEndpoint;
    }

    return peer;
}

bool HasRuntimeErrors() {
    for (std::size_t i = 0; i < g_state.peer_count; ++i) {
        if (g_state.runtime[i].state == wgnx::PeerRuntimeState::Error) {
            return true;
        }
    }
    return false;
}

void InitializeState() {
    if (g_state.initialized) {
        return;
    }

    char auto_start_name[sizeof(wgnx::PeerInfo::name)] = {};
    const bool has_auto_start_name = LoadAutoStartPeerName(auto_start_name, sizeof(auto_start_name));

    wgnx::PeerConfigSet config{};
    if (LoadPeerConfig(&config)) {
        g_state.peer_count = static_cast<std::uint32_t>(config.peer_count);

        for (std::size_t i = 0; i < config.peer_count; ++i) {
            const auto &entry = config.peers[i];
            g_state.configured_peers[i] = entry;
            SetPeerInactive(i);

            if (has_auto_start_name && std::strncmp(entry.name, auto_start_name, sizeof(entry.name)) == 0) {
                g_state.auto_start_peer_index = static_cast<std::int32_t>(i);
            }
        }
    } else {
        g_state.peer_count = 0;
        g_state.auto_start_peer_index = -1;
    }

    g_state.initialized = true;
    logger::Log("Initialized peer state with %u configured peer(s)", g_state.peer_count);
}

bool IsValidPeerIndex(std::int32_t peer_index) {
    return peer_index >= -1 && peer_index < static_cast<std::int32_t>(g_state.peer_count);
}

void TickActivePeer() {
    if (g_state.active_peer_index < 0) {
        return;
    }

    auto &runtime = g_state.runtime[static_cast<std::size_t>(g_state.active_peer_index)];
    AdvanceAges(&runtime);
    ++runtime.state_ticks;

    switch (runtime.state) {
        case wgnx::PeerRuntimeState::Inactive:
            break;
        case wgnx::PeerRuntimeState::ResolvingEndpoint:
            break;
        case wgnx::PeerRuntimeState::Handshaking:
            if (runtime.state_ticks >= 2) {
                SetPeerActive(static_cast<std::size_t>(g_state.active_peer_index));
            }
            break;
        case wgnx::PeerRuntimeState::Active:
            if ((runtime.state_ticks % 2U) == 0) {
                runtime.last_tx_seconds = 0;
                runtime.tx_bytes += 768 + (runtime.state_ticks * 29U);
            }
            if ((runtime.state_ticks % 3U) == 0) {
                runtime.last_rx_seconds = 0;
                runtime.rx_bytes += 1024 + (runtime.state_ticks * 37U);
            }
            if ((runtime.state_ticks % 10U) == 0) {
                runtime.last_handshake_seconds = 0;
            }
            break;
        case wgnx::PeerRuntimeState::Error:
            break;
    }
}

bool DequeueResolveRequest(ResolveRequest *out_request) {
    std::scoped_lock lock(g_state_mutex);
    if (!g_resolve_request.pending || out_request == nullptr) {
        return false;
    }

    *out_request = g_resolve_request;
    g_resolve_request.pending = false;
    return true;
}

void CommitResolveResult(const ResolveRequest &request, const endpoint_resolution::ResolveResult &result) {
    std::scoped_lock lock(g_state_mutex);
    if (request.peer_index >= g_state.peer_count) {
        return;
    }

    auto &runtime = g_state.runtime[request.peer_index];
    if (g_state.active_peer_index != static_cast<std::int32_t>(request.peer_index) ||
        runtime.activation_generation != request.activation_generation ||
        runtime.state != wgnx::PeerRuntimeState::ResolvingEndpoint) {
        return;
    }

    if (!result.success) {
        SetPeerError(request.peer_index, result.error_stage, result.error_code);
        logger::Log("Endpoint resolution failed for peer %zu activation=%u stage=%s code=%s",
            request.peer_index,
            request.activation_generation,
            wgnx::GetPeerErrorStageName(result.error_stage),
            wgnx::GetPeerErrorCodeName(result.error_code));
        return;
    }

    SetResolvedEndpoint(std::addressof(runtime), result.endpoint);
    SetPeerHandshaking(request.peer_index);
    logger::Log("Endpoint resolved for peer %zu activation=%u -> %s",
        request.peer_index,
        request.activation_generation,
        runtime.resolved_endpoint);
}

void ResolverThreadMain(void *) {
    while (true) {
        g_resolver_event.Wait();

        ResolveRequest request{};
        while (DequeueResolveRequest(std::addressof(request))) {
            const auto result = endpoint_resolution::Resolve(request.endpoint);
            CommitResolveResult(request, result);
        }
    }
}

void InitializeResolverWorker() {
    if (g_resolver_thread_started) {
        return;
    }

    R_ABORT_UNLESS(ams::os::CreateThread(
        std::addressof(g_resolver_thread),
        ResolverThreadMain,
        nullptr,
        g_resolver_thread_stack,
        sizeof(g_resolver_thread_stack),
        ResolverThreadPriority));
    ams::os::SetThreadNamePointer(std::addressof(g_resolver_thread), "wgnx-resolve");
    ams::os::StartThread(std::addressof(g_resolver_thread));
    g_resolver_thread_started = true;
    logger::Log("Started endpoint resolver worker");
}

} // namespace

ams::Result ControlService::GetApiVersion(ams::sf::Out<u32> out) {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();
    out.SetValue(wgnx::IpcApiVersion);
    R_SUCCEED();
}

ams::Result ControlService::GetDaemonStatus(ams::sf::Out<wgnx::DaemonStatus> out) {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();
    TickActivePeer();

    wgnx::DaemonStatus status = {
        .abi_version = wgnx::IpcApiVersion,
        .peer_count = g_state.peer_count,
        .active_peer_index = g_state.active_peer_index,
        .auto_start_peer_index = g_state.auto_start_peer_index,
        .flags = wgnx::DaemonFlag_Ready |
                 (g_state.active_peer_index >= 0 ? wgnx::DaemonFlag_TunnelActive : 0U) |
                 (HasRuntimeErrors() ? wgnx::DaemonFlag_HasErrors : 0U),
        .reserved = 0,
    };

    out.SetValue(status);
    R_SUCCEED();
}

ams::Result ControlService::ListPeers(ams::sf::Out<u32> out_count, const ams::sf::OutArray<wgnx::PeerInfo> &out) {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();
    TickActivePeer();

    const std::size_t copy_count = std::min<std::size_t>(out.GetSize(), g_state.peer_count);
    for (std::size_t i = 0; i < copy_count; ++i) {
        out[i] = BuildPeerInfo(i);
    }

    out_count.SetValue(g_state.peer_count);
    R_SUCCEED();
}

ams::Result ControlService::SetActivePeer(const wgnx::PeerSelectionRequest &request) {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();

    if (!IsValidPeerIndex(request.peer_index)) {
        logger::Log("Rejected SetActivePeer(%d): invalid index", request.peer_index);
        R_THROW(ams::fs::ResultInvalidArgument());
    }

    if (request.peer_index == g_state.active_peer_index) {
        logger::Log("SetActivePeer(%d): no change", request.peer_index);
        R_SUCCEED();
    }

    if (g_state.active_peer_index >= 0 && g_state.active_peer_index != request.peer_index) {
        const std::size_t old_index = static_cast<std::size_t>(g_state.active_peer_index);
        SetPeerInactive(old_index);
    }

    g_state.active_peer_index = request.peer_index;
    if (request.peer_index >= 0) {
        StartPeerRuntime(static_cast<std::size_t>(request.peer_index));
    }
    logger::Log("SetActivePeer(%d)", request.peer_index);
    R_SUCCEED();
}

ams::Result ControlService::SetAutoStartPeer(const wgnx::PeerSelectionRequest &request) {
    std::scoped_lock lock(g_state_mutex);
    InitializeState();

    if (!IsValidPeerIndex(request.peer_index)) {
        logger::Log("Rejected SetAutoStartPeer(%d): invalid index", request.peer_index);
        R_THROW(ams::fs::ResultInvalidArgument());
    }

    const char *peer_name = nullptr;
    if (request.peer_index >= 0) {
        peer_name = g_state.configured_peers[static_cast<std::size_t>(request.peer_index)].name;
    }

    const ams::Result store_rc = StoreAutoStartPeerName(peer_name);
    if (R_FAILED(store_rc)) {
        logger::Log("Rejected SetAutoStartPeer(%d): persist failed rc=0x%08x", request.peer_index, static_cast<u32>(store_rc.GetValue()));
        R_THROW(store_rc);
    }

    g_state.auto_start_peer_index = request.peer_index;
    logger::Log("SetAutoStartPeer(%d)", request.peer_index);
    R_SUCCEED();
}

void RunIpcServer() {
    {
        std::scoped_lock lock(g_state_mutex);
        InitializeState();
    }
    InitializeResolverWorker();
    logger::Log("Constructing IPC server");

    g_server_manager = ams::util::ConstructAt(g_server_manager_storage);
    R_ABORT_UNLESS(g_server_manager->RegisterObjectForServer(g_control_service_object.GetShared(), ams::sm::ServiceName::Encode(wgnx::ServiceName), 8));
    logger::Log("Registered service '%s'", wgnx::ServiceName);
    logger::Log("Entering server loop");
    g_server_manager->LoopProcess();
}

} // namespace wgnx::sysmodule
