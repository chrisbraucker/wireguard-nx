#include "ipc_service.hpp"
#include "config_loader.hpp"
#include "logger.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>

namespace wgnx::sysmodule {

namespace {

using ServerManager = ams::sf::hipc::ServerManager<1>;

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
        std::int32_t last_handshake_seconds{-1};
        std::int32_t last_rx_seconds{-1};
        std::int32_t last_tx_seconds{-1};
        std::uint64_t rx_bytes{0};
        std::uint64_t tx_bytes{0};
        bool established{false};
    };
    std::array<PeerRuntimeInfo, wgnx::MaxPeers> runtime{};
    std::uint32_t peer_count{0};
    std::int32_t active_peer_index{-1};
    std::int32_t auto_start_peer_index{-1};
    bool initialized{false};
};

constinit DaemonState g_state = {};

void ResetRuntimePeer(DaemonState::PeerRuntimeInfo *runtime, const wgnx::PeerConfigEntry &config) {
    if (runtime == nullptr) {
        return;
    }

    *runtime = {};
    runtime->state = wgnx::PeerRuntimeState::Inactive;
    runtime->error_stage = wgnx::PeerErrorStage::None;
    runtime->persistent_keepalive_interval = config.persistent_keepalive;
    runtime->last_handshake_seconds = -1;
    runtime->last_rx_seconds = -1;
    runtime->last_tx_seconds = -1;
}

bool EndpointLooksUsable(const char *endpoint) {
    if (endpoint == nullptr || endpoint[0] == '\0') {
        return false;
    }

    const char *port = std::strrchr(endpoint, ':');
    if (port == nullptr || port == endpoint || port[1] == '\0') {
        return false;
    }

    ++port;
    char *end = nullptr;
    const unsigned long value = std::strtoul(port, &end, 10);
    return end != port && *end == '\0' && value > 0 && value <= 65535;
}

void SetRuntimeError(std::size_t peer_index, wgnx::PeerErrorStage stage, std::uint32_t code) {
    auto &runtime = g_state.runtime[peer_index];
    runtime.state = wgnx::PeerRuntimeState::Error;
    runtime.error_stage = stage;
    runtime.last_error_code = code;
    runtime.established = false;
}

void StartPeerRuntime(std::size_t peer_index) {
    auto &config = g_state.configured_peers[peer_index];
    auto &runtime = g_state.runtime[peer_index];

    ResetRuntimePeer(&runtime, config);
    if (!EndpointLooksUsable(config.endpoint)) {
        SetRuntimeError(peer_index, wgnx::PeerErrorStage::ResolveEndpoint, 1);
        return;
    }

    runtime.state = wgnx::PeerRuntimeState::ResolvingEndpoint;
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
    peer.last_handshake_seconds = runtime.last_handshake_seconds;
    peer.last_rx_seconds = runtime.last_rx_seconds;
    peer.last_tx_seconds = runtime.last_tx_seconds;
    peer.last_error_code = runtime.last_error_code;
    peer.persistent_keepalive_interval = runtime.persistent_keepalive_interval;
    peer.runtime_state = static_cast<std::uint8_t>(runtime.state);
    peer.error_stage = static_cast<std::uint8_t>(runtime.error_stage);
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
            ResetRuntimePeer(&g_state.runtime[i], entry);

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
            if (runtime.state_ticks >= 1) {
                runtime.state = wgnx::PeerRuntimeState::Handshaking;
                runtime.state_ticks = 0;
                runtime.last_tx_seconds = 0;
            }
            break;
        case wgnx::PeerRuntimeState::Handshaking:
            if (runtime.state_ticks >= 2) {
                runtime.state = wgnx::PeerRuntimeState::Active;
                runtime.state_ticks = 0;
                runtime.established = true;
                runtime.last_handshake_seconds = 0;
                runtime.last_rx_seconds = 0;
                runtime.last_tx_seconds = 0;
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

} // namespace

ams::Result ControlService::GetApiVersion(ams::sf::Out<u32> out) {
    InitializeState();
    out.SetValue(wgnx::IpcApiVersion);
    R_SUCCEED();
}

ams::Result ControlService::GetDaemonStatus(ams::sf::Out<wgnx::DaemonStatus> out) {
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
    InitializeState();

    if (!IsValidPeerIndex(request.peer_index)) {
        logger::Log("Rejected SetActivePeer(%d): invalid index", request.peer_index);
        R_THROW(ams::fs::ResultInvalidArgument());
    }

    if (g_state.active_peer_index >= 0 && g_state.active_peer_index != request.peer_index) {
        const std::size_t old_index = static_cast<std::size_t>(g_state.active_peer_index);
        ResetRuntimePeer(&g_state.runtime[old_index], g_state.configured_peers[old_index]);
    }

    g_state.active_peer_index = request.peer_index;
    if (request.peer_index >= 0) {
        StartPeerRuntime(static_cast<std::size_t>(request.peer_index));
    }
    logger::Log("SetActivePeer(%d)", request.peer_index);
    R_SUCCEED();
}

ams::Result ControlService::SetAutoStartPeer(const wgnx::PeerSelectionRequest &request) {
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
    InitializeState();
    logger::Log("Constructing IPC server");

    g_server_manager = ams::util::ConstructAt(g_server_manager_storage);
    R_ABORT_UNLESS(g_server_manager->RegisterObjectForServer(g_control_service_object.GetShared(), ams::sm::ServiceName::Encode(wgnx::ServiceName), 8));
    logger::Log("Registered service '%s'", wgnx::ServiceName);
    logger::Log("Entering server loop");
    g_server_manager->LoopProcess();
}

} // namespace wgnx::sysmodule
