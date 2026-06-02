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
    std::array<wgnx::PeerInfo, wgnx::MaxPeers> peers{};
    std::uint32_t peer_count{0};
    std::int32_t active_peer_index{-1};
    std::int32_t auto_start_peer_index{-1};
    std::uint32_t tick_count{0};
    bool initialized{false};
};

constinit DaemonState g_state = {};

template<std::size_t Size>
void CopyString(char (&dst)[Size], const char *src) {
    std::snprintf(dst, Size, "%s", src);
}

void ResetPeerCounters(wgnx::PeerInfo &peer) {
    peer.last_handshake_seconds = 0;
    peer.rx_bytes = 0;
    peer.tx_bytes = 0;
}

void UpdatePeerFlags() {
    for (std::size_t i = 0; i < g_state.peer_count; ++i) {
        auto &peer = g_state.peers[i];
        peer.flags = 0;

        if (static_cast<std::int32_t>(i) == g_state.active_peer_index) {
            peer.flags |= wgnx::PeerFlag_Active;
        }
        if (static_cast<std::int32_t>(i) == g_state.auto_start_peer_index) {
            peer.flags |= wgnx::PeerFlag_AutoStart;
        }
    }
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
            auto &peer = g_state.peers[i];
            const auto &entry = config.peers[i];

            CopyString(peer.name, entry.name);
            CopyString(peer.address, entry.address);
            CopyString(peer.endpoint, entry.endpoint);
            ResetPeerCounters(peer);

            if (has_auto_start_name && std::strncmp(entry.name, auto_start_name, sizeof(entry.name)) == 0) {
                g_state.auto_start_peer_index = static_cast<std::int32_t>(i);
            }
        }
    } else {
        g_state.peer_count = 0;
        g_state.auto_start_peer_index = -1;
    }

    UpdatePeerFlags();
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

    auto &peer = g_state.peers[static_cast<std::size_t>(g_state.active_peer_index)];
    ++g_state.tick_count;

    peer.last_handshake_seconds = static_cast<std::int32_t>((g_state.tick_count * 3) % 120);
    peer.rx_bytes += 1024 + (g_state.tick_count * 37);
    peer.tx_bytes += 768 + (g_state.tick_count * 29);
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
        .flags = wgnx::DaemonFlag_Ready | (g_state.active_peer_index >= 0 ? wgnx::DaemonFlag_TunnelActive : 0U),
        .reserved = 0,
    };

    out.SetValue(status);
    R_SUCCEED();
}

ams::Result ControlService::ListPeers(ams::sf::Out<u32> out_count, const ams::sf::OutArray<wgnx::PeerInfo> &out) {
    InitializeState();
    TickActivePeer();
    UpdatePeerFlags();

    const std::size_t copy_count = std::min<std::size_t>(out.GetSize(), g_state.peer_count);
    for (std::size_t i = 0; i < copy_count; ++i) {
        out[i] = g_state.peers[i];
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
        ResetPeerCounters(g_state.peers[static_cast<std::size_t>(g_state.active_peer_index)]);
    }

    g_state.active_peer_index = request.peer_index;
    UpdatePeerFlags();
    logger::Log("SetActivePeer(%d)", request.peer_index);
    R_SUCCEED();
}

ams::Result ControlService::SetAutoStartPeer(const wgnx::PeerSelectionRequest &request) {
    InitializeState();

    if (!IsValidPeerIndex(request.peer_index)) {
        logger::Log("Rejected SetAutoStartPeer(%d): invalid index", request.peer_index);
        R_THROW(ams::fs::ResultInvalidArgument());
    }

    g_state.auto_start_peer_index = request.peer_index;
    UpdatePeerFlags();
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
