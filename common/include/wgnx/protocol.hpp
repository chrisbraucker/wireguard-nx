#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace wgnx {

constexpr inline char ServiceName[] = "wgnx:ctl";
constexpr inline std::uint32_t IpcApiVersion = 2;
constexpr inline std::size_t MaxPeers = 8;

enum class CommandId : std::uint32_t {
    GetApiVersion = 0,
    GetDaemonStatus = 1,
    ListPeers = 2,
    SetActivePeer = 10,
    SetAutoStartPeer = 11,
};

enum PeerFlags : std::uint8_t {
    PeerFlag_Active = 1U << 0,
    PeerFlag_AutoStart = 1U << 1,
    PeerFlag_Established = 1U << 2,
    PeerFlag_HasError = 1U << 3,
};

enum class PeerRuntimeState : std::uint8_t {
    Inactive = 0,
    ResolvingEndpoint = 1,
    Handshaking = 2,
    Active = 3,
    Error = 4,
};

enum class PeerErrorStage : std::uint8_t {
    None = 0,
    Config = 1,
    ResolveEndpoint = 2,
    Handshake = 3,
    Transport = 4,
    Internal = 5,
};

enum DaemonFlags : std::uint32_t {
    DaemonFlag_Ready = 1U << 0,
    DaemonFlag_TunnelActive = 1U << 1,
    DaemonFlag_HasErrors = 1U << 2,
};

struct PeerInfo {
    char name[32];
    char address[48];
    char endpoint[256];
    std::int32_t last_handshake_seconds;
    std::int32_t last_rx_seconds;
    std::int32_t last_tx_seconds;
    std::uint32_t last_error_code;
    std::uint16_t persistent_keepalive_interval;
    std::uint8_t runtime_state;
    std::uint8_t error_stage;
    std::uint64_t rx_bytes;
    std::uint64_t tx_bytes;
    std::uint8_t flags;
    std::uint8_t reserved1[7];
};

struct DaemonStatus {
    std::uint32_t abi_version;
    std::uint32_t peer_count;
    std::int32_t active_peer_index;
    std::int32_t auto_start_peer_index;
    std::uint32_t flags;
    std::uint32_t reserved;
};

struct PeerSelectionRequest {
    std::int32_t peer_index;
    std::uint32_t reserved;
};

static_assert(std::is_standard_layout_v<PeerInfo>);
static_assert(std::is_trivially_copyable_v<PeerInfo>);
static_assert(std::is_standard_layout_v<DaemonStatus>);
static_assert(std::is_trivially_copyable_v<DaemonStatus>);
static_assert(std::is_standard_layout_v<PeerSelectionRequest>);
static_assert(std::is_trivially_copyable_v<PeerSelectionRequest>);

} // namespace wgnx
