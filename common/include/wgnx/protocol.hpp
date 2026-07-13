#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace wgnx {

constexpr inline char ServiceName[] = "wgnx:ctl";
// Increment whenever the public IPC command set or wire contract changes.
constexpr inline std::uint32_t IpcApiVersion = 2;
constexpr inline std::size_t MaxPeers = 8;
constexpr inline std::size_t MaxInnerIpv4PacketSize = 1500;

enum class CommandId : std::uint32_t {
    GetApiVersion = 0,
    GetDaemonStatus = 1,
    ListPeers = 2,
    GetBuildInfo = 3,
    SetActivePeer = 10,
    SetAutoStartPeer = 11,
#if WGNX_ENABLE_DEBUG_PROBE
    TriggerDebugPayload = 20,
    SubmitInnerIpv4Packet = 21,
    ReceiveInnerIpv4Packet = 22,
#endif
};

enum class PacketApiStatus : std::uint32_t {
    Success = 0,
    Queued = 1,
    QueueEmpty = 2,
    QueueFull = 3,
    TunnelUnavailable = 4,
    MalformedPacket = 5,
    OutputBufferTooSmall = 6,
    StaleActivation = 7,
    AccessDenied = 8,
    InternalError = 9,
};

enum class DebugTriggerAction : std::uint32_t {
    None = 0,
    PingTunnelPeer = 1,
    PingPublicDns = 2,
};

enum class DebugProbeStatus : std::uint32_t {
    None = 0,
    Queued = 1,
    Sent = 2,
    ReplyValidated = 3,
    ReplyRejected = 4,
    TimedOut = 5,
    StaleActivation = 6,
    InvalidState = 7,
    BuildFailed = 8,
    SendFailed = 9,
};

enum PeerFlags : std::uint8_t {
    PeerFlag_Active = 1U << 0,
    PeerFlag_AutoStart = 1U << 1,
    PeerFlag_Established = 1U << 2,
    PeerFlag_HasError = 1U << 3,
    PeerFlag_HasResolvedEndpoint = 1U << 4,
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

enum class PeerErrorCode : std::uint32_t {
    None = 0,
    ConfigInvalid = 1,
    EndpointMissing = 2,
    EndpointMalformed = 3,
    EndpointResolutionFailed = 4,
    TransportInitFailed = 5,
    InternalFailure = 6,
    KeyInvalid = 7,
    HandshakeInitFailed = 8,
    TransportOpenFailed = 9,
    TransportSendFailed = 10,
    TransportReceiveFailed = 11,
    HandshakeTimedOut = 12,
};

enum DaemonFlags : std::uint32_t {
    DaemonFlag_Ready = 1U << 0,
    DaemonFlag_TunnelActive = 1U << 1,
    DaemonFlag_HasErrors = 1U << 2,
};

enum class PeerResolvedFamily : std::uint8_t {
    Unspecified = 0,
    Inet = 1,
    Inet6 = 2,
};

struct PeerInfo {
    char name[32];
    char address[48];
    char endpoint[256];
    char resolved_endpoint[64];
    char derived_public_key[64];
    std::int32_t last_handshake_seconds;
    std::int32_t last_rx_seconds;
    std::int32_t last_tx_seconds;
    std::int32_t last_debug_probe_seconds;
    std::uint32_t last_error_code;
    std::uint32_t debug_probe_action;
    std::uint32_t debug_probe_status;
    std::uint16_t persistent_keepalive_interval;
    std::uint8_t runtime_state;
    std::uint8_t error_stage;
    /*
     * Stores `PeerResolvedFamily` values, not native `AF_*` socket constants.
     * This keeps the IPC surface aligned with the project-owned endpoint model.
     */
    std::uint8_t resolved_family;
    std::uint8_t reserved0;
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

struct BuildInfo {
    char version[32];
    char build_id[64];
};

struct PeerSelectionRequest {
    std::int32_t peer_index;
    std::uint32_t reserved;
};

struct DebugTriggerRequest {
    std::uint32_t action;
    std::uint32_t reserved;
};

struct PacketSubmissionResult {
    std::uint64_t packet_id;
    std::uint32_t status;
    std::uint32_t packet_size;
    std::uint32_t activation_generation;
    std::int32_t peer_index;
};

struct PacketReceiveResult {
    std::uint64_t packet_id;
    std::uint32_t status;
    std::uint32_t packet_size;
    std::uint32_t activation_generation;
    std::int32_t peer_index;
};

constexpr inline const char *GetPeerRuntimeStateName(PeerRuntimeState state) {
    switch (state) {
        case PeerRuntimeState::Inactive:
            return "inactive";
        case PeerRuntimeState::ResolvingEndpoint:
            return "resolving";
        case PeerRuntimeState::Handshaking:
            return "handshaking";
        case PeerRuntimeState::Active:
            return "active";
        case PeerRuntimeState::Error:
            return "error";
    }

    return "unknown";
}

constexpr inline const char *GetPeerErrorStageName(PeerErrorStage stage) {
    switch (stage) {
        case PeerErrorStage::None:
            return "none";
        case PeerErrorStage::Config:
            return "config";
        case PeerErrorStage::ResolveEndpoint:
            return "resolve";
        case PeerErrorStage::Handshake:
            return "handshake";
        case PeerErrorStage::Transport:
            return "transport";
        case PeerErrorStage::Internal:
            return "internal";
    }

    return "unknown";
}

constexpr inline const char *GetPeerErrorCodeName(PeerErrorCode code) {
    switch (code) {
        case PeerErrorCode::None:
            return "none";
        case PeerErrorCode::ConfigInvalid:
            return "config invalid";
        case PeerErrorCode::EndpointMissing:
            return "endpoint missing";
        case PeerErrorCode::EndpointMalformed:
            return "endpoint malformed";
        case PeerErrorCode::EndpointResolutionFailed:
            return "endpoint resolution failed";
        case PeerErrorCode::TransportInitFailed:
            return "transport init failed";
        case PeerErrorCode::InternalFailure:
            return "internal failure";
        case PeerErrorCode::KeyInvalid:
            return "key invalid";
        case PeerErrorCode::HandshakeInitFailed:
            return "handshake init failed";
        case PeerErrorCode::TransportOpenFailed:
            return "transport open failed";
        case PeerErrorCode::TransportSendFailed:
            return "transport send failed";
        case PeerErrorCode::TransportReceiveFailed:
            return "transport receive failed";
        case PeerErrorCode::HandshakeTimedOut:
            return "handshake timed out";
    }

    return "unknown";
}

constexpr inline const char *GetPeerResolvedFamilyName(PeerResolvedFamily family) {
    switch (family) {
        case PeerResolvedFamily::Unspecified:
            return "unspecified";
        case PeerResolvedFamily::Inet:
            return "inet";
        case PeerResolvedFamily::Inet6:
            return "inet6";
    }

    return "unknown";
}

constexpr inline const char *GetDebugTriggerActionName(DebugTriggerAction action) {
    switch (action) {
        case DebugTriggerAction::None:
            return "none";
        case DebugTriggerAction::PingTunnelPeer:
            return "ping-tunnel-peer";
        case DebugTriggerAction::PingPublicDns:
            return "ping-public-dns";
    }

    return "unknown";
}

constexpr inline const char *GetDebugProbeStatusName(DebugProbeStatus status) {
    switch (status) {
        case DebugProbeStatus::None:
            return "none";
        case DebugProbeStatus::Queued:
            return "queued";
        case DebugProbeStatus::Sent:
            return "sent";
        case DebugProbeStatus::ReplyValidated:
            return "reply validated";
        case DebugProbeStatus::ReplyRejected:
            return "reply rejected";
        case DebugProbeStatus::TimedOut:
            return "timed out";
        case DebugProbeStatus::StaleActivation:
            return "stale activation";
        case DebugProbeStatus::InvalidState:
            return "invalid state";
        case DebugProbeStatus::BuildFailed:
            return "build failed";
        case DebugProbeStatus::SendFailed:
            return "send failed";
    }

    return "unknown";
}

constexpr inline const char *GetPacketApiStatusName(PacketApiStatus status) {
    switch (status) {
        case PacketApiStatus::Success:
            return "success";
        case PacketApiStatus::Queued:
            return "queued";
        case PacketApiStatus::QueueEmpty:
            return "queue empty";
        case PacketApiStatus::QueueFull:
            return "queue full";
        case PacketApiStatus::TunnelUnavailable:
            return "tunnel unavailable";
        case PacketApiStatus::MalformedPacket:
            return "malformed packet";
        case PacketApiStatus::OutputBufferTooSmall:
            return "output buffer too small";
        case PacketApiStatus::StaleActivation:
            return "stale activation";
        case PacketApiStatus::AccessDenied:
            return "access denied";
        case PacketApiStatus::InternalError:
            return "internal error";
    }

    return "unknown";
}

static_assert(std::is_standard_layout_v<PeerInfo>);
static_assert(std::is_trivially_copyable_v<PeerInfo>);
static_assert(std::is_standard_layout_v<DaemonStatus>);
static_assert(std::is_trivially_copyable_v<DaemonStatus>);
static_assert(std::is_standard_layout_v<BuildInfo>);
static_assert(std::is_trivially_copyable_v<BuildInfo>);
static_assert(std::is_standard_layout_v<PeerSelectionRequest>);
static_assert(std::is_trivially_copyable_v<PeerSelectionRequest>);
static_assert(std::is_standard_layout_v<DebugTriggerRequest>);
static_assert(std::is_trivially_copyable_v<DebugTriggerRequest>);
static_assert(std::is_standard_layout_v<PacketSubmissionResult>);
static_assert(std::is_trivially_copyable_v<PacketSubmissionResult>);
static_assert(sizeof(PacketSubmissionResult) == 24);
static_assert(std::is_standard_layout_v<PacketReceiveResult>);
static_assert(std::is_trivially_copyable_v<PacketReceiveResult>);
static_assert(sizeof(PacketReceiveResult) == 24);

} // namespace wgnx
