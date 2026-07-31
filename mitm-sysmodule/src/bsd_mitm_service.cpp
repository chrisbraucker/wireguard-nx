#include "bsd_mitm_service.hpp"

#include "bsd_endpoint.hpp"
#include "bsd_response.hpp"
#include "bsd_tunneled_contract.hpp"
#include "logger.hpp"
#include "mitm_policy.hpp"
#include "mitm_runtime_policy.hpp"
#include "tunnel_discovery_service.hpp"
#include "tunnel_flow_worker.hpp"

#include <stratosphere/sf/sf_mitm_dispatch.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <poll.h>
#include <span>
#include <sys/socket.h>

namespace wgnx::mitm {

namespace {

constexpr s32 BsdSocketDatagram = 2;
constexpr s32 BsdProtocolUdp = 17;
constexpr std::size_t MaximumPollDescriptors = 4;

[[nodiscard]] bool DecodeIpv4Endpoint(const ams::sf::InAutoSelectBuffer& address, TunnelFlowEndpoint* out_endpoint) {
    if (address.GetPointer() == nullptr || out_endpoint == nullptr) {
        return false;
    }

    BsdIpv4Endpoint decoded{};
    if (!DecodeBsdIpv4Endpoint({static_cast<const std::uint8_t*>(address.GetPointer()), address.GetSize()}, std::addressof(decoded))) {
        return false;
    }

    std::memcpy(out_endpoint->address, decoded.address.data(), decoded.address.size());
    out_endpoint->port = decoded.port;
    return true;
}

void EncodeIpv4Endpoint(const TunnelFlowEndpoint& endpoint, void* out_buffer) {
    BsdIpv4Endpoint encoded{};
    std::memcpy(encoded.address.data(), endpoint.address, encoded.address.size());
    encoded.port = endpoint.port;
    const bool written = EncodeBsdIpv4Endpoint(encoded, {static_cast<std::uint8_t*>(out_buffer), sizeof(BsdSockAddrIn)});
    AMS_ABORT_UNLESS(written);
}

void EncodeIpv4Endpoint(const BsdIpv4Endpoint& endpoint, void* out_buffer) {
    const bool written = EncodeBsdIpv4Endpoint(endpoint, {static_cast<std::uint8_t*>(out_buffer), sizeof(BsdSockAddrIn)});
    AMS_ABORT_UNLESS(written);
}

[[nodiscard]] bool IsUdpIpv4Socket(const s32 domain, const s32 type, const s32 protocol) {
    return domain == BsdAddressFamilyInet && type == BsdSocketDatagram && (protocol == 0 || protocol == BsdProtocolUdp);
}

[[nodiscard]] const char* TunnelFlowResultName(const TunnelFlowResult result) {
    switch (result) {
    case TunnelFlowResult::Opened:
        return "opened";
    case TunnelFlowResult::RouteNotCovered:
        return "route_not_covered";
    case TunnelFlowResult::TunnelUnavailable:
        return "tunnel_unavailable";
    case TunnelFlowResult::BlockedByPolicy:
        return "blocked_by_policy";
    case TunnelFlowResult::SocketError:
        return "socket_error";
    case TunnelFlowResult::MessageTooLarge:
        return "message_too_large";
    case TunnelFlowResult::QueueFull:
        return "queue_full";
    case TunnelFlowResult::WouldBlock:
        return "would_block";
    case TunnelFlowResult::Closed:
        return "closed";
    }
    return "unknown";
}

} // namespace

std::atomic_uint32_t BsdMitmService::s_next_session_id{0};

BsdMitmService::BsdMitmService(std::shared_ptr<::Service>&& forward_service, const ams::sm::MitmProcessInfo& client_info)
    : MitmServiceImplBase(std::move(forward_service), client_info),
      m_owner(static_cast<std::uint64_t>(s_next_session_id.fetch_add(1, std::memory_order_relaxed)) + 1U) {
    logger::Log(
        "bsd:s session accepted owner=%llu pid=%llu program_id=0x%016llX",
        static_cast<unsigned long long>(m_owner),
        static_cast<unsigned long long>(client_info.process_id.value),
        static_cast<unsigned long long>(client_info.program_id.value)
    );
}

BsdMitmService::~BsdMitmService() {
    GetTunnelFlowWorker().CloseOwner(m_owner);
    logger::Log("bsd:s session released owner=%llu", static_cast<unsigned long long>(m_owner));
}

bool BsdMitmService::ShouldMitm(const ams::sm::MitmProcessInfo& client_info) {
    if (!IsRequesterForwarderProgram(client_info.program_id.value) || IsProgramExcludedFromBsdSystemMitm(client_info.program_id.value) ||
        !IsRequesterBsdSystemInterceptionEnabled()) {
        return false;
    }

    constexpr bool intercept = ShouldInterceptRequesterBsdSession();
    logger::Log(
        "bsd:s ShouldMitm requester pid=%llu decision=%u admission=all_requester_sessions",
        static_cast<unsigned long long>(client_info.process_id.value),
        static_cast<unsigned>(intercept)
    );
    return intercept;
}

BsdMitmService::SocketState* BsdMitmService::FindSocket(const s32 descriptor) {
    for (SocketState& socket : m_sockets) {
        if (socket.occupied && socket.descriptor == descriptor) {
            return std::addressof(socket);
        }
    }
    return nullptr;
}

const char* BsdMitmService::SocketRouteName(const SocketState* socket) {
    if (socket == nullptr) {
        return "untracked";
    }
    return BsdSocketRouteStateName(socket->route);
}

bool BsdMitmService::CaptureVisibleLocalEndpoint(SocketState& socket) {
    std::array<std::uint8_t, sizeof(BsdSockAddrIn)> address{};
    BsdResultAndAddressLength output{};
    const Result rc = serviceMitmDispatchInOut(
        m_forward_service.get(),
        16,
        socket.descriptor,
        output,
        .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect},
        .buffers = {{address.data(), address.size()}}
    );
    BsdIpv4Endpoint endpoint{};
    if (R_FAILED(rc) || output.response.result != 0 || output.response.error != 0 || output.address_size < sizeof(BsdSockAddrIn) ||
        !DecodeBsdIpv4Endpoint(address, std::addressof(endpoint))) {
        logger::Log(
            "bsd:s visible endpoint capture failed owner=%llu fd=%d rc=0x%08X result=%d errno=%d address_size=%u",
            static_cast<unsigned long long>(m_owner),
            socket.descriptor,
            static_cast<unsigned>(rc),
            output.response.result,
            output.response.error,
            output.address_size
        );
        return false;
    }

    socket.visible_local = endpoint;
    socket.visible_local_valid = true;
    logger::Log(
        "bsd:s visible endpoint captured owner=%llu fd=%d local=%u.%u.%u.%u:%u",
        static_cast<unsigned long long>(m_owner),
        socket.descriptor,
        endpoint.address[0],
        endpoint.address[1],
        endpoint.address[2],
        endpoint.address[3],
        endpoint.port
    );
    return true;
}

void BsdMitmService::ForgetSocket(const s32 descriptor) {
    if (SocketState* socket = FindSocket(descriptor); socket != nullptr) {
        socket->route = AdvanceBsdSocketRoute(socket->route, BsdSocketRouteEvent::Close);
        logger::Log(
            "bsd:s socket forget owner=%llu fd=%d route=%s",
            static_cast<unsigned long long>(m_owner),
            descriptor,
            SocketRouteName(socket)
        );
        *socket = {};
        return;
    }
    logger::Log("bsd:s socket forget miss owner=%llu fd=%d", static_cast<unsigned long long>(m_owner), descriptor);
}

ams::Result
BsdMitmService::Socket(ams::sf::Out<s32> out_fd, ams::sf::Out<s32> out_errno, const s32 domain, const s32 type, const s32 protocol) {
    struct {
        s32 domain;
        s32 type;
        s32 protocol;
    } input{domain, type, protocol};
    BsdResultAndErrno output{};
    const Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 2, input, output);
    out_errno.SetValue(output.error);
    out_fd.SetValue(output.result);
    bool tracked = false;
    bool table_full = false;
    const bool udp_ipv4 = IsUdpIpv4Socket(domain, type, protocol);
    if (R_SUCCEEDED(rc) && output.result >= 0) {
        for (SocketState& socket : m_sockets) {
            if (!socket.occupied) {
                socket = {.occupied = true, .udp_ipv4 = udp_ipv4, .descriptor = output.result};
                tracked = true;
                break;
            }
        }
        table_full = !tracked;
    }
    logger::Log(
        "bsd:s socket owner=%llu domain=%d type=%d protocol=%d rc=0x%08X errno=%d fd=%d udp_ipv4=%u tracked=%u table_full=%u",
        static_cast<unsigned long long>(m_owner),
        domain,
        type,
        protocol,
        static_cast<unsigned>(rc),
        output.error,
        output.result,
        udp_ipv4 ? 1U : 0U,
        tracked ? 1U : 0U,
        table_full ? 1U : 0U
    );
    return rc;
}

ams::Result BsdMitmService::Connect(
    ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, const s32 fd, const ams::sf::InAutoSelectBuffer& address
) {
    SocketState* socket = FindSocket(fd);
    logger::Log(
        "bsd:s connect enter owner=%llu fd=%d route=%s address_bytes=%zu",
        static_cast<unsigned long long>(m_owner),
        fd,
        SocketRouteName(socket),
        address.GetSize()
    );

    if (socket != nullptr && socket->route == BsdSocketRouteState::Tunneled) {
        out_result.SetValue(-1);
        out_errno.SetValue(EISCONN);
        logger::Log(
            "bsd:s connect rejected owner=%llu fd=%d route=tunneled reason=already_connected",
            static_cast<unsigned long long>(m_owner),
            fd
        );
        R_SUCCEED();
    }
    if (socket != nullptr && socket->route == BsdSocketRouteState::OpeningTunnel) {
        out_result.SetValue(-1);
        out_errno.SetValue(EALREADY);
        logger::Log(
            "bsd:s connect rejected owner=%llu fd=%d route=opening_tunnel reason=operation_in_progress",
            static_cast<unsigned long long>(m_owner),
            fd
        );
        R_SUCCEED();
    }
    if (socket != nullptr && IsTerminalSocketRoute(socket->route)) {
        out_result.SetValue(-1);
        out_errno.SetValue(ECONNABORTED);
        logger::Log(
            "bsd:s connect rejected owner=%llu fd=%d route=%s reason=terminal_socket",
            static_cast<unsigned long long>(m_owner),
            fd,
            SocketRouteName(socket)
        );
        R_SUCCEED();
    }

    TunnelFlowEndpoint remote{};
    const bool decoded_endpoint = DecodeIpv4Endpoint(address, std::addressof(remote));
    const bool eligible = socket != nullptr && socket->udp_ipv4 && CanOpenTunnelFlow(socket->route) && decoded_endpoint;
    TunnelFlowResult tunnel_result = TunnelFlowResult::TunnelUnavailable;
    if (eligible) {
        socket->route = AdvanceBsdSocketRoute(socket->route, BsdSocketRouteEvent::BeginTunnelOpen);
        GetTunnelDiscoveryService().RequestForInterceptedTraffic();
        tunnel_result = GetTunnelFlowWorker().OpenConnectedUdp(m_owner, fd, remote);
        logger::Log(
            "bsd:s connect tunnel-open owner=%llu fd=%d remote=%u.%u.%u.%u:%u result=%s",
            static_cast<unsigned long long>(m_owner),
            fd,
            remote.address[0],
            remote.address[1],
            remote.address[2],
            remote.address[3],
            remote.port,
            TunnelFlowResultName(tunnel_result)
        );
        if (tunnel_result == TunnelFlowResult::Opened) {
            // The retained descriptor selects the native local address and ephemeral
            // port we expose to the application while payload traffic stays on wgnx:tun.
            BsdResultAndErrno anchor_connect{};
            const Result anchor_rc = serviceMitmDispatchInOut(
                m_forward_service.get(),
                14,
                fd,
                anchor_connect,
                .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcAutoSelect},
                .buffers = {{address.GetPointer(), address.GetSize()}}
            );
            if (R_FAILED(anchor_rc) || anchor_connect.result != 0 || anchor_connect.error != 0 || !CaptureVisibleLocalEndpoint(*socket)) {
                GetTunnelFlowWorker().Close(m_owner, fd);
                socket->route = AdvanceBsdSocketRoute(socket->route, BsdSocketRouteEvent::TunnelFailed);
                out_result.SetValue(-1);
                out_errno.SetValue(R_SUCCEEDED(anchor_rc) && anchor_connect.error != 0 ? anchor_connect.error : EIO);
                logger::Log(
                    "bsd:s connect tunnel-anchor failed owner=%llu fd=%d rc=0x%08X result=%d errno=%d",
                    static_cast<unsigned long long>(m_owner),
                    fd,
                    static_cast<unsigned>(anchor_rc),
                    anchor_connect.result,
                    anchor_connect.error
                );
                R_RETURN(anchor_rc);
            }
            std::memcpy(socket->remote.address.data(), remote.address, socket->remote.address.size());
            socket->remote.port = remote.port;
            socket->route = AdvanceBsdSocketRoute(socket->route, BsdSocketRouteEvent::TunnelOpened);
            out_result.SetValue(0);
            out_errno.SetValue(0);
            logger::Log(
                "bsd:s connect tunneled owner=%llu fd=%d remote=%u.%u.%u.%u:%u visible_local=%u.%u.%u.%u:%u",
                static_cast<unsigned long long>(m_owner),
                fd,
                remote.address[0],
                remote.address[1],
                remote.address[2],
                remote.address[3],
                remote.port,
                socket->visible_local.address[0],
                socket->visible_local.address[1],
                socket->visible_local.address[2],
                socket->visible_local.address[3],
                socket->visible_local.port
            );
            R_SUCCEED();
        }
        if (tunnel_result != TunnelFlowResult::RouteNotCovered && tunnel_result != TunnelFlowResult::TunnelUnavailable) {
            socket->route = AdvanceBsdSocketRoute(
                socket->route,
                tunnel_result == TunnelFlowResult::BlockedByPolicy ? BsdSocketRouteEvent::TunnelBypassed : BsdSocketRouteEvent::TunnelFailed
            );
            out_result.SetValue(-1);
            out_errno.SetValue(ErrnoForResult(tunnel_result));
            R_SUCCEED();
        }
        socket->route = AdvanceBsdSocketRoute(socket->route, BsdSocketRouteEvent::TunnelBypassed);
    }

    if (!eligible) {
        const char* reason = socket == nullptr                              ? "untracked_fd"
                             : !socket->udp_ipv4                            ? "not_ipv4_udp"
                             : socket->route == BsdSocketRouteState::Direct ? "already_direct"
                             : !decoded_endpoint                            ? "invalid_endpoint"
                                                                            : "unknown";
        logger::Log(
            "bsd:s connect bypass owner=%llu fd=%d reason=%s address_bytes=%zu",
            static_cast<unsigned long long>(m_owner),
            fd,
            reason,
            address.GetSize()
        );
    } else {
        logger::Log(
            "bsd:s connect bypass owner=%llu fd=%d reason=tunnel_%s",
            static_cast<unsigned long long>(m_owner),
            fd,
            TunnelFlowResultName(tunnel_result)
        );
    }

    BsdResultAndErrno output{};
    const Result rc = serviceMitmDispatchInOut(
        m_forward_service.get(),
        14,
        fd,
        output,
        .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcAutoSelect},
        .buffers = {{address.GetPointer(), address.GetSize()}}
    );
    out_result.SetValue(output.result);
    out_errno.SetValue(output.error);
    if (socket != nullptr && socket->route == BsdSocketRouteState::Created && R_SUCCEEDED(rc) && output.result == 0 && output.error == 0) {
        socket->route = AdvanceBsdSocketRoute(socket->route, BsdSocketRouteEvent::DirectConnected);
    }
    logger::Log("bsd:s connect direct owner=%llu fd=%d rc=0x%08X", static_cast<unsigned long long>(m_owner), fd, static_cast<unsigned>(rc));
    return rc;
}

ams::Result BsdMitmService::Send(
    ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, const s32 fd, const s32 flags, const ams::sf::InAutoSelectBuffer& buffer
) {
    const SocketState* socket = FindSocket(fd);
    logger::LogPacket(
        "bsd:s send enter owner=%llu fd=%d route=%s bytes=%zu flags=0x%X",
        static_cast<unsigned long long>(m_owner),
        fd,
        SocketRouteName(socket),
        buffer.GetSize(),
        static_cast<unsigned>(flags)
    );
    if (socket != nullptr && UsesTunnelFlow(socket->route)) {
        if (!SupportsTunneledMessageFlags(flags)) {
            out_errno.SetValue(EOPNOTSUPP);
            out_size.SetValue(-1);
            logger::Log(
                "bsd:s send rejected tunneled owner=%llu fd=%d flags=0x%X reason=unsupported_flags",
                static_cast<unsigned long long>(m_owner),
                fd,
                static_cast<unsigned>(flags)
            );
            R_SUCCEED();
        }
        const TunnelFlowResult result = GetTunnelFlowWorker().Send(m_owner, fd, buffer.GetPointer(), buffer.GetSize());
        out_errno.SetValue(ErrnoForResult(result));
        out_size.SetValue(result == TunnelFlowResult::Opened ? static_cast<s32>(buffer.GetSize()) : -1);
        logger::LogPacket(
            "bsd:s send tunneled owner=%llu fd=%d bytes=%zu result=%s",
            static_cast<unsigned long long>(m_owner),
            fd,
            buffer.GetSize(),
            TunnelFlowResultName(result)
        );
        R_SUCCEED();
    }
    if (socket != nullptr && IsTerminalSocketRoute(socket->route)) {
        out_errno.SetValue(ECONNABORTED);
        out_size.SetValue(-1);
        R_SUCCEED();
    }
    struct {
        s32 fd;
        s32 flags;
    } input{fd, flags};
    BsdResultAndErrno output{};
    const Result rc = serviceMitmDispatchInOut(
        m_forward_service.get(),
        10,
        input,
        output,
        .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcAutoSelect},
        .buffers = {{buffer.GetPointer(), buffer.GetSize()}}
    );
    out_errno.SetValue(output.error);
    out_size.SetValue(output.result);
    logger::LogPacket(
        "bsd:s send direct owner=%llu fd=%d bytes=%zu flags=0x%X rc=0x%08X errno=%d result=%d",
        static_cast<unsigned long long>(m_owner),
        fd,
        buffer.GetSize(),
        static_cast<unsigned>(flags),
        static_cast<unsigned>(rc),
        output.error,
        output.result
    );
    return rc;
}

ams::Result BsdMitmService::SendTo(
    ams::sf::Out<s32> out_size,
    ams::sf::Out<s32> out_errno,
    const s32 fd,
    const s32 flags,
    const ams::sf::InAutoSelectBuffer& buffer,
    const ams::sf::InAutoSelectBuffer& address
) {
    const SocketState* socket = FindSocket(fd);
    logger::Log(
        "bsd:s sendto enter owner=%llu fd=%d route=%s bytes=%zu address_bytes=%zu flags=0x%X",
        static_cast<unsigned long long>(m_owner),
        fd,
        SocketRouteName(socket),
        buffer.GetSize(),
        address.GetSize(),
        static_cast<unsigned>(flags)
    );
    if (socket != nullptr && UsesTunnelFlow(socket->route)) {
        out_errno.SetValue(EOPNOTSUPP);
        out_size.SetValue(-1);
        logger::Log(
            "bsd:s sendto rejected tunneled owner=%llu fd=%d bytes=%zu reason=connected_udp_only",
            static_cast<unsigned long long>(m_owner),
            fd,
            buffer.GetSize()
        );
        R_SUCCEED();
    }
    if (socket != nullptr && IsTerminalSocketRoute(socket->route)) {
        out_errno.SetValue(ECONNABORTED);
        out_size.SetValue(-1);
        R_SUCCEED();
    }
    struct {
        s32 fd;
        s32 flags;
    } input{fd, flags};
    BsdResultAndErrno output{};
    const Result rc = serviceMitmDispatchInOut(
        m_forward_service.get(),
        11,
        input,
        output,
        .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcAutoSelect, SfBufferAttr_In | SfBufferAttr_HipcAutoSelect},
        .buffers = {{buffer.GetPointer(), buffer.GetSize()}, {address.GetPointer(), address.GetSize()}}
    );
    out_errno.SetValue(output.error);
    out_size.SetValue(output.result);
    logger::Log(
        "bsd:s sendto direct owner=%llu fd=%d bytes=%zu address_bytes=%zu flags=0x%X rc=0x%08X errno=%d result=%d",
        static_cast<unsigned long long>(m_owner),
        fd,
        buffer.GetSize(),
        address.GetSize(),
        static_cast<unsigned>(flags),
        static_cast<unsigned>(rc),
        output.error,
        output.result
    );
    return rc;
}

ams::Result BsdMitmService::Recv(
    ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, const s32 fd, const s32 flags, ams::sf::OutAutoSelectBuffer buffer
) {
    const SocketState* socket = FindSocket(fd);
    logger::LogPacket(
        "bsd:s recv enter owner=%llu fd=%d route=%s capacity=%zu flags=0x%X",
        static_cast<unsigned long long>(m_owner),
        fd,
        SocketRouteName(socket),
        buffer.GetSize(),
        static_cast<unsigned>(flags)
    );
    if (socket != nullptr && UsesTunnelFlow(socket->route)) {
        if (!SupportsTunneledMessageFlags(flags)) {
            out_errno.SetValue(EOPNOTSUPP);
            out_size.SetValue(-1);
            logger::Log(
                "bsd:s recv rejected tunneled owner=%llu fd=%d flags=0x%X reason=unsupported_flags",
                static_cast<unsigned long long>(m_owner),
                fd,
                static_cast<unsigned>(flags)
            );
            R_SUCCEED();
        }
        const TunnelReceiveResult result = GetTunnelFlowWorker().Receive(m_owner, fd, buffer.GetPointer(), buffer.GetSize());
        out_errno.SetValue(ErrnoForResult(result.result));
        out_size.SetValue(result.result == TunnelFlowResult::Opened ? static_cast<s32>(result.size) : -1);
        logger::LogPacket(
            "bsd:s recv tunneled owner=%llu fd=%d capacity=%zu result=%s bytes=%zu",
            static_cast<unsigned long long>(m_owner),
            fd,
            buffer.GetSize(),
            TunnelFlowResultName(result.result),
            result.size
        );
        R_SUCCEED();
    }
    if (socket != nullptr && IsTerminalSocketRoute(socket->route)) {
        out_errno.SetValue(ECONNABORTED);
        out_size.SetValue(-1);
        R_SUCCEED();
    }
    struct {
        s32 fd;
        s32 flags;
    } input{fd, flags};
    BsdResultAndErrno output{};
    const Result rc = serviceMitmDispatchInOut(
        m_forward_service.get(),
        8,
        input,
        output,
        .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect},
        .buffers = {{buffer.GetPointer(), buffer.GetSize()}}
    );
    out_errno.SetValue(output.error);
    out_size.SetValue(output.result);
    logger::LogPacket(
        "bsd:s recv direct owner=%llu fd=%d capacity=%zu flags=0x%X rc=0x%08X errno=%d result=%d",
        static_cast<unsigned long long>(m_owner),
        fd,
        buffer.GetSize(),
        static_cast<unsigned>(flags),
        static_cast<unsigned>(rc),
        output.error,
        output.result
    );
    return rc;
}

ams::Result BsdMitmService::RecvFrom(
    ams::sf::Out<s32> out_size,
    ams::sf::Out<s32> out_errno,
    ams::sf::Out<u32> out_addr_len,
    const s32 fd,
    const s32 flags,
    ams::sf::OutAutoSelectBuffer buffer,
    ams::sf::OutAutoSelectBuffer address
) {
    const SocketState* socket = FindSocket(fd);
    logger::LogPacket(
        "bsd:s recvfrom enter owner=%llu fd=%d route=%s capacity=%zu address_capacity=%zu flags=0x%X",
        static_cast<unsigned long long>(m_owner),
        fd,
        SocketRouteName(socket),
        buffer.GetSize(),
        address.GetSize(),
        static_cast<unsigned>(flags)
    );
    if (socket != nullptr && UsesTunnelFlow(socket->route)) {
        if (!SupportsTunneledMessageFlags(flags)) {
            out_errno.SetValue(EOPNOTSUPP);
            out_size.SetValue(-1);
            out_addr_len.SetValue(0);
            logger::Log(
                "bsd:s recvfrom rejected tunneled owner=%llu fd=%d flags=0x%X reason=unsupported_flags",
                static_cast<unsigned long long>(m_owner),
                fd,
                static_cast<unsigned>(flags)
            );
            R_SUCCEED();
        }
        const TunnelReceiveResult result = GetTunnelFlowWorker().Receive(m_owner, fd, buffer.GetPointer(), buffer.GetSize());
        out_errno.SetValue(ErrnoForResult(result.result));
        out_size.SetValue(result.result == TunnelFlowResult::Opened ? static_cast<s32>(result.size) : -1);
        if (result.result == TunnelFlowResult::Opened && address.GetSize() >= sizeof(BsdSockAddrIn)) {
            EncodeIpv4Endpoint(result.remote, address.GetPointer());
            out_addr_len.SetValue(sizeof(BsdSockAddrIn));
        } else {
            out_addr_len.SetValue(0);
        }
        logger::LogPacket(
            "bsd:s recvfrom tunneled owner=%llu fd=%d capacity=%zu result=%s bytes=%zu",
            static_cast<unsigned long long>(m_owner),
            fd,
            buffer.GetSize(),
            TunnelFlowResultName(result.result),
            result.size
        );
        R_SUCCEED();
    }
    if (socket != nullptr && IsTerminalSocketRoute(socket->route)) {
        out_errno.SetValue(ECONNABORTED);
        out_size.SetValue(-1);
        out_addr_len.SetValue(0);
        R_SUCCEED();
    }
    struct {
        s32 fd;
        s32 flags;
    } input{fd, flags};
    BsdResultAndAddressLength output{};
    const Result rc = serviceMitmDispatchInOut(
        m_forward_service.get(),
        9,
        input,
        output,
        .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect, SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect},
        .buffers = {{buffer.GetPointer(), buffer.GetSize()}, {address.GetPointer(), address.GetSize()}}
    );
    out_size.SetValue(output.response.result);
    out_errno.SetValue(output.response.error);
    out_addr_len.SetValue(output.address_size);
    logger::LogPacket(
        "bsd:s recvfrom direct owner=%llu fd=%d capacity=%zu address_capacity=%zu flags=0x%X rc=0x%08X errno=%d result=%d address_size=%u",
        static_cast<unsigned long long>(m_owner),
        fd,
        buffer.GetSize(),
        address.GetSize(),
        static_cast<unsigned>(flags),
        static_cast<unsigned>(rc),
        output.response.error,
        output.response.result,
        output.address_size
    );
    return rc;
}

ams::Result BsdMitmService::Poll(
    ams::sf::Out<s32> out_count,
    ams::sf::Out<s32> out_errno,
    const ams::sf::InAutoSelectBuffer& fds_in,
    ams::sf::OutAutoSelectBuffer fds_out,
    const s32 nfds,
    const s32 timeout
) {
    if (nfds < 0 || static_cast<std::size_t>(nfds) > MaximumPollDescriptors ||
        fds_in.GetSize() < static_cast<std::size_t>(nfds) * sizeof(pollfd) ||
        fds_out.GetSize() < static_cast<std::size_t>(nfds) * sizeof(pollfd)) {
        out_errno.SetValue(EINVAL);
        out_count.SetValue(-1);
        logger::Log(
            "bsd:s poll rejected owner=%llu nfds=%d input_bytes=%zu output_bytes=%zu reason=invalid_arguments",
            static_cast<unsigned long long>(m_owner),
            nfds,
            fds_in.GetSize(),
            fds_out.GetSize()
        );
        R_SUCCEED();
    }
    std::array<pollfd, MaximumPollDescriptors> descriptors{};
    std::memcpy(descriptors.data(), fds_in.GetPointer(), static_cast<std::size_t>(nfds) * sizeof(pollfd));
    bool any_virtual = false;
    bool any_direct = false;
    logger::LogPacket(
        "bsd:s poll enter owner=%llu nfds=%d timeout_ms=%d input_bytes=%zu output_bytes=%zu",
        static_cast<unsigned long long>(m_owner),
        nfds,
        timeout,
        fds_in.GetSize(),
        fds_out.GetSize()
    );
    for (s32 index = 0; index < nfds; ++index) {
        const SocketState* socket = FindSocket(descriptors[index].fd);
        logger::LogPacket(
            "bsd:s poll descriptor owner=%llu index=%d fd=%d events=0x%X route=%s",
            static_cast<unsigned long long>(m_owner),
            index,
            descriptors[index].fd,
            static_cast<unsigned>(descriptors[index].events),
            SocketRouteName(socket)
        );
        descriptors[index].revents = 0;
        any_virtual = any_virtual || (socket != nullptr && !CanForwardToUpstreamBsd(socket->route));
        any_direct = any_direct || socket == nullptr || (socket != nullptr && CanForwardToUpstreamBsd(socket->route));
    }
    if (!any_virtual) {
        struct {
            s32 descriptor_count;
            s32 timeout_milliseconds;
        } input{nfds, timeout};
        BsdResultAndErrno output{};
        const Result rc = serviceMitmDispatchInOut(
            m_forward_service.get(),
            6,
            input,
            output,
            .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcAutoSelect, SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect},
            .buffers = {{fds_in.GetPointer(), fds_in.GetSize()}, {fds_out.GetPointer(), fds_out.GetSize()}}
        );
        out_errno.SetValue(output.error);
        out_count.SetValue(output.result);
        logger::LogPacket(
            "bsd:s poll direct owner=%llu nfds=%d timeout_ms=%d rc=0x%08X errno=%d ready=%d",
            static_cast<unsigned long long>(m_owner),
            nfds,
            timeout,
            static_cast<unsigned>(rc),
            output.error,
            output.result
        );
        return rc;
    }
    if (any_direct) {
        out_errno.SetValue(EOPNOTSUPP);
        out_count.SetValue(-1);
        logger::Log(
            "bsd:s poll rejected owner=%llu nfds=%d reason=mixed_direct_and_virtual",
            static_cast<unsigned long long>(m_owner),
            nfds
        );
        R_SUCCEED();
    }
    if (const SocketState* socket = FindSocket(descriptors[0].fd); socket != nullptr && IsTerminalSocketRoute(socket->route)) {
        descriptors[0].revents = POLLHUP;
        std::memcpy(fds_out.GetPointer(), descriptors.data(), sizeof(pollfd));
        out_errno.SetValue(0);
        out_count.SetValue(1);
        logger::Log(
            "bsd:s poll terminal owner=%llu fd=%d revents=0x%X",
            static_cast<unsigned long long>(m_owner),
            descriptors[0].fd,
            static_cast<unsigned>(descriptors[0].revents)
        );
        R_SUCCEED();
    }
    if (!SupportsTunneledPoll(nfds, descriptors[0].events)) {
        out_errno.SetValue(EOPNOTSUPP);
        out_count.SetValue(-1);
        logger::Log(
            "bsd:s poll rejected owner=%llu nfds=%d events=0x%X reason=unsupported_tunneled_contract",
            static_cast<unsigned long long>(m_owner),
            nfds,
            static_cast<unsigned>(descriptors[0].events)
        );
        R_SUCCEED();
    }
    const TunnelPollResult result = GetTunnelFlowWorker().Poll(m_owner, descriptors[0].fd, descriptors[0].events, timeout);
    const s32 poll_errno = TunneledPollErrno(result.result);
    if (poll_errno != 0) {
        std::memcpy(fds_out.GetPointer(), descriptors.data(), sizeof(pollfd));
        out_errno.SetValue(poll_errno);
        out_count.SetValue(-1);
        logger::Log(
            "bsd:s poll failed owner=%llu fd=%d result=%s errno=%d",
            static_cast<unsigned long long>(m_owner),
            descriptors[0].fd,
            TunnelFlowResultName(result.result),
            poll_errno
        );
        R_SUCCEED();
    }
    descriptors[0].revents = result.revents;
    const s32 ready_count = descriptors[0].revents != 0 ? 1 : 0;
    std::memcpy(fds_out.GetPointer(), descriptors.data(), sizeof(pollfd));
    out_errno.SetValue(0);
    out_count.SetValue(ready_count);
    logger::LogPacket(
        "bsd:s poll tunneled owner=%llu nfds=%d timeout_ms=%d ready=%d",
        static_cast<unsigned long long>(m_owner),
        nfds,
        timeout,
        ready_count
    );
    R_SUCCEED();
}

ams::Result
BsdMitmService::Bind(ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, const s32 fd, const ams::sf::InAutoSelectBuffer& address) {
    if (const SocketState* socket = FindSocket(fd); socket != nullptr && UsesTunnelFlow(socket->route)) {
        out_result.SetValue(-1);
        out_errno.SetValue(EOPNOTSUPP);
        logger::Log(
            "bsd:s bind rejected tunneled owner=%llu fd=%d address_bytes=%zu",
            static_cast<unsigned long long>(m_owner),
            fd,
            address.GetSize()
        );
        R_SUCCEED();
    }
    if (const SocketState* socket = FindSocket(fd); socket != nullptr && IsTerminalSocketRoute(socket->route)) {
        out_result.SetValue(-1);
        out_errno.SetValue(ECONNABORTED);
        R_SUCCEED();
    }
    R_RETURN(ams::sm::mitm::ResultShouldForwardToSession());
}

ams::Result BsdMitmService::GetPeerName(
    ams::sf::Out<s32> out_result,
    ams::sf::Out<s32> out_errno,
    ams::sf::Out<u32> out_addr_len,
    const s32 fd,
    ams::sf::OutAutoSelectBuffer address
) {
    const SocketState* socket = FindSocket(fd);
    logger::Log(
        "bsd:s getpeername enter owner=%llu fd=%d route=%s address_bytes=%zu",
        static_cast<unsigned long long>(m_owner),
        fd,
        SocketRouteName(socket),
        address.GetSize()
    );
    if (socket != nullptr && UsesTunnelFlow(socket->route)) {
        if (address.GetSize() < sizeof(BsdSockAddrIn)) {
            out_result.SetValue(-1);
            out_errno.SetValue(EINVAL);
            out_addr_len.SetValue(0);
        } else {
            EncodeIpv4Endpoint(socket->remote, address.GetPointer());
            out_result.SetValue(0);
            out_errno.SetValue(0);
            out_addr_len.SetValue(sizeof(BsdSockAddrIn));
        }
        logger::Log(
            "bsd:s getpeername tunneled owner=%llu fd=%d address_bytes=%zu",
            static_cast<unsigned long long>(m_owner),
            fd,
            address.GetSize()
        );
        R_SUCCEED();
    }
    if (socket != nullptr && IsTerminalSocketRoute(socket->route)) {
        out_result.SetValue(-1);
        out_errno.SetValue(ECONNABORTED);
        out_addr_len.SetValue(0);
        R_SUCCEED();
    }
    logger::Log(
        "bsd:s getpeername direct owner=%llu fd=%d address_bytes=%zu",
        static_cast<unsigned long long>(m_owner),
        fd,
        address.GetSize()
    );
    BsdResultAndAddressLength output{};
    const Result rc = serviceMitmDispatchInOut(
        m_forward_service.get(),
        15,
        fd,
        output,
        .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect},
        .buffers = {{address.GetPointer(), address.GetSize()}}
    );
    out_result.SetValue(output.response.result);
    out_errno.SetValue(output.response.error);
    out_addr_len.SetValue(output.address_size);
    return rc;
}

ams::Result BsdMitmService::GetSockName(
    ams::sf::Out<s32> out_result,
    ams::sf::Out<s32> out_errno,
    ams::sf::Out<u32> out_addr_len,
    const s32 fd,
    ams::sf::OutAutoSelectBuffer address
) {
    const SocketState* socket = FindSocket(fd);
    logger::Log(
        "bsd:s getsockname enter owner=%llu fd=%d route=%s address_bytes=%zu",
        static_cast<unsigned long long>(m_owner),
        fd,
        SocketRouteName(socket),
        address.GetSize()
    );
    if (socket != nullptr && UsesTunnelFlow(socket->route)) {
        if (!socket->visible_local_valid || address.GetSize() < sizeof(BsdSockAddrIn)) {
            out_result.SetValue(-1);
            out_errno.SetValue(EINVAL);
            out_addr_len.SetValue(0);
        } else {
            EncodeIpv4Endpoint(socket->visible_local, address.GetPointer());
            out_result.SetValue(0);
            out_errno.SetValue(0);
            out_addr_len.SetValue(sizeof(BsdSockAddrIn));
        }
        logger::Log(
            "bsd:s getsockname tunneled owner=%llu fd=%d address_bytes=%zu",
            static_cast<unsigned long long>(m_owner),
            fd,
            address.GetSize()
        );
        R_SUCCEED();
    }
    if (socket != nullptr && IsTerminalSocketRoute(socket->route)) {
        out_result.SetValue(-1);
        out_errno.SetValue(ECONNABORTED);
        out_addr_len.SetValue(0);
        R_SUCCEED();
    }
    logger::Log(
        "bsd:s getsockname direct owner=%llu fd=%d address_bytes=%zu",
        static_cast<unsigned long long>(m_owner),
        fd,
        address.GetSize()
    );
    BsdResultAndAddressLength output{};
    const Result rc = serviceMitmDispatchInOut(
        m_forward_service.get(),
        16,
        fd,
        output,
        .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect},
        .buffers = {{address.GetPointer(), address.GetSize()}}
    );
    out_result.SetValue(output.response.result);
    out_errno.SetValue(output.response.error);
    out_addr_len.SetValue(output.address_size);
    return rc;
}

ams::Result
BsdMitmService::Fcntl(ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, const s32 fd, const s32 command, const s32 value) {
    if (const SocketState* socket = FindSocket(fd); socket != nullptr && UsesTunnelFlow(socket->route)) {
        if (!SupportsTunneledFcntl(command, value)) {
            out_result.SetValue(-1);
            out_errno.SetValue(EOPNOTSUPP);
            logger::Log(
                "bsd:s fcntl rejected tunneled owner=%llu fd=%d command=%d value=0x%X",
                static_cast<unsigned long long>(m_owner),
                fd,
                command,
                static_cast<unsigned>(value)
            );
            R_SUCCEED();
        }
        out_result.SetValue(TunneledFcntlResult(command));
        out_errno.SetValue(0);
        logger::Log(
            "bsd:s fcntl tunneled owner=%llu fd=%d command=%d value=0x%X",
            static_cast<unsigned long long>(m_owner),
            fd,
            command,
            static_cast<unsigned>(value)
        );
        R_SUCCEED();
    }
    if (const SocketState* socket = FindSocket(fd); socket != nullptr && IsTerminalSocketRoute(socket->route)) {
        out_result.SetValue(-1);
        out_errno.SetValue(ECONNABORTED);
        R_SUCCEED();
    }
    R_RETURN(ams::sm::mitm::ResultShouldForwardToSession());
}

ams::Result BsdMitmService::SetSockOpt(
    ams::sf::Out<s32> out_result,
    ams::sf::Out<s32> out_errno,
    const s32 fd,
    const s32 level,
    const s32 option,
    const ams::sf::InAutoSelectBuffer& value
) {
    if (const SocketState* socket = FindSocket(fd); socket != nullptr && UsesTunnelFlow(socket->route)) {
        out_result.SetValue(-1);
        out_errno.SetValue(EOPNOTSUPP);
        logger::Log(
            "bsd:s setsockopt rejected tunneled owner=%llu fd=%d level=%d option=%d value_bytes=%zu",
            static_cast<unsigned long long>(m_owner),
            fd,
            level,
            option,
            value.GetSize()
        );
        R_SUCCEED();
    }
    if (const SocketState* socket = FindSocket(fd); socket != nullptr && IsTerminalSocketRoute(socket->route)) {
        out_result.SetValue(-1);
        out_errno.SetValue(ECONNABORTED);
        R_SUCCEED();
    }
    R_RETURN(ams::sm::mitm::ResultShouldForwardToSession());
}

ams::Result BsdMitmService::Shutdown(ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, const s32 fd, const s32 how) {
    if (const SocketState* socket = FindSocket(fd); socket != nullptr && UsesTunnelFlow(socket->route)) {
        out_result.SetValue(-1);
        out_errno.SetValue(EOPNOTSUPP);
        logger::Log("bsd:s shutdown rejected tunneled owner=%llu fd=%d how=%d", static_cast<unsigned long long>(m_owner), fd, how);
        R_SUCCEED();
    }
    if (const SocketState* socket = FindSocket(fd); socket != nullptr && IsTerminalSocketRoute(socket->route)) {
        out_result.SetValue(-1);
        out_errno.SetValue(ECONNABORTED);
        R_SUCCEED();
    }
    R_RETURN(ams::sm::mitm::ResultShouldForwardToSession());
}

ams::Result BsdMitmService::Close(ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, const s32 fd) {
    const SocketState* socket = FindSocket(fd);
    const bool tunneled = socket != nullptr && UsesTunnelFlow(socket->route);
    logger::Log("bsd:s close enter owner=%llu fd=%d route=%s", static_cast<unsigned long long>(m_owner), fd, SocketRouteName(socket));
    if (tunneled) {
        GetTunnelFlowWorker().Close(m_owner, fd);
    }
    ForgetSocket(fd);
    BsdResultAndErrno output{};
    const Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 26, fd, output);
    out_result.SetValue(output.result);
    out_errno.SetValue(output.error);
    logger::Log(
        "bsd:s close owner=%llu fd=%d route=%s rc=0x%08X",
        static_cast<unsigned long long>(m_owner),
        fd,
        tunneled ? "tunneled" : "direct",
        static_cast<unsigned>(rc)
    );
    return rc;
}

} // namespace wgnx::mitm
