#include "bsd_mitm_service.hpp"

#include "bsd_endpoint.hpp"
#include "bsd_response.hpp"
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

[[nodiscard]] s32 ErrnoForResult(const TunnelFlowResult result) {
    switch (result) {
    case TunnelFlowResult::WouldBlock:
        return EAGAIN;
    case TunnelFlowResult::Closed:
        return ECONNABORTED;
    case TunnelFlowResult::SocketError:
        return EIO;
    case TunnelFlowResult::MessageTooLarge:
        return EMSGSIZE;
    case TunnelFlowResult::BlockedByPolicy:
        return ENETUNREACH;
    case TunnelFlowResult::RouteNotCovered:
    case TunnelFlowResult::TunnelUnavailable:
    case TunnelFlowResult::Opened:
        return 0;
    }
    return EIO;
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
    logger::Log("bsd:s session accepted owner=%llu pid=%llu program_id=0x%016llX", static_cast<unsigned long long>(m_owner),
                static_cast<unsigned long long>(client_info.process_id.value),
                static_cast<unsigned long long>(client_info.program_id.value));
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
    logger::Log("bsd:s ShouldMitm requester pid=%llu decision=%u admission=all_requester_sessions",
                static_cast<unsigned long long>(client_info.process_id.value), static_cast<unsigned>(intercept));
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
    if (socket->tunneled) {
        return "tunneled";
    }
    if (socket->udp_ipv4) {
        return "direct_ipv4_udp";
    }
    return "direct_other";
}

void BsdMitmService::ForgetSocket(const s32 descriptor) {
    if (SocketState* socket = FindSocket(descriptor); socket != nullptr) {
        logger::Log("bsd:s socket forget owner=%llu fd=%d tunneled=%u", static_cast<unsigned long long>(m_owner), descriptor,
                    socket->tunneled ? 1U : 0U);
        *socket = {};
        return;
    }
    logger::Log("bsd:s socket forget miss owner=%llu fd=%d", static_cast<unsigned long long>(m_owner), descriptor);
}

ams::Result BsdMitmService::Socket(ams::sf::Out<s32> out_fd, ams::sf::Out<s32> out_errno, const s32 domain, const s32 type,
                                   const s32 protocol) {
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
    logger::Log("bsd:s socket owner=%llu domain=%d type=%d protocol=%d rc=0x%08X errno=%d fd=%d udp_ipv4=%u tracked=%u table_full=%u",
                static_cast<unsigned long long>(m_owner), domain, type, protocol, static_cast<unsigned>(rc), output.error, output.result,
                udp_ipv4 ? 1U : 0U, tracked ? 1U : 0U, table_full ? 1U : 0U);
    return rc;
}

ams::Result BsdMitmService::Connect(ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, const s32 fd,
                                    const ams::sf::InAutoSelectBuffer& address) {
    SocketState* socket = FindSocket(fd);
    logger::Log("bsd:s connect enter owner=%llu fd=%d route=%s address_bytes=%zu", static_cast<unsigned long long>(m_owner), fd,
                SocketRouteName(socket), address.GetSize());
    TunnelFlowEndpoint remote{};
    const bool decoded_endpoint = DecodeIpv4Endpoint(address, std::addressof(remote));
    const bool eligible = socket != nullptr && socket->udp_ipv4 && !socket->tunneled && decoded_endpoint;
    TunnelFlowResult tunnel_result = TunnelFlowResult::TunnelUnavailable;
    if (eligible) {
        GetTunnelDiscoveryService().RequestForInterceptedTraffic();
        tunnel_result = GetTunnelFlowWorker().OpenConnectedUdp(m_owner, fd, remote);
        logger::Log("bsd:s connect tunnel-open owner=%llu fd=%d remote=%u.%u.%u.%u:%u result=%s", static_cast<unsigned long long>(m_owner),
                    fd, remote.address[0], remote.address[1], remote.address[2], remote.address[3], remote.port,
                    TunnelFlowResultName(tunnel_result));
        if (tunnel_result == TunnelFlowResult::Opened) {
            socket->tunneled = true;
            out_result.SetValue(0);
            out_errno.SetValue(0);
            logger::Log("bsd:s connect tunneled owner=%llu fd=%d remote=%u.%u.%u.%u:%u", static_cast<unsigned long long>(m_owner), fd,
                        remote.address[0], remote.address[1], remote.address[2], remote.address[3], remote.port);
            R_SUCCEED();
        }
        if (tunnel_result != TunnelFlowResult::RouteNotCovered && tunnel_result != TunnelFlowResult::TunnelUnavailable) {
            out_result.SetValue(-1);
            out_errno.SetValue(ErrnoForResult(tunnel_result));
            R_SUCCEED();
        }
    }

    if (!eligible) {
        const char* reason = socket == nullptr   ? "untracked_fd"
                             : !socket->udp_ipv4 ? "not_ipv4_udp"
                             : socket->tunneled  ? "already_tunneled"
                             : !decoded_endpoint ? "invalid_endpoint"
                                                 : "unknown";
        logger::Log("bsd:s connect bypass owner=%llu fd=%d reason=%s address_bytes=%zu", static_cast<unsigned long long>(m_owner), fd,
                    reason, address.GetSize());
    } else {
        logger::Log("bsd:s connect bypass owner=%llu fd=%d reason=tunnel_%s", static_cast<unsigned long long>(m_owner), fd,
                    TunnelFlowResultName(tunnel_result));
    }

    BsdResultAndErrno output{};
    const Result rc =
        serviceMitmDispatchInOut(m_forward_service.get(), 14, fd, output, .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcAutoSelect},
                                 .buffers = {{address.GetPointer(), address.GetSize()}});
    out_result.SetValue(output.result);
    out_errno.SetValue(output.error);
    logger::Log("bsd:s connect direct owner=%llu fd=%d rc=0x%08X", static_cast<unsigned long long>(m_owner), fd, static_cast<unsigned>(rc));
    return rc;
}

ams::Result BsdMitmService::Send(ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, const s32 fd, const s32 flags,
                                 const ams::sf::InAutoSelectBuffer& buffer) {
    const SocketState* socket = FindSocket(fd);
    logger::Log("bsd:s send enter owner=%llu fd=%d route=%s bytes=%zu flags=0x%X", static_cast<unsigned long long>(m_owner), fd,
                SocketRouteName(socket), buffer.GetSize(), static_cast<unsigned>(flags));
    if (socket != nullptr && socket->tunneled) {
        const TunnelFlowResult result = GetTunnelFlowWorker().Send(m_owner, fd, buffer.GetPointer(), buffer.GetSize());
        out_errno.SetValue(ErrnoForResult(result));
        out_size.SetValue(result == TunnelFlowResult::Opened ? static_cast<s32>(buffer.GetSize()) : -1);
        logger::Log("bsd:s send tunneled owner=%llu fd=%d bytes=%zu result=%s", static_cast<unsigned long long>(m_owner), fd,
                    buffer.GetSize(), TunnelFlowResultName(result));
        R_SUCCEED();
    }
    struct {
        s32 fd;
        s32 flags;
    } input{fd, flags};
    BsdResultAndErrno output{};
    const Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 10, input, output,
                                               .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcAutoSelect},
                                               .buffers = {{buffer.GetPointer(), buffer.GetSize()}});
    out_errno.SetValue(output.error);
    out_size.SetValue(output.result);
    logger::Log("bsd:s send direct owner=%llu fd=%d bytes=%zu flags=0x%X rc=0x%08X errno=%d result=%d",
                static_cast<unsigned long long>(m_owner), fd, buffer.GetSize(), static_cast<unsigned>(flags), static_cast<unsigned>(rc),
                output.error, output.result);
    return rc;
}

ams::Result BsdMitmService::SendTo(ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, const s32 fd, const s32 flags,
                                   const ams::sf::InAutoSelectBuffer& buffer, const ams::sf::InAutoSelectBuffer& address) {
    const SocketState* socket = FindSocket(fd);
    logger::Log("bsd:s sendto enter owner=%llu fd=%d route=%s bytes=%zu address_bytes=%zu flags=0x%X",
                static_cast<unsigned long long>(m_owner), fd, SocketRouteName(socket), buffer.GetSize(), address.GetSize(),
                static_cast<unsigned>(flags));
    if (socket != nullptr && socket->tunneled) {
        out_errno.SetValue(EOPNOTSUPP);
        out_size.SetValue(-1);
        logger::Log("bsd:s sendto rejected tunneled owner=%llu fd=%d bytes=%zu reason=connected_udp_only",
                    static_cast<unsigned long long>(m_owner), fd, buffer.GetSize());
        R_SUCCEED();
    }
    struct {
        s32 fd;
        s32 flags;
    } input{fd, flags};
    BsdResultAndErrno output{};
    const Result rc = serviceMitmDispatchInOut(
        m_forward_service.get(), 11, input, output,
        .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcAutoSelect, SfBufferAttr_In | SfBufferAttr_HipcAutoSelect},
        .buffers = {{buffer.GetPointer(), buffer.GetSize()}, {address.GetPointer(), address.GetSize()}});
    out_errno.SetValue(output.error);
    out_size.SetValue(output.result);
    logger::Log("bsd:s sendto direct owner=%llu fd=%d bytes=%zu address_bytes=%zu flags=0x%X rc=0x%08X errno=%d result=%d",
                static_cast<unsigned long long>(m_owner), fd, buffer.GetSize(), address.GetSize(), static_cast<unsigned>(flags),
                static_cast<unsigned>(rc), output.error, output.result);
    return rc;
}

ams::Result BsdMitmService::Recv(ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, const s32 fd, const s32 flags,
                                 ams::sf::OutAutoSelectBuffer buffer) {
    const SocketState* socket = FindSocket(fd);
    logger::Log("bsd:s recv enter owner=%llu fd=%d route=%s capacity=%zu flags=0x%X", static_cast<unsigned long long>(m_owner), fd,
                SocketRouteName(socket), buffer.GetSize(), static_cast<unsigned>(flags));
    if (socket != nullptr && socket->tunneled) {
        const TunnelReceiveResult result = GetTunnelFlowWorker().Receive(m_owner, fd, buffer.GetPointer(), buffer.GetSize());
        out_errno.SetValue(ErrnoForResult(result.result));
        out_size.SetValue(result.result == TunnelFlowResult::Opened ? static_cast<s32>(result.size) : -1);
        logger::Log("bsd:s recv tunneled owner=%llu fd=%d capacity=%zu result=%s bytes=%zu", static_cast<unsigned long long>(m_owner), fd,
                    buffer.GetSize(), TunnelFlowResultName(result.result), result.size);
        R_SUCCEED();
    }
    struct {
        s32 fd;
        s32 flags;
    } input{fd, flags};
    BsdResultAndErrno output{};
    const Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 8, input, output,
                                               .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect},
                                               .buffers = {{buffer.GetPointer(), buffer.GetSize()}});
    out_errno.SetValue(output.error);
    out_size.SetValue(output.result);
    logger::Log("bsd:s recv direct owner=%llu fd=%d capacity=%zu flags=0x%X rc=0x%08X errno=%d result=%d",
                static_cast<unsigned long long>(m_owner), fd, buffer.GetSize(), static_cast<unsigned>(flags), static_cast<unsigned>(rc),
                output.error, output.result);
    return rc;
}

ams::Result BsdMitmService::RecvFrom(ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addr_len, const s32 fd,
                                     const s32 flags, ams::sf::OutAutoSelectBuffer buffer, ams::sf::OutAutoSelectBuffer address) {
    const SocketState* socket = FindSocket(fd);
    logger::Log("bsd:s recvfrom enter owner=%llu fd=%d route=%s capacity=%zu address_capacity=%zu flags=0x%X",
                static_cast<unsigned long long>(m_owner), fd, SocketRouteName(socket), buffer.GetSize(), address.GetSize(),
                static_cast<unsigned>(flags));
    if (socket != nullptr && socket->tunneled) {
        const TunnelReceiveResult result = GetTunnelFlowWorker().Receive(m_owner, fd, buffer.GetPointer(), buffer.GetSize());
        out_errno.SetValue(ErrnoForResult(result.result));
        out_size.SetValue(result.result == TunnelFlowResult::Opened ? static_cast<s32>(result.size) : -1);
        if (result.result == TunnelFlowResult::Opened && address.GetSize() >= sizeof(BsdSockAddrIn)) {
            EncodeIpv4Endpoint(result.remote, address.GetPointer());
            out_addr_len.SetValue(sizeof(BsdSockAddrIn));
        } else {
            out_addr_len.SetValue(0);
        }
        logger::Log("bsd:s recvfrom tunneled owner=%llu fd=%d capacity=%zu result=%s bytes=%zu", static_cast<unsigned long long>(m_owner),
                    fd, buffer.GetSize(), TunnelFlowResultName(result.result), result.size);
        R_SUCCEED();
    }
    struct {
        s32 fd;
        s32 flags;
    } input{fd, flags};
    BsdResultAndAddressLength output{};
    const Result rc = serviceMitmDispatchInOut(
        m_forward_service.get(), 9, input, output,
        .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect, SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect},
        .buffers = {{buffer.GetPointer(), buffer.GetSize()}, {address.GetPointer(), address.GetSize()}});
    out_size.SetValue(output.response.result);
    out_errno.SetValue(output.response.error);
    out_addr_len.SetValue(output.address_size);
    logger::Log(
        "bsd:s recvfrom direct owner=%llu fd=%d capacity=%zu address_capacity=%zu flags=0x%X rc=0x%08X errno=%d result=%d address_size=%u",
        static_cast<unsigned long long>(m_owner), fd, buffer.GetSize(), address.GetSize(), static_cast<unsigned>(flags),
        static_cast<unsigned>(rc), output.response.error, output.response.result, output.address_size);
    return rc;
}

ams::Result BsdMitmService::Poll(ams::sf::Out<s32> out_count, ams::sf::Out<s32> out_errno, const ams::sf::InAutoSelectBuffer& fds_in,
                                 ams::sf::OutAutoSelectBuffer fds_out, const s32 nfds, const s32 timeout) {
    if (nfds < 0 || static_cast<std::size_t>(nfds) > MaximumPollDescriptors ||
        fds_in.GetSize() < static_cast<std::size_t>(nfds) * sizeof(pollfd) ||
        fds_out.GetSize() < static_cast<std::size_t>(nfds) * sizeof(pollfd)) {
        out_errno.SetValue(EINVAL);
        out_count.SetValue(-1);
        logger::Log("bsd:s poll rejected owner=%llu nfds=%d input_bytes=%zu output_bytes=%zu reason=invalid_arguments",
                    static_cast<unsigned long long>(m_owner), nfds, fds_in.GetSize(), fds_out.GetSize());
        R_SUCCEED();
    }
    std::array<pollfd, MaximumPollDescriptors> descriptors{};
    std::memcpy(descriptors.data(), fds_in.GetPointer(), static_cast<std::size_t>(nfds) * sizeof(pollfd));
    bool any_tunneled = false;
    bool any_direct = false;
    logger::Log("bsd:s poll enter owner=%llu nfds=%d timeout_ms=%d input_bytes=%zu output_bytes=%zu",
                static_cast<unsigned long long>(m_owner), nfds, timeout, fds_in.GetSize(), fds_out.GetSize());
    for (s32 index = 0; index < nfds; ++index) {
        const SocketState* socket = FindSocket(descriptors[index].fd);
        logger::Log("bsd:s poll descriptor owner=%llu index=%d fd=%d events=0x%X route=%s", static_cast<unsigned long long>(m_owner), index,
                    descriptors[index].fd, static_cast<unsigned>(descriptors[index].events), SocketRouteName(socket));
        descriptors[index].revents = 0;
        any_tunneled = any_tunneled || (socket != nullptr && socket->tunneled);
        any_direct = any_direct || socket == nullptr || !socket->tunneled;
    }
    if (!any_tunneled) {
        struct {
            s32 descriptor_count;
            s32 timeout_milliseconds;
        } input{nfds, timeout};
        BsdResultAndErrno output{};
        const Result rc = serviceMitmDispatchInOut(
            m_forward_service.get(), 6, input, output,
            .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcAutoSelect, SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect},
            .buffers = {{fds_in.GetPointer(), fds_in.GetSize()}, {fds_out.GetPointer(), fds_out.GetSize()}});
        out_errno.SetValue(output.error);
        out_count.SetValue(output.result);
        logger::Log("bsd:s poll direct owner=%llu nfds=%d timeout_ms=%d rc=0x%08X errno=%d ready=%d",
                    static_cast<unsigned long long>(m_owner), nfds, timeout, static_cast<unsigned>(rc), output.error, output.result);
        return rc;
    }
    if (any_direct) {
        out_errno.SetValue(EOPNOTSUPP);
        out_count.SetValue(-1);
        logger::Log("bsd:s poll rejected owner=%llu nfds=%d reason=mixed_direct_and_tunneled", static_cast<unsigned long long>(m_owner),
                    nfds);
        R_SUCCEED();
    }
    s32 ready_count = 0;
    for (s32 index = 0; index < nfds; ++index) {
        const TunnelFlowResult result = GetTunnelFlowWorker().Poll(m_owner, descriptors[index].fd, index == 0 ? timeout : 0);
        if (result == TunnelFlowResult::Opened && (descriptors[index].events & POLLIN) != 0) {
            descriptors[index].revents |= POLLIN;
            ++ready_count;
        } else if (result == TunnelFlowResult::Closed) {
            descriptors[index].revents |= POLLHUP;
            ++ready_count;
        }
    }
    std::memcpy(fds_out.GetPointer(), descriptors.data(), static_cast<std::size_t>(nfds) * sizeof(pollfd));
    out_errno.SetValue(0);
    out_count.SetValue(ready_count);
    logger::Log("bsd:s poll tunneled owner=%llu nfds=%d timeout_ms=%d ready=%d", static_cast<unsigned long long>(m_owner), nfds, timeout,
                ready_count);
    R_SUCCEED();
}

ams::Result BsdMitmService::GetPeerName(ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addr_len,
                                        const s32 fd, ams::sf::OutAutoSelectBuffer address) {
    const SocketState* socket = FindSocket(fd);
    logger::Log("bsd:s getpeername enter owner=%llu fd=%d route=%s address_bytes=%zu", static_cast<unsigned long long>(m_owner), fd,
                SocketRouteName(socket), address.GetSize());
    if (socket != nullptr && socket->tunneled) {
        TunnelFlowEndpoint remote{};
        if (!GetTunnelFlowWorker().GetEndpoints(m_owner, fd, std::addressof(remote), nullptr) ||
            address.GetSize() < sizeof(BsdSockAddrIn)) {
            out_result.SetValue(-1);
            out_errno.SetValue(EINVAL);
            out_addr_len.SetValue(0);
        } else {
            EncodeIpv4Endpoint(remote, address.GetPointer());
            out_result.SetValue(0);
            out_errno.SetValue(0);
            out_addr_len.SetValue(sizeof(BsdSockAddrIn));
        }
        logger::Log("bsd:s getpeername tunneled owner=%llu fd=%d address_bytes=%zu", static_cast<unsigned long long>(m_owner), fd,
                    address.GetSize());
        R_SUCCEED();
    }
    logger::Log("bsd:s getpeername direct owner=%llu fd=%d address_bytes=%zu", static_cast<unsigned long long>(m_owner), fd,
                address.GetSize());
    BsdResultAndAddressLength output{};
    const Result rc =
        serviceMitmDispatchInOut(m_forward_service.get(), 15, fd, output, .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect},
                                 .buffers = {{address.GetPointer(), address.GetSize()}});
    out_result.SetValue(output.response.result);
    out_errno.SetValue(output.response.error);
    out_addr_len.SetValue(output.address_size);
    return rc;
}

ams::Result BsdMitmService::GetSockName(ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addr_len,
                                        const s32 fd, ams::sf::OutAutoSelectBuffer address) {
    const SocketState* socket = FindSocket(fd);
    logger::Log("bsd:s getsockname enter owner=%llu fd=%d route=%s address_bytes=%zu", static_cast<unsigned long long>(m_owner), fd,
                SocketRouteName(socket), address.GetSize());
    if (socket != nullptr && socket->tunneled) {
        TunnelFlowEndpoint local{};
        if (!GetTunnelFlowWorker().GetEndpoints(m_owner, fd, nullptr, std::addressof(local)) || address.GetSize() < sizeof(BsdSockAddrIn)) {
            out_result.SetValue(-1);
            out_errno.SetValue(EINVAL);
            out_addr_len.SetValue(0);
        } else {
            EncodeIpv4Endpoint(local, address.GetPointer());
            out_result.SetValue(0);
            out_errno.SetValue(0);
            out_addr_len.SetValue(sizeof(BsdSockAddrIn));
        }
        logger::Log("bsd:s getsockname tunneled owner=%llu fd=%d address_bytes=%zu", static_cast<unsigned long long>(m_owner), fd,
                    address.GetSize());
        R_SUCCEED();
    }
    logger::Log("bsd:s getsockname direct owner=%llu fd=%d address_bytes=%zu", static_cast<unsigned long long>(m_owner), fd,
                address.GetSize());
    BsdResultAndAddressLength output{};
    const Result rc =
        serviceMitmDispatchInOut(m_forward_service.get(), 16, fd, output, .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect},
                                 .buffers = {{address.GetPointer(), address.GetSize()}});
    out_result.SetValue(output.response.result);
    out_errno.SetValue(output.response.error);
    out_addr_len.SetValue(output.address_size);
    return rc;
}

ams::Result BsdMitmService::Close(ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, const s32 fd) {
    const SocketState* socket = FindSocket(fd);
    const bool tunneled = socket != nullptr && socket->tunneled;
    logger::Log("bsd:s close enter owner=%llu fd=%d route=%s", static_cast<unsigned long long>(m_owner), fd, SocketRouteName(socket));
    if (tunneled) {
        GetTunnelFlowWorker().Close(m_owner, fd);
    }
    ForgetSocket(fd);
    BsdResultAndErrno output{};
    const Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 26, fd, output);
    out_result.SetValue(output.result);
    out_errno.SetValue(output.error);
    logger::Log("bsd:s close owner=%llu fd=%d route=%s rc=0x%08X", static_cast<unsigned long long>(m_owner), fd,
                tunneled ? "tunneled" : "direct", static_cast<unsigned>(rc));
    return rc;
}

} // namespace wgnx::mitm
