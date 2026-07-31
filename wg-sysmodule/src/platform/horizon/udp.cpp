#include "platform_internal.hpp"

#include "logger.hpp"
#include "wgnx/resource_budget.hpp"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <span>

#include <stratosphere.hpp>
#include <stratosphere/socket/socket_api.hpp>
#include <stratosphere/socket/socket_errno.hpp>

namespace wgnx::sysmodule::platform::horizon::internal {

namespace {

using SocketConfigType = ams::socket::SystemConfigLightDefault;

constexpr inline size_t SocketAllocatorSize = wgnx::resource_budget::SocketAllocatorBytes;
constexpr inline long ReceiveTimeoutSeconds = 1;
constexpr inline long ReceiveTimeoutMicroseconds = 0;
constexpr inline size_t SocketMemoryPoolSize = ams::util::AlignUp(
    SocketConfigType::PerTcpSocketWorstCaseMemoryPoolSize + SocketConfigType::PerUdpSocketWorstCaseMemoryPoolSize, ams::os::MemoryPageSize
);
constexpr inline size_t SocketRequiredSize = ams::util::AlignUp(SocketMemoryPoolSize + SocketAllocatorSize, ams::os::MemoryPageSize);

static_assert(SocketRequiredSize == wgnx::resource_budget::SocketArenaBytes);

alignas(ams::os::MemoryPageSize) constinit std::uint8_t g_socket_memory[SocketRequiredSize] = {};
constinit bool g_socket_initialized = false;
ams::os::Mutex g_runtime_mutex(false);

} // namespace

ams::Result EnsureUdpRuntimeInitialized() {
    std::scoped_lock lock(g_runtime_mutex);
    if (!g_socket_initialized) {
        constexpr SocketConfigType
            SocketConfig(g_socket_memory, sizeof(g_socket_memory), SocketAllocatorSize, wgnx::resource_budget::SocketConcurrency);
        R_TRY(ams::socket::Initialize(SocketConfig));
        g_socket_initialized = true;
    }

    R_SUCCEED();
}

int ToNativeAddressFamily(wgnx::platform::address_family family) {
    switch (family) {
    case wgnx::platform::address_family::inet:
        return AF_INET;
    case wgnx::platform::address_family::inet6:
        return AF_INET6;
    case wgnx::platform::address_family::unspecified:
        break;
    }

    return AF_UNSPEC;
}

ams::socket::Family ToAmsAddressFamily(wgnx::platform::address_family family) {
    switch (family) {
    case wgnx::platform::address_family::inet:
        return ams::socket::Family::Af_Inet;
    case wgnx::platform::address_family::inet6:
        return ams::socket::Family::Af_Inet6;
    case wgnx::platform::address_family::unspecified:
        break;
    }

    return ams::socket::Family::Af_Unspec;
}

wgnx::platform::address_family FromNativeAddressFamily(int family) {
    switch (family) {
    case AF_INET:
        return wgnx::platform::address_family::inet;
    case AF_INET6:
        return wgnx::platform::address_family::inet6;
    default:
        return wgnx::platform::address_family::unspecified;
    }
}

bool EncodeEndpointFromSockaddr(wgnx::platform::endpoint* out, const sockaddr* address) {
    if (out == nullptr || address == nullptr) {
        return false;
    }

    *out = {};

    if (address->sa_family == AF_INET) {
        const auto* addr4 = reinterpret_cast<const sockaddr_in*>(address);
        out->family = wgnx::platform::address_family::inet;
        out->port = ntohs(addr4->sin_port);
        std::memcpy(out->address.data(), std::addressof(addr4->sin_addr), sizeof(addr4->sin_addr));
        return true;
    }

    if (address->sa_family == AF_INET6) {
        const auto* addr6 = reinterpret_cast<const sockaddr_in6*>(address);
        out->family = wgnx::platform::address_family::inet6;
        out->port = ntohs(addr6->sin6_port);
        std::memcpy(out->address.data(), std::addressof(addr6->sin6_addr), sizeof(addr6->sin6_addr));
        return true;
    }

    return false;
}

bool DecodeEndpointToSockaddr(sockaddr_storage* out_address, socklen_t* out_length, const wgnx::platform::endpoint& endpoint) {
    if (out_address == nullptr || out_length == nullptr) {
        return false;
    }

    *out_address = {};
    *out_length = 0;

    if (endpoint.family == wgnx::platform::address_family::inet) {
        auto* addr4 = reinterpret_cast<sockaddr_in*>(out_address);
        *addr4 = {};
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(endpoint.port);
        std::memcpy(std::addressof(addr4->sin_addr), endpoint.address.data(), sizeof(addr4->sin_addr));
        *out_length = sizeof(*addr4);
        return true;
    }

    if (endpoint.family == wgnx::platform::address_family::inet6) {
        auto* addr6 = reinterpret_cast<sockaddr_in6*>(out_address);
        *addr6 = {};
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(endpoint.port);
        std::memcpy(std::addressof(addr6->sin6_addr), endpoint.address.data(), sizeof(addr6->sin6_addr));
        *out_length = sizeof(*addr6);
        return true;
    }

    return false;
}

} // namespace wgnx::sysmodule::platform::horizon::internal

namespace wgnx::platform {

namespace {

bool SetReceiveTimeout(socket_handle socket) {
    const ams::socket::TimeVal timeout = {
        .tv_sec = wgnx::sysmodule::platform::horizon::internal::ReceiveTimeoutSeconds,
        .tv_usec = wgnx::sysmodule::platform::horizon::internal::ReceiveTimeoutMicroseconds,
    };

    return ams::socket::SetSockOpt(
               socket,
               ams::socket::Level::Sol_Socket,
               ams::socket::Option::So_RcvTimeo,
               std::addressof(timeout),
               sizeof(timeout)
           ) == 0;
}

udp_receive_native_condition ClassifyNativeReceiveCondition(ams::socket::Errno error) {
    if (error == ams::socket::Errno::ESuccess) {
        return udp_receive_native_condition::none;
    }
    if (error == ams::socket::Errno::EAgain || error == ams::socket::Errno::EWouldBlock) {
        return udp_receive_native_condition::would_block;
    }
    if (error == ams::socket::Errno::ETimedOut) {
        return udp_receive_native_condition::timed_out;
    }
    if (error == ams::socket::Errno::EIntr) {
        return udp_receive_native_condition::interrupted;
    }
    return udp_receive_native_condition::other;
}

} // namespace

bool endpoint_to_string(const endpoint& endpoint, std::span<char> out_text) {
    if (out_text.empty()) {
        return false;
    }

    char host[INET6_ADDRSTRLEN] = {};

    switch (endpoint.family) {
    case address_family::inet:
        if (::inet_ntop(AF_INET, endpoint.address.data(), host, sizeof(host)) == nullptr) {
            return false;
        }
        std::snprintf(out_text.data(), out_text.size(), "%s:%u", host, static_cast<unsigned int>(endpoint.port));
        return true;
    case address_family::inet6:
        if (::inet_ntop(AF_INET6, endpoint.address.data(), host, sizeof(host)) == nullptr) {
            return false;
        }
        std::snprintf(out_text.data(), out_text.size(), "[%s]:%u", host, static_cast<unsigned int>(endpoint.port));
        return true;
    case address_family::unspecified:
        break;
    }

    return false;
}

socket_error udp_open(socket_handle* out_socket, address_family family) {
    if (out_socket == nullptr) {
        return socket_error::open_failed;
    }

    *out_socket = InvalidSocket;

    if (family == address_family::unspecified) {
        wgnx::sysmodule::logger::Log("udp_open rejected unspecified address family");
        return socket_error::invalid_endpoint;
    }

    const ams::Result init_result = wgnx::sysmodule::platform::horizon::internal::EnsureUdpRuntimeInitialized();
    if (R_FAILED(init_result)) {
        wgnx::sysmodule::logger::Log(
            "udp_open runtime initialization failed family=%u rc=0x%08x",
            static_cast<unsigned int>(family),
            static_cast<u32>(init_result.GetValue())
        );
        return socket_error::transport_init_failed;
    }

    const auto ams_family = wgnx::sysmodule::platform::horizon::internal::ToAmsAddressFamily(family);
    const s32 socket_fd = ams::socket::Socket(ams_family, ams::socket::Type::Sock_Dgram, ams::socket::Protocol::IpProto_Udp);
    if (socket_fd < 0) {
        const auto socket_errno = ams::socket::GetLastError();
        wgnx::sysmodule::logger::Log(
            "udp_open socket() failed family=%u ams_family=%u socket_errno=%u",
            static_cast<unsigned int>(family),
            static_cast<unsigned int>(ams_family),
            static_cast<unsigned int>(socket_errno)
        );
        return socket_error::open_failed;
    }

    *out_socket = socket_fd;
    if (!SetReceiveTimeout(*out_socket)) {
        const auto socket_errno = ams::socket::GetLastError();
        wgnx::sysmodule::logger::Log("udp_open SetSockOpt(SO_RCVTIMEO) failed socket_errno=%u", static_cast<unsigned int>(socket_errno));
        static_cast<void>(ams::socket::Shutdown(*out_socket, ams::socket::ShutdownMethod::Shut_RdWr));
        static_cast<void>(ams::socket::Close(*out_socket));
        *out_socket = InvalidSocket;
        return socket_error::open_failed;
    }
    return socket_error::none;
}

void udp_close(socket_handle socket) {
    if (socket == InvalidSocket) {
        return;
    }

    wgnx::sysmodule::logger::Log("udp_close shutdown begin socket=%d", static_cast<int>(socket));
    const s32 shutdown_result = ams::socket::Shutdown(socket, ams::socket::ShutdownMethod::Shut_RdWr);
    const auto shutdown_errno = shutdown_result < 0 ? ams::socket::GetLastError() : ams::socket::Errno::ESuccess;
    wgnx::sysmodule::logger::Log(
        "udp_close shutdown end socket=%d result=%d socket_errno=%u",
        static_cast<int>(socket),
        static_cast<int>(shutdown_result),
        static_cast<unsigned int>(shutdown_errno)
    );

    wgnx::sysmodule::logger::Log("udp_close close begin socket=%d", static_cast<int>(socket));
    const s32 close_result = ams::socket::Close(socket);
    const auto close_errno = close_result < 0 ? ams::socket::GetLastError() : ams::socket::Errno::ESuccess;
    wgnx::sysmodule::logger::Log(
        "udp_close close end socket=%d result=%d socket_errno=%u",
        static_cast<int>(socket),
        static_cast<int>(close_result),
        static_cast<unsigned int>(close_errno)
    );
}

socket_error udp_send(socket_handle socket, const endpoint& destination, std::span<const std::uint8_t> data, std::size_t* out_sent) {
    if (socket == InvalidSocket) {
        return socket_error::invalid_endpoint;
    }

    sockaddr_storage native_address = {};
    socklen_t native_length = 0;
    if (!wgnx::sysmodule::platform::horizon::internal::DecodeEndpointToSockaddr(
            std::addressof(native_address),
            std::addressof(native_length),
            destination
        )) {
        return socket_error::invalid_endpoint;
    }

    const ssize_t rc = ams::socket::SendTo(
        socket,
        data.data(),
        data.size(),
        ams::socket::MsgFlag::Msg_None,
        reinterpret_cast<const ams::socket::SockAddr*>(std::addressof(native_address)),
        static_cast<ams::socket::SockLenT>(native_length)
    );
    if (rc < 0) {
        wgnx::sysmodule::logger::Log("udp_send failed socket_errno=%u", static_cast<unsigned int>(ams::socket::GetLastError()));
        return socket_error::send_failed;
    }

    if (out_sent != nullptr) {
        *out_sent = static_cast<std::size_t>(rc);
    }
    return socket_error::none;
}

udp_receive_result udp_receive(socket_handle socket, std::span<std::uint8_t> buffer) {
    if (socket == InvalidSocket) {
        return {
            .disposition = udp_receive_disposition::failure,
            .native_condition = udp_receive_native_condition::other,
            .error = socket_error::receive_failed,
        };
    }

    sockaddr_storage native_address = {};
    ams::socket::SockLenT native_length = sizeof(native_address);
    const ssize_t rc = ams::socket::RecvFrom(
        socket,
        buffer.data(),
        buffer.size(),
        ams::socket::MsgFlag::Msg_None,
        reinterpret_cast<ams::socket::SockAddr*>(std::addressof(native_address)),
        std::addressof(native_length)
    );
    const auto socket_errno = rc < 0 ? ams::socket::GetLastError() : ams::socket::Errno::ESuccess;

    endpoint source{};
    if (rc >= 0 && !wgnx::sysmodule::platform::horizon::internal::EncodeEndpointFromSockaddr(
                       std::addressof(source),
                       reinterpret_cast<const sockaddr*>(std::addressof(native_address))
                   )) {
        const auto* generic = reinterpret_cast<const sockaddr*>(std::addressof(native_address));
        wgnx::sysmodule::logger::Log(
            "udp_receive source decode skipped sa_family=%d addrlen=%u",
            generic->sa_family,
            static_cast<unsigned int>(native_length)
        );
    }

    return classify_udp_receive_result(
        static_cast<std::int64_t>(rc),
        ClassifyNativeReceiveCondition(socket_errno),
        static_cast<std::uint32_t>(socket_errno),
        source
    );
}

} // namespace wgnx::platform
