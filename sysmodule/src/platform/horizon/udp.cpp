#include "platform_internal.hpp"

#include "logger.hpp"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>

#include <stratosphere.hpp>
#include <stratosphere/socket/socket_api.hpp>
#include <stratosphere/socket/socket_errno.hpp>
#include <switch/services/nifm.h>

namespace wgnx::sysmodule::platform::horizon::internal {

namespace {

using SocketConfigType = ams::socket::SystemConfigLightDefault;

constexpr inline size_t SocketAllocatorSize = 128 * 1024;
constexpr inline size_t SocketMemoryPoolSize = ams::util::AlignUp(
    SocketConfigType::PerTcpSocketWorstCaseMemoryPoolSize + SocketConfigType::PerUdpSocketWorstCaseMemoryPoolSize,
    ams::os::MemoryPageSize);
constexpr inline size_t SocketRequiredSize = ams::util::AlignUp(SocketMemoryPoolSize + SocketAllocatorSize, ams::os::MemoryPageSize);

alignas(ams::os::MemoryPageSize) constinit std::uint8_t g_socket_memory[SocketRequiredSize] = {};
constinit bool g_socket_initialized = false;
constinit bool g_nifm_initialized = false;
ams::os::Mutex g_socket_mutex(false);

} // namespace

ams::Result EnsureUdpRuntimeInitialized() {
    std::scoped_lock lock(g_socket_mutex);
    if (!g_socket_initialized) {
        constexpr SocketConfigType SocketConfig(g_socket_memory, sizeof(g_socket_memory), SocketAllocatorSize, 2);
        R_TRY(ams::socket::Initialize(SocketConfig));
        g_socket_initialized = true;
    }

    if (!g_nifm_initialized) {
        R_TRY(static_cast<ams::Result>(nifmInitialize(NifmServiceType_System)));
        g_nifm_initialized = true;
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

bool EncodeEndpointFromSockaddr(wgnx::platform::endpoint *out, const sockaddr *address) {
    if (out == nullptr || address == nullptr) {
        return false;
    }

    *out = {};

    if (address->sa_family == AF_INET) {
        const auto *addr4 = reinterpret_cast<const sockaddr_in *>(address);
        out->family = wgnx::platform::address_family::inet;
        out->port = ntohs(addr4->sin_port);
        std::memcpy(out->address, std::addressof(addr4->sin_addr), sizeof(addr4->sin_addr));
        return true;
    }

    if (address->sa_family == AF_INET6) {
        const auto *addr6 = reinterpret_cast<const sockaddr_in6 *>(address);
        out->family = wgnx::platform::address_family::inet6;
        out->port = ntohs(addr6->sin6_port);
        std::memcpy(out->address, std::addressof(addr6->sin6_addr), sizeof(addr6->sin6_addr));
        return true;
    }

    return false;
}

bool DecodeEndpointToSockaddr(sockaddr_storage *out_address, socklen_t *out_length, const wgnx::platform::endpoint &endpoint) {
    if (out_address == nullptr || out_length == nullptr) {
        return false;
    }

    *out_address = {};
    *out_length = 0;

    if (endpoint.family == wgnx::platform::address_family::inet) {
        auto *addr4 = reinterpret_cast<sockaddr_in *>(out_address);
        *addr4 = {};
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(endpoint.port);
        std::memcpy(std::addressof(addr4->sin_addr), endpoint.address, sizeof(addr4->sin_addr));
        *out_length = sizeof(*addr4);
        return true;
    }

    if (endpoint.family == wgnx::platform::address_family::inet6) {
        auto *addr6 = reinterpret_cast<sockaddr_in6 *>(out_address);
        *addr6 = {};
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(endpoint.port);
        std::memcpy(std::addressof(addr6->sin6_addr), endpoint.address, sizeof(addr6->sin6_addr));
        *out_length = sizeof(*addr6);
        return true;
    }

    return false;
}

} // namespace wgnx::sysmodule::platform::horizon::internal

namespace wgnx::platform {

bool endpoint_to_string(const endpoint *endpoint, char *out_text, std::size_t out_text_size) {
    if (endpoint == nullptr || out_text == nullptr || out_text_size == 0) {
        return false;
    }

    char host[INET6_ADDRSTRLEN] = {};

    switch (endpoint->family) {
        case address_family::inet:
            if (::inet_ntop(AF_INET, endpoint->address, host, sizeof(host)) == nullptr) {
                return false;
            }
            std::snprintf(out_text, out_text_size, "%s:%u", host, static_cast<unsigned int>(endpoint->port));
            return true;
        case address_family::inet6:
            if (::inet_ntop(AF_INET6, endpoint->address, host, sizeof(host)) == nullptr) {
                return false;
            }
            std::snprintf(out_text, out_text_size, "[%s]:%u", host, static_cast<unsigned int>(endpoint->port));
            return true;
        case address_family::unspecified:
            break;
    }

    return false;
}

socket_error udp_open(socket_handle *out_socket, address_family family) {
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
            static_cast<u32>(init_result.GetValue()));
        return socket_error::transport_init_failed;
    }

    const auto ams_family = wgnx::sysmodule::platform::horizon::internal::ToAmsAddressFamily(family);
    const s32 socket_fd = ams::socket::Socket(
        ams_family,
        ams::socket::Type::Sock_Dgram,
        ams::socket::Protocol::IpProto_Udp);
    if (socket_fd < 0) {
        const auto socket_errno = ams::socket::GetLastError();
        wgnx::sysmodule::logger::Log(
            "udp_open socket() failed family=%u ams_family=%u socket_errno=%u",
            static_cast<unsigned int>(family),
            static_cast<unsigned int>(ams_family),
            static_cast<unsigned int>(socket_errno));
        return socket_error::open_failed;
    }

    *out_socket = socket_fd;
    return socket_error::none;
}

void udp_close(socket_handle socket) {
    if (socket == InvalidSocket) {
        return;
    }

    static_cast<void>(ams::socket::Close(socket));
}

socket_error udp_send(socket_handle socket, const endpoint *destination, const void *data, std::size_t size, std::size_t *out_sent) {
    if (socket == InvalidSocket || destination == nullptr || data == nullptr) {
        return socket_error::invalid_endpoint;
    }

    sockaddr_storage native_address = {};
    socklen_t native_length = 0;
    if (!wgnx::sysmodule::platform::horizon::internal::DecodeEndpointToSockaddr(
            std::addressof(native_address), std::addressof(native_length), *destination)) {
        return socket_error::invalid_endpoint;
    }

    const ssize_t rc = ams::socket::SendTo(
        socket,
        data,
        size,
        ams::socket::MsgFlag::Msg_None,
        reinterpret_cast<const ams::socket::SockAddr *>(std::addressof(native_address)),
        static_cast<ams::socket::SockLenT>(native_length));
    if (rc < 0) {
        wgnx::sysmodule::logger::Log(
            "udp_send failed socket_errno=%u",
            static_cast<unsigned int>(ams::socket::GetLastError()));
        return socket_error::send_failed;
    }

    if (out_sent != nullptr) {
        *out_sent = static_cast<std::size_t>(rc);
    }
    return socket_error::none;
}

socket_error udp_receive(socket_handle socket, void *buffer, std::size_t capacity, std::size_t *out_received, endpoint *out_source) {
    if (socket == InvalidSocket || buffer == nullptr) {
        return socket_error::receive_failed;
    }

    sockaddr_storage native_address = {};
    ams::socket::SockLenT native_length = sizeof(native_address);
    const ssize_t rc = ams::socket::RecvFrom(
        socket,
        buffer,
        capacity,
        ams::socket::MsgFlag::Msg_None,
        reinterpret_cast<ams::socket::SockAddr *>(std::addressof(native_address)),
        std::addressof(native_length));
    if (rc < 0) {
        wgnx::sysmodule::logger::Log(
            "udp_receive failed socket_errno=%u",
            static_cast<unsigned int>(ams::socket::GetLastError()));
        return socket_error::receive_failed;
    }

    if (out_received != nullptr) {
        *out_received = static_cast<std::size_t>(rc);
    }
    if (out_source != nullptr) {
        *out_source = {};
        if (!wgnx::sysmodule::platform::horizon::internal::EncodeEndpointFromSockaddr(
                out_source, reinterpret_cast<const sockaddr *>(std::addressof(native_address)))) {
            const auto *generic = reinterpret_cast<const sockaddr *>(std::addressof(native_address));
            wgnx::sysmodule::logger::Log(
                "udp_receive source decode skipped sa_family=%d addrlen=%u",
                generic->sa_family,
                static_cast<unsigned int>(native_length));
        }
    }

    return socket_error::none;
}

} // namespace wgnx::platform
