#include "platform_internal.hpp"

#include "logger.hpp"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <span>

#include <stratosphere.hpp>
#include <stratosphere/socket/socket_api.hpp>
#include <stratosphere/socket/socket_errno.hpp>
#include <switch/services/nifm.h>

namespace wgnx::sysmodule::platform::horizon::internal {

namespace {

using SocketConfigType = ams::socket::SystemConfigLightDefault;

constexpr inline size_t SocketAllocatorSize = 128 * 1024;
constexpr inline long ReceiveTimeoutSeconds = 1;
constexpr inline long ReceiveTimeoutMicroseconds = 0;
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
        std::memcpy(out->address.data(), std::addressof(addr4->sin_addr), sizeof(addr4->sin_addr));
        return true;
    }

    if (address->sa_family == AF_INET6) {
        const auto *addr6 = reinterpret_cast<const sockaddr_in6 *>(address);
        out->family = wgnx::platform::address_family::inet6;
        out->port = ntohs(addr6->sin6_port);
        std::memcpy(out->address.data(), std::addressof(addr6->sin6_addr), sizeof(addr6->sin6_addr));
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
        std::memcpy(std::addressof(addr4->sin_addr), endpoint.address.data(), sizeof(addr4->sin_addr));
        *out_length = sizeof(*addr4);
        return true;
    }

    if (endpoint.family == wgnx::platform::address_family::inet6) {
        auto *addr6 = reinterpret_cast<sockaddr_in6 *>(out_address);
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

struct NetworkPathFingerprint {
    std::uint32_t initialization_result{0};
    std::uint32_t internet_status_result{0};
    std::uint32_t ip_config_result{0};
    std::uint32_t connection_type{0};
    std::uint32_t connection_status{0};
    std::uint32_t wifi_strength{0};
    std::uint32_t current_address{0};
    std::uint32_t subnet_mask{0};
    std::uint32_t gateway{0};
    std::uint32_t primary_dns{0};
    std::uint32_t secondary_dns{0};
};

constinit NetworkPathFingerprint g_last_network_path = {};
constinit bool g_has_last_network_path = false;

bool NetworkPathsEqual(const NetworkPathFingerprint &lhs, const NetworkPathFingerprint &rhs) {
    return lhs.initialization_result == rhs.initialization_result &&
           lhs.internet_status_result == rhs.internet_status_result &&
           lhs.ip_config_result == rhs.ip_config_result &&
           lhs.connection_type == rhs.connection_type &&
           lhs.connection_status == rhs.connection_status &&
           lhs.wifi_strength == rhs.wifi_strength &&
           lhs.current_address == rhs.current_address &&
           lhs.subnet_mask == rhs.subnet_mask &&
           lhs.gateway == rhs.gateway &&
           lhs.primary_dns == rhs.primary_dns &&
           lhs.secondary_dns == rhs.secondary_dns;
}

void FormatIpv4(std::uint32_t address, char *out, std::size_t out_size) {
    std::snprintf(
        out,
        out_size,
        "%u.%u.%u.%u",
        address & 0xffU,
        (address >> 8U) & 0xffU,
        (address >> 16U) & 0xffU,
        (address >> 24U) & 0xffU);
}

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
               sizeof(timeout)) == 0;
}

} // namespace

bool endpoint_to_string(const endpoint &endpoint, std::span<char> out_text) {
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
    if (!SetReceiveTimeout(*out_socket)) {
        const auto socket_errno = ams::socket::GetLastError();
        wgnx::sysmodule::logger::Log(
            "udp_open SetSockOpt(SO_RCVTIMEO) failed socket_errno=%u",
            static_cast<unsigned int>(socket_errno));
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

    static_cast<void>(ams::socket::Shutdown(socket, ams::socket::ShutdownMethod::Shut_RdWr));
    static_cast<void>(ams::socket::Close(socket));
}

socket_error udp_send(socket_handle socket, const endpoint &destination, std::span<const std::uint8_t> data, std::size_t *out_sent) {
    if (socket == InvalidSocket) {
        return socket_error::invalid_endpoint;
    }

    sockaddr_storage native_address = {};
    socklen_t native_length = 0;
    if (!wgnx::sysmodule::platform::horizon::internal::DecodeEndpointToSockaddr(
            std::addressof(native_address), std::addressof(native_length), destination)) {
        return socket_error::invalid_endpoint;
    }

    const ssize_t rc = ams::socket::SendTo(
        socket,
        data.data(),
        data.size(),
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

socket_error udp_receive(socket_handle socket, std::span<std::uint8_t> buffer, std::size_t *out_received, endpoint *out_source) {
    if (socket == InvalidSocket) {
        return socket_error::receive_failed;
    }

    sockaddr_storage native_address = {};
    ams::socket::SockLenT native_length = sizeof(native_address);
    const ssize_t rc = ams::socket::RecvFrom(
        socket,
        buffer.data(),
        buffer.size(),
        ams::socket::MsgFlag::Msg_None,
        reinterpret_cast<ams::socket::SockAddr *>(std::addressof(native_address)),
        std::addressof(native_length));
    if (rc < 0) {
        const auto socket_errno = ams::socket::GetLastError();
        if (socket_errno == ams::socket::Errno::ESuccess ||
            socket_errno == ams::socket::Errno::EAgain ||
            socket_errno == ams::socket::Errno::EWouldBlock ||
            socket_errno == ams::socket::Errno::ETimedOut ||
            socket_errno == ams::socket::Errno::EIntr) {
            if (out_received != nullptr) {
                *out_received = 0;
            }
            if (out_source != nullptr) {
                *out_source = {};
            }
            return socket_error::none;
        }

        wgnx::sysmodule::logger::Log(
            "udp_receive failed socket_errno=%u",
            static_cast<unsigned int>(socket_errno));
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

void observe_network_path() {
    NetworkPathFingerprint current{};
    const ams::Result initialization_result =
        wgnx::sysmodule::platform::horizon::internal::EnsureUdpRuntimeInitialized();
    current.initialization_result = static_cast<std::uint32_t>(initialization_result.GetValue());

    if (R_SUCCEEDED(initialization_result)) {
        NifmInternetConnectionType connection_type{};
        NifmInternetConnectionStatus connection_status{};
        u32 wifi_strength = 0;
        const Result status_result = nifmGetInternetConnectionStatus(
            std::addressof(connection_type),
            std::addressof(wifi_strength),
            std::addressof(connection_status));
        current.internet_status_result = status_result;
        if (R_SUCCEEDED(status_result)) {
            current.connection_type = static_cast<std::uint32_t>(connection_type);
            current.connection_status = static_cast<std::uint32_t>(connection_status);
            current.wifi_strength = wifi_strength;
        }

        const Result config_result = nifmGetCurrentIpConfigInfo(
            std::addressof(current.current_address),
            std::addressof(current.subnet_mask),
            std::addressof(current.gateway),
            std::addressof(current.primary_dns),
            std::addressof(current.secondary_dns));
        current.ip_config_result = config_result;
        if (R_FAILED(config_result)) {
            current.current_address = 0;
            current.subnet_mask = 0;
            current.gateway = 0;
            current.primary_dns = 0;
            current.secondary_dns = 0;
        }
    }

    if (g_has_last_network_path && NetworkPathsEqual(current, g_last_network_path)) {
        return;
    }

    char address[16]{};
    char subnet[16]{};
    char gateway[16]{};
    char primary_dns[16]{};
    char secondary_dns[16]{};
    FormatIpv4(current.current_address, address, sizeof(address));
    FormatIpv4(current.subnet_mask, subnet, sizeof(subnet));
    FormatIpv4(current.gateway, gateway, sizeof(gateway));
    FormatIpv4(current.primary_dns, primary_dns, sizeof(primary_dns));
    FormatIpv4(current.secondary_dns, secondary_dns, sizeof(secondary_dns));
    wgnx::sysmodule::logger::Log(
        "NIFM path changed init_rc=0x%08x status_rc=0x%08x type=%u status=%u strength=%u "
        "config_rc=0x%08x address=%s subnet=%s gateway=%s dns=%s,%s",
        current.initialization_result,
        current.internet_status_result,
        current.connection_type,
        current.connection_status,
        current.wifi_strength,
        current.ip_config_result,
        address,
        subnet,
        gateway,
        primary_dns,
        secondary_dns);
    g_last_network_path = current;
    g_has_last_network_path = true;
}

} // namespace wgnx::platform
