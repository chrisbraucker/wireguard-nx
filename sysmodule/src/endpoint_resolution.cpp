#include "endpoint_resolution.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <mutex>

#include <stratosphere.hpp>
#include <switch/runtime/resolver.h>
#include <switch/services/nifm.h>

extern "C" {
#include <switch/services/sfdnsres.h>
}

#include "logger.hpp"

namespace wgnx::sysmodule::endpoint_resolution {

namespace {

constexpr inline std::size_t MaxEndpointText = sizeof(wgnx::PeerInfo::endpoint);
constexpr inline std::size_t MaxResolvedText = sizeof(wgnx::PeerInfo::resolved_endpoint);
constexpr inline std::size_t MaxHostText = MaxEndpointText;
constexpr inline std::size_t MaxServiceText = 6;
constexpr inline std::size_t ResolverAddrInfoBufferSize = 16 * 1024;

using SocketConfigType = ams::socket::SystemConfigLightDefault;

// Hostname resolution needs a substantially larger libnx-side allocator heap
// than the minimal socket bring-up path used for numeric endpoints only.
constexpr inline size_t SocketAllocatorSize = 128 * 1024;
constexpr inline size_t SocketMemoryPoolSize = ams::util::AlignUp(
    SocketConfigType::PerTcpSocketWorstCaseMemoryPoolSize + SocketConfigType::PerUdpSocketWorstCaseMemoryPoolSize,
    ams::os::MemoryPageSize);
constexpr inline size_t SocketRequiredSize = ams::util::AlignUp(SocketMemoryPoolSize + SocketAllocatorSize, ams::os::MemoryPageSize);

alignas(ams::os::MemoryPageSize) constinit std::uint8_t g_socket_memory[SocketRequiredSize] = {};
constinit std::uint8_t g_resolver_addrinfo_buffer[ResolverAddrInfoBufferSize] = {};
constinit bool g_socket_initialized = false;
constinit bool g_nifm_initialized = false;
ams::os::Mutex g_socket_mutex(false);

struct EndpointParts {
    char host[MaxHostText]{};
    char service[MaxServiceText]{};
};

struct AddrInfoSerializedHeader {
    std::uint32_t magic;
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    std::uint32_t ai_addrlen;
};

constexpr inline std::uint32_t AddrInfoMagic = 0xBEEFCAFEu;

bool IsAsciiSpace(char ch) {
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

void TrimSpan(const char **begin, const char **end) {
    while (*begin < *end && IsAsciiSpace(**begin)) {
        ++(*begin);
    }
    while (*begin < *end && IsAsciiSpace(*((*end) - 1))) {
        --(*end);
    }
}

bool CopySpan(char *dst, std::size_t dst_size, const char *begin, const char *end) {
    if (dst == nullptr || dst_size == 0 || begin == nullptr || end == nullptr || begin > end) {
        return false;
    }

    const std::size_t length = static_cast<std::size_t>(end - begin);
    if (length == 0 || length >= dst_size) {
        return false;
    }

    std::memcpy(dst, begin, length);
    dst[length] = '\0';
    return true;
}

bool ParseEndpointParts(const char *configured_endpoint, EndpointParts *out) {
    if (configured_endpoint == nullptr || out == nullptr) {
        return false;
    }

    const char *begin = configured_endpoint;
    const char *end = configured_endpoint + std::strlen(configured_endpoint);
    TrimSpan(&begin, &end);
    if (begin == end) {
        return false;
    }

    if (*begin == '[') {
        const char *closing = static_cast<const char *>(std::memchr(begin, ']', static_cast<std::size_t>(end - begin)));
        if (closing == nullptr || closing == begin + 1 || closing + 1 >= end || closing[1] != ':') {
            return false;
        }

        const char *host_begin = begin + 1;
        const char *host_end = closing;
        const char *service_begin = closing + 2;
        const char *service_end = end;
        TrimSpan(&host_begin, &host_end);
        TrimSpan(&service_begin, &service_end);
        return CopySpan(out->host, sizeof(out->host), host_begin, host_end) &&
               CopySpan(out->service, sizeof(out->service), service_begin, service_end);
    }

    const char *separator = nullptr;
    for (const char *it = end; it != begin;) {
        --it;
        if (*it == ':') {
            separator = it;
            break;
        }
    }
    if (separator == nullptr || separator == begin || separator + 1 >= end) {
        return false;
    }

    if (std::memchr(begin, ':', static_cast<std::size_t>(separator - begin)) != nullptr) {
        return false;
    }

    const char *host_begin = begin;
    const char *host_end = separator;
    const char *service_begin = separator + 1;
    const char *service_end = end;
    TrimSpan(&host_begin, &host_end);
    TrimSpan(&service_begin, &service_end);
    return CopySpan(out->host, sizeof(out->host), host_begin, host_end) &&
           CopySpan(out->service, sizeof(out->service), service_begin, service_end);
}

bool ParsePort(const char *service) {
    if (service == nullptr || service[0] == '\0') {
        return false;
    }

    char *end = nullptr;
    errno = 0;
    const unsigned long value = std::strtoul(service, &end, 10);
    return errno == 0 && end != service && *end == '\0' && value > 0 && value <= 65535;
}

bool IsNumericHost(const char *host) {
    if (host == nullptr || host[0] == '\0') {
        return false;
    }

    in_addr addr4 = {};
    if (::inet_pton(AF_INET, host, std::addressof(addr4)) == 1) {
        return true;
    }

    in6_addr addr6 = {};
    return ::inet_pton(AF_INET6, host, std::addressof(addr6)) == 1;
}

bool FormatResolvedEndpoint(const sockaddr *address, char *out_text, std::size_t out_text_size, std::uint8_t *out_family);

size_t SerializeHints(const addrinfo &hints, std::uint8_t *buffer, std::size_t buffer_size) {
    if (buffer == nullptr || buffer_size < sizeof(AddrInfoSerializedHeader) + sizeof(std::uint32_t) + 1 + sizeof(std::uint32_t)) {
        return 0;
    }

    AddrInfoSerializedHeader header = {};
    header.magic = htonl(AddrInfoMagic);
    header.ai_flags = htonl(hints.ai_flags);
    header.ai_family = htonl(hints.ai_family);
    header.ai_socktype = htonl(hints.ai_socktype);
    header.ai_protocol = htonl(hints.ai_protocol);
    header.ai_addrlen = 0;

    std::uint8_t *out = buffer;
    std::memcpy(out, std::addressof(header), sizeof(header));
    out += sizeof(header);

    *reinterpret_cast<std::uint32_t *>(out) = 0;
    out += sizeof(std::uint32_t);
    *out++ = '\0';
    *reinterpret_cast<std::uint32_t *>(out) = 0;
    out += sizeof(std::uint32_t);

    return static_cast<std::size_t>(out - buffer);
}

bool ParseSerializedResult(ResolvedEndpoint *out, const void *buffer, std::size_t buffer_size) {
    if (out == nullptr || buffer == nullptr || buffer_size < sizeof(AddrInfoSerializedHeader)) {
        return false;
    }

    const auto *cursor = static_cast<const std::uint8_t *>(buffer);
    const auto *end = cursor + buffer_size;

    while (cursor + sizeof(AddrInfoSerializedHeader) <= end) {
        const auto *header = reinterpret_cast<const AddrInfoSerializedHeader *>(cursor);
        if (ntohl(header->magic) != AddrInfoMagic) {
            break;
        }

        const int family = ntohl(header->ai_family);
        std::size_t addr_length = ntohl(header->ai_addrlen);
        if (addr_length == 0) {
            addr_length = sizeof(std::uint32_t);
        }

        const char *canon_name = reinterpret_cast<const char *>(cursor + sizeof(AddrInfoSerializedHeader) + addr_length);
        if (cursor + sizeof(AddrInfoSerializedHeader) + addr_length > end || canon_name >= reinterpret_cast<const char *>(end)) {
            break;
        }

        const std::size_t canon_length = static_cast<std::size_t>(ams::util::Strnlen(
            canon_name,
            static_cast<int>(reinterpret_cast<const char *>(end) - canon_name))) + 1;
        const std::size_t total_length = sizeof(AddrInfoSerializedHeader) + addr_length + canon_length;
        if (cursor + total_length > end) {
            break;
        }

        if (family == AF_INET) {
            sockaddr_in addr = {};
            std::memcpy(std::addressof(addr), cursor + sizeof(AddrInfoSerializedHeader), std::min(addr_length, sizeof(addr)));
            addr.sin_len = sizeof(addr);
            addr.sin_port = ntohs(addr.sin_port);
            addr.sin_addr.s_addr = ntohl(addr.sin_addr.s_addr);
            out->address = {};
            std::memcpy(std::addressof(out->address), std::addressof(addr), sizeof(addr));
            out->address_length = sizeof(addr);
            return FormatResolvedEndpoint(reinterpret_cast<const sockaddr *>(std::addressof(addr)), out->endpoint, sizeof(out->endpoint), std::addressof(out->family));
        }

        if (family == AF_INET6) {
            sockaddr_in6 addr = {};
            std::memcpy(std::addressof(addr), cursor + sizeof(AddrInfoSerializedHeader), std::min(addr_length, sizeof(addr)));
            addr.sin6_port = ntohs(addr.sin6_port);
            addr.sin6_flowinfo = ntohl(addr.sin6_flowinfo);
            addr.sin6_scope_id = ntohl(addr.sin6_scope_id);
            out->address = {};
            std::memcpy(std::addressof(out->address), std::addressof(addr), sizeof(addr));
            out->address_length = sizeof(addr);
            return FormatResolvedEndpoint(reinterpret_cast<const sockaddr *>(std::addressof(addr)), out->endpoint, sizeof(out->endpoint), std::addressof(out->family));
        }

        cursor += total_length;
    }

    return false;
}

bool ResolveNumericEndpoint(const EndpointParts &parts, ResolvedEndpoint *out) {
    if (out == nullptr) {
        return false;
    }

    in_addr addr4 = {};
    if (::inet_pton(AF_INET, parts.host, std::addressof(addr4)) == 1) {
        auto *addr = reinterpret_cast<sockaddr_in *>(std::addressof(out->address));
        *addr = {};
        addr->sin_family = AF_INET;
        addr->sin_port = htons(static_cast<std::uint16_t>(std::strtoul(parts.service, nullptr, 10)));
        addr->sin_addr = addr4;
        out->address_length = sizeof(*addr);
        return FormatResolvedEndpoint(reinterpret_cast<const sockaddr *>(addr), out->endpoint, sizeof(out->endpoint), std::addressof(out->family));
    }

    in6_addr addr6 = {};
    if (::inet_pton(AF_INET6, parts.host, std::addressof(addr6)) == 1) {
        auto *addr = reinterpret_cast<sockaddr_in6 *>(std::addressof(out->address));
        *addr = {};
        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons(static_cast<std::uint16_t>(std::strtoul(parts.service, nullptr, 10)));
        addr->sin6_addr = addr6;
        out->address_length = sizeof(*addr);
        return FormatResolvedEndpoint(reinterpret_cast<const sockaddr *>(addr), out->endpoint, sizeof(out->endpoint), std::addressof(out->family));
    }

    return false;
}

ams::Result EnsureResolverRuntimeInitialized() {
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

    resolverSetEnableServiceDiscovery(true);
    R_SUCCEED();
}

bool FormatResolvedEndpoint(const sockaddr *address, char *out_text, std::size_t out_text_size, std::uint8_t *out_family) {
    if (address == nullptr || out_text == nullptr || out_text_size == 0 || out_family == nullptr) {
        return false;
    }

    char host[INET6_ADDRSTRLEN] = {};
    std::uint16_t port = 0;

    if (address->sa_family == AF_INET) {
        const auto *addr4 = reinterpret_cast<const sockaddr_in *>(address);
        if (::inet_ntop(AF_INET, std::addressof(addr4->sin_addr), host, sizeof(host)) == nullptr) {
            return false;
        }
        port = ntohs(addr4->sin_port);
        *out_family = AF_INET;
        std::snprintf(out_text, out_text_size, "%s:%u", host, static_cast<unsigned int>(port));
        return true;
    }

    if (address->sa_family == AF_INET6) {
        const auto *addr6 = reinterpret_cast<const sockaddr_in6 *>(address);
        if (::inet_ntop(AF_INET6, std::addressof(addr6->sin6_addr), host, sizeof(host)) == nullptr) {
            return false;
        }
        port = ntohs(addr6->sin6_port);
        *out_family = AF_INET6;
        std::snprintf(out_text, out_text_size, "[%s]:%u", host, static_cast<unsigned int>(port));
        return true;
    }

    return false;
}

} // namespace

ResolveResult Resolve(const char *configured_endpoint) {
    ResolveResult result{};

    EndpointParts parts = {};
    if (!ParseEndpointParts(configured_endpoint, std::addressof(parts)) || !ParsePort(parts.service)) {
        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointMalformed;
        return result;
    }

    if (IsNumericHost(parts.host)) {
        if (ResolveNumericEndpoint(parts, std::addressof(result.endpoint))) {
            result.success = true;
            return result;
        }

        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointResolutionFailed;
        return result;
    }

    if (R_FAILED(EnsureResolverRuntimeInitialized())) {
        result.error_stage = wgnx::PeerErrorStage::Transport;
        result.error_code = wgnx::PeerErrorCode::TransportInitFailed;
        return result;
    }

    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_NUMERICSERV;

    std::uint8_t hints_buffer[64] = {};
    const size_t hints_size = SerializeHints(hints, hints_buffer, sizeof(hints_buffer));
    if (hints_size == 0) {
        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointResolutionFailed;
        return result;
    }

    std::uint32_t remote_errno = 0;
    std::uint32_t serialized_size = 0;
    s32 remote_ret = 0;
    const Result resolver_rc = sfdnsresGetAddrInfoRequest(
        resolverGetCancelHandle(),
        resolverGetEnableServiceDiscovery(),
        parts.host,
        parts.service,
        hints_buffer,
        hints_size,
        g_resolver_addrinfo_buffer,
        sizeof(g_resolver_addrinfo_buffer),
        std::addressof(remote_errno),
        std::addressof(remote_ret),
        std::addressof(serialized_size));

    if (R_FAILED(resolver_rc) || remote_ret != 0) {
        logger::Log("sfdnsresGetAddrInfoRequest failed for '%s:%s': resolver_rc=0x%08x ret=%d errno=%u serialized_size=%u",
            parts.host, parts.service, static_cast<u32>(resolver_rc), remote_ret, remote_errno, serialized_size);
        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointResolutionFailed;
        return result;
    }

    if (serialized_size == 0 || serialized_size > sizeof(g_resolver_addrinfo_buffer)) {
        logger::Log("resolver returned invalid serialized size for '%s:%s': size=%u capacity=%zu",
            parts.host, parts.service, serialized_size, sizeof(g_resolver_addrinfo_buffer));
        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointResolutionFailed;
        return result;
    }

    if (ParseSerializedResult(std::addressof(result.endpoint), g_resolver_addrinfo_buffer, serialized_size)) {
        result.success = true;
        result.error_stage = wgnx::PeerErrorStage::None;
        result.error_code = wgnx::PeerErrorCode::None;
    }

    if (!result.success) {
        logger::Log("resolver returned no usable AF_INET/AF_INET6 result for '%s:%s'", parts.host, parts.service);
        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointResolutionFailed;
    }

    return result;
}

} // namespace wgnx::sysmodule::endpoint_resolution
