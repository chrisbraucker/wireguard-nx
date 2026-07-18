#include "platform_internal.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <span>
#include <string_view>
#include <sys/socket.h>

#include <algorithm>

#include <stratosphere.hpp>
#include <switch/runtime/resolver.h>

extern "C" {
#include <switch/services/sfdnsres.h>
}

#include "logger.hpp"
#include "wgnx/resource_budget.hpp"

namespace wgnx::platform {

namespace {

constexpr inline std::size_t MaxEndpointText = sizeof(wgnx::PeerInfo::endpoint);
constexpr inline std::size_t MaxHostText = MaxEndpointText;
constexpr inline std::size_t MaxServiceText = 6;
constexpr inline std::size_t ResolverAddrInfoBufferSize =
    wgnx::resource_budget::ResolverScratchBytes;

constinit std::uint8_t g_resolver_addrinfo_buffer[ResolverAddrInfoBufferSize] = {};

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

std::string_view TrimView(std::string_view value) {
    while (!value.empty() && IsAsciiSpace(value.front())) {
        value.remove_prefix(1);
    }
    while (!value.empty() && IsAsciiSpace(value.back())) {
        value.remove_suffix(1);
    }

    return value;
}

bool CopyView(std::span<char> dst, std::string_view value) {
    if (dst.empty()) {
        return false;
    }

    if (value.empty() || value.size() >= dst.size()) {
        return false;
    }

    std::memcpy(dst.data(), value.data(), value.size());
    dst[value.size()] = '\0';
    return true;
}

bool ParseEndpointParts(std::string_view configured_endpoint, EndpointParts *out) {
    if (out == nullptr) {
        return false;
    }

    const std::string_view endpoint = TrimView(configured_endpoint);
    if (endpoint.empty()) {
        return false;
    }

    if (endpoint.front() == '[') {
        const std::size_t closing = endpoint.find(']');
        if (closing == std::string_view::npos || closing == 1 || (closing + 1) >= endpoint.size() || endpoint[closing + 1] != ':') {
            return false;
        }

        const std::string_view host = TrimView(endpoint.substr(1, closing - 1));
        const std::string_view service = TrimView(endpoint.substr(closing + 2));
        return CopyView(out->host, host) && CopyView(out->service, service);
    }

    std::size_t separator = std::string_view::npos;
    for (std::size_t i = endpoint.size(); i-- > 0;) {
        if (endpoint[i] == ':') {
            separator = i;
            break;
        }
    }
    if (separator == std::string_view::npos || separator == 0 || (separator + 1) >= endpoint.size()) {
        return false;
    }

    if (endpoint.substr(0, separator).find(':') != std::string_view::npos) {
        return false;
    }

    const std::string_view host = TrimView(endpoint.substr(0, separator));
    const std::string_view service = TrimView(endpoint.substr(separator + 1));
    return CopyView(out->host, host) && CopyView(out->service, service);
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

bool StoreResolvedText(endpoint_resolution_result *out) {
    return out != nullptr && endpoint_to_string(out->resolved, out->text);
}

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

bool ParseSerializedResult(endpoint_resolution_result *out, const void *buffer, std::size_t buffer_size) {
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
            out->resolved = {};
            if (wgnx::sysmodule::platform::horizon::internal::EncodeEndpointFromSockaddr(
                    std::addressof(out->resolved), reinterpret_cast<const sockaddr *>(std::addressof(addr)))) {
                return StoreResolvedText(out);
            }
            return false;
        }

        if (family == AF_INET6) {
            sockaddr_in6 addr = {};
            std::memcpy(std::addressof(addr), cursor + sizeof(AddrInfoSerializedHeader), std::min(addr_length, sizeof(addr)));
            addr.sin6_port = ntohs(addr.sin6_port);
            addr.sin6_flowinfo = ntohl(addr.sin6_flowinfo);
            addr.sin6_scope_id = ntohl(addr.sin6_scope_id);
            out->resolved = {};
            if (wgnx::sysmodule::platform::horizon::internal::EncodeEndpointFromSockaddr(
                    std::addressof(out->resolved), reinterpret_cast<const sockaddr *>(std::addressof(addr)))) {
                return StoreResolvedText(out);
            }
            return false;
        }

        cursor += total_length;
    }

    return false;
}

bool ResolveNumericEndpoint(const EndpointParts &parts, endpoint_resolution_result *out) {
    if (out == nullptr) {
        return false;
    }

    in_addr addr4 = {};
    if (::inet_pton(AF_INET, parts.host, std::addressof(addr4)) == 1) {
        out->resolved = {};
        out->resolved.family = address_family::inet;
        out->resolved.port = static_cast<std::uint16_t>(std::strtoul(parts.service, nullptr, 10));
        std::memcpy(out->resolved.address.data(), std::addressof(addr4), sizeof(addr4));
        return StoreResolvedText(out);
    }

    in6_addr addr6 = {};
    if (::inet_pton(AF_INET6, parts.host, std::addressof(addr6)) == 1) {
        out->resolved = {};
        out->resolved.family = address_family::inet6;
        out->resolved.port = static_cast<std::uint16_t>(std::strtoul(parts.service, nullptr, 10));
        std::memcpy(out->resolved.address.data(), std::addressof(addr6), sizeof(addr6));
        return StoreResolvedText(out);
    }

    return false;
}

} // namespace

endpoint_resolution_result resolve_endpoint(std::string_view configured_endpoint) {
    endpoint_resolution_result result{};

    EndpointParts parts = {};
    if (!ParseEndpointParts(configured_endpoint, std::addressof(parts)) || !ParsePort(parts.service)) {
        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointMalformed;
        return result;
    }

    if (IsNumericHost(parts.host)) {
        if (ResolveNumericEndpoint(parts, std::addressof(result))) {
            result.success = true;
            return result;
        }

        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointResolutionFailed;
        return result;
    }

    if (R_FAILED(wgnx::sysmodule::platform::horizon::internal::EnsureUdpRuntimeInitialized())) {
        result.error_stage = wgnx::PeerErrorStage::Transport;
        result.error_code = wgnx::PeerErrorCode::TransportInitFailed;
        return result;
    }

    resolverSetEnableServiceDiscovery(true);

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
        wgnx::sysmodule::logger::Log("sfdnsresGetAddrInfoRequest failed for '%s:%s': resolver_rc=0x%08x ret=%d errno=%u serialized_size=%u",
            parts.host, parts.service, static_cast<u32>(resolver_rc), remote_ret, remote_errno, serialized_size);
        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointResolutionFailed;
        return result;
    }

    if (serialized_size == 0 || serialized_size > sizeof(g_resolver_addrinfo_buffer)) {
        wgnx::sysmodule::logger::Log("resolver returned invalid serialized size for '%s:%s': size=%u capacity=%zu",
            parts.host, parts.service, serialized_size, sizeof(g_resolver_addrinfo_buffer));
        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointResolutionFailed;
        return result;
    }

    if (ParseSerializedResult(std::addressof(result), g_resolver_addrinfo_buffer, serialized_size)) {
        result.success = true;
        result.error_stage = wgnx::PeerErrorStage::None;
        result.error_code = wgnx::PeerErrorCode::None;
    }

    if (!result.success) {
        wgnx::sysmodule::logger::Log("resolver returned no usable AF_INET/AF_INET6 result for '%s:%s'", parts.host, parts.service);
        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointResolutionFailed;
    }

    return result;
}

} // namespace wgnx::platform
