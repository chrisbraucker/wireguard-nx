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

#include <stratosphere.hpp>
#include <switch/runtime/resolver.h>

extern "C" {
#include <switch/services/sfdnsres.h>
}

#include "logger.hpp"
#include "platform/endpoint_parser.hpp"
#include "platform/resolver_serialization.hpp"
#include "wgnx/resource_budget.hpp"

namespace wgnx::platform {

namespace {

constexpr inline std::size_t ResolverAddrInfoBufferSize = wgnx::resource_budget::ResolverScratchBytes;

constinit std::uint8_t g_resolver_addrinfo_buffer[ResolverAddrInfoBufferSize] = {};

bool IsNumericHost(const char* host) {
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

bool StoreResolvedText(endpoint_resolution_result* out) {
    return out != nullptr && endpoint_to_string(out->resolved, out->text);
}

bool ResolveNumericEndpoint(const EndpointTextParts& parts, endpoint_resolution_result* out) {
    if (out == nullptr) {
        return false;
    }

    in_addr addr4 = {};
    if (::inet_pton(AF_INET, parts.host.data(), std::addressof(addr4)) == 1) {
        out->resolved = {};
        out->resolved.family = address_family::inet;
        out->resolved.port = static_cast<std::uint16_t>(std::strtoul(parts.service.data(), nullptr, 10));
        std::memcpy(out->resolved.address.data(), std::addressof(addr4), sizeof(addr4));
        return StoreResolvedText(out);
    }

    in6_addr addr6 = {};
    if (::inet_pton(AF_INET6, parts.host.data(), std::addressof(addr6)) == 1) {
        out->resolved = {};
        out->resolved.family = address_family::inet6;
        out->resolved.port = static_cast<std::uint16_t>(std::strtoul(parts.service.data(), nullptr, 10));
        std::memcpy(out->resolved.address.data(), std::addressof(addr6), sizeof(addr6));
        return StoreResolvedText(out);
    }

    return false;
}

} // namespace

endpoint_resolution_result resolve_endpoint(std::string_view configured_endpoint) {
    endpoint_resolution_result result{};

    EndpointTextParts parts = {};
    if (!ParseEndpointText(configured_endpoint, std::addressof(parts)) || !ParseEndpointPort(parts.service.data())) {
        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointMalformed;
        return result;
    }

    if (IsNumericHost(parts.host.data())) {
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

    resolver_serialization::HorizonAddrInfoHints hints_buffer{};
    if (!resolver_serialization::serialize_horizon_addrinfo_hints(hints_buffer, hints.ai_flags, hints.ai_family, hints.ai_socktype,
                                                                  hints.ai_protocol)) {
        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointResolutionFailed;
        return result;
    }

    std::uint32_t remote_errno = 0;
    std::uint32_t serialized_size = 0;
    s32 remote_ret = 0;
    const Result resolver_rc =
        sfdnsresGetAddrInfoRequest(resolverGetCancelHandle(), resolverGetEnableServiceDiscovery(), parts.host.data(), parts.service.data(),
                                   hints_buffer.data(), hints_buffer.size(), g_resolver_addrinfo_buffer, sizeof(g_resolver_addrinfo_buffer),
                                   std::addressof(remote_errno), std::addressof(remote_ret), std::addressof(serialized_size));

    if (R_FAILED(resolver_rc) || remote_ret != 0) {
        wgnx::sysmodule::logger::Log("sfdnsresGetAddrInfoRequest failed for '%s:%s': resolver_rc=0x%08x ret=%d errno=%u serialized_size=%u",
                                     parts.host.data(), parts.service.data(), static_cast<u32>(resolver_rc), remote_ret, remote_errno,
                                     serialized_size);
        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointResolutionFailed;
        return result;
    }

    if (serialized_size == 0 || serialized_size > sizeof(g_resolver_addrinfo_buffer)) {
        wgnx::sysmodule::logger::Log("resolver returned invalid serialized size for '%s:%s': size=%u capacity=%zu", parts.host.data(),
                                     parts.service.data(), serialized_size, sizeof(g_resolver_addrinfo_buffer));
        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointResolutionFailed;
        return result;
    }

    if (resolver_serialization::parse_horizon_addrinfo_result(std::span{g_resolver_addrinfo_buffer}.first(serialized_size),
                                                              result.resolved) &&
        StoreResolvedText(std::addressof(result))) {
        result.success = true;
        result.error_stage = wgnx::PeerErrorStage::None;
        result.error_code = wgnx::PeerErrorCode::None;
    }

    if (!result.success) {
        wgnx::sysmodule::logger::Log("resolver returned no usable AF_INET/AF_INET6 result for '%s:%s'", parts.host.data(),
                                     parts.service.data());
        result.error_stage = wgnx::PeerErrorStage::ResolveEndpoint;
        result.error_code = wgnx::PeerErrorCode::EndpointResolutionFailed;
    }

    return result;
}

} // namespace wgnx::platform
