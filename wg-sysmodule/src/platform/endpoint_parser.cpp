#include "platform/endpoint_parser.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <span>

namespace wgnx::platform {

namespace {

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
    if (dst.empty() || value.empty() || value.size() >= dst.size()) {
        return false;
    }

    std::memcpy(dst.data(), value.data(), value.size());
    dst[value.size()] = '\0';
    return true;
}

} // namespace

bool ParseEndpointText(std::string_view configured_endpoint, EndpointTextParts* out) {
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
    if (separator == std::string_view::npos || separator == 0 || (separator + 1) >= endpoint.size() ||
        endpoint.substr(0, separator).find(':') != std::string_view::npos) {
        return false;
    }

    const std::string_view host = TrimView(endpoint.substr(0, separator));
    const std::string_view service = TrimView(endpoint.substr(separator + 1));
    return CopyView(out->host, host) && CopyView(out->service, service);
}

bool ParseEndpointPort(const char* service) {
    if (service == nullptr || service[0] == '\0') {
        return false;
    }

    char* end = nullptr;
    errno = 0;
    const unsigned long value = std::strtoul(service, &end, 10);
    return errno == 0 && end != service && *end == '\0' && value > 0 && value <= 65535;
}

} // namespace wgnx::platform
