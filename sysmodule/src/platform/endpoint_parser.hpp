#pragma once

#include "wgnx/protocol.hpp"

#include <array>
#include <cstddef>
#include <string_view>

namespace wgnx::platform {

struct EndpointTextParts {
    std::array<char, sizeof(wgnx::PeerInfo::endpoint)> host{};
    std::array<char, 6> service{};
};

bool ParseEndpointText(std::string_view configured_endpoint, EndpointTextParts* out);
bool ParseEndpointPort(const char* service);

} // namespace wgnx::platform
