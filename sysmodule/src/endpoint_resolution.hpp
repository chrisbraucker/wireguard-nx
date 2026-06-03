#pragma once

#include <sys/socket.h>

#include "wgnx/protocol.hpp"

namespace wgnx::sysmodule::endpoint_resolution {

struct ResolvedEndpoint {
    sockaddr_storage address{};
    socklen_t address_length{0};
    std::uint8_t family{0};
    char endpoint[sizeof(wgnx::PeerInfo::resolved_endpoint)]{};
};

struct ResolveResult {
    bool success{false};
    wgnx::PeerErrorStage error_stage{wgnx::PeerErrorStage::None};
    wgnx::PeerErrorCode error_code{wgnx::PeerErrorCode::None};
    ResolvedEndpoint endpoint{};
};

ResolveResult Resolve(const char *configured_endpoint);

} // namespace wgnx::sysmodule::endpoint_resolution
