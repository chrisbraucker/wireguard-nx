#pragma once

#include <array>
#include <cstddef>

#include "wgnx/protocol.hpp"

namespace wgnx {

struct PeerConfigEntry {
    char name[sizeof(PeerInfo::name)];
    char address[sizeof(PeerInfo::address)];
    char endpoint[sizeof(PeerInfo::endpoint)];
};

struct PeerConfigSet {
    std::array<PeerConfigEntry, MaxPeers> peers{};
    std::size_t peer_count{0};
};

} // namespace wgnx
