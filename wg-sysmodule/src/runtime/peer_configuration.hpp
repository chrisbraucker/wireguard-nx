#pragma once

#include "runtime/peer/peer_runtime.hpp"

#include <array>
#include <cstddef>

namespace wgnx::sysmodule::runtime {

struct LoadedPeerConfiguration {
    std::array<wgnx::PeerConfigEntry, wgnx::MaxPeers> peers{};
    std::array<PeerConfigDerivedInfo, wgnx::MaxPeers> derived{};
    std::size_t peer_count{0};
    std::int32_t auto_start_peer_index{-1};
};

class PeerConfigurationLoader {
  public:
    bool Load(LoadedPeerConfiguration& out) const;
};

} // namespace wgnx::sysmodule::runtime
