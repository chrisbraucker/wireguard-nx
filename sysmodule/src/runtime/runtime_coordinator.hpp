#pragma once

#include "runtime/peer_runtime.hpp"
#include "runtime/runtime_events.hpp"

namespace wgnx::sysmodule::runtime {

class RuntimeCoordinator {
public:
    explicit constexpr RuntimeCoordinator(PeerRegistry &peers) : m_peers(peers) {}

    EffectBatch Dispatch(const PeerEvent &event);

private:
    PeerRegistry &m_peers;
};

} // namespace wgnx::sysmodule::runtime
