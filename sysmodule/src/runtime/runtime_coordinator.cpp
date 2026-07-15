#include "runtime/runtime_coordinator.hpp"

namespace wgnx::sysmodule::runtime {

EffectBatch RuntimeCoordinator::Dispatch(const PeerEvent &event) {
    const PeerIdentity identity = GetPeerIdentity(event);
    if (identity.peer_index >= m_peers.Count()) {
        return {};
    }
    return m_peers[identity.peer_index].Handle(event);
}

} // namespace wgnx::sysmodule::runtime
