#include "runtime/endpoint_resolver.hpp"

namespace wgnx::sysmodule::runtime {

bool EndpointResolver::Queue(const ResolveEndpointEffect &request) {
    m_pending = request;
    const bool should_schedule = !m_worker_scheduled;
    m_worker_scheduled = true;
    return should_schedule;
}

void EndpointResolver::MarkWorkerIdle() {
    m_worker_scheduled = false;
}

std::optional<ResolveEndpointEffect> EndpointResolver::Take() {
    auto pending = m_pending;
    m_pending.reset();
    return pending;
}

void EndpointResolver::Cancel(const PeerIdentity &peer) {
    if (m_pending.has_value() && m_pending->peer == peer) {
        m_pending.reset();
    }
}

} // namespace wgnx::sysmodule::runtime
