#include "runtime/endpoint_resolver.hpp"

namespace wgnx::sysmodule::runtime {

EndpointQueueResult EndpointResolver::Queue(const ResolveEndpointEffect& request) {
    const bool replaced = m_pending.has_value();
    m_pending = request;
    m_accounting.RecordAdmission(replaced);
    const bool should_schedule = !m_worker_scheduled;
    m_worker_scheduled = true;
    if (!should_schedule) {
        m_accounting.RecordCoalesced();
    }
    if (should_schedule) {
        return EndpointQueueResult::Scheduled;
    }
    return replaced ? EndpointQueueResult::Replaced : EndpointQueueResult::Coalesced;
}

void EndpointResolver::MarkWorkerIdle() {
    m_worker_scheduled = false;
}

std::optional<ResolveEndpointEffect> EndpointResolver::Take() {
    auto pending = m_pending;
    m_pending.reset();
    if (pending.has_value()) {
        m_accounting.RecordTake();
    }
    return pending;
}

void EndpointResolver::Cancel(const PeerIdentity& peer) {
    if (m_pending.has_value() && m_pending->peer == peer) {
        m_pending.reset();
        m_accounting.RecordCancellation();
    }
}

} // namespace wgnx::sysmodule::runtime
