#include "tunnel_discovery_service.hpp"

#include "logger.hpp"
#include "tunnel_flow_worker.hpp"

namespace wgnx::mitm {

namespace {

[[nodiscard]] std::uint64_t GetMonotonicNanoseconds() {
    return ams::os::GetSystemTick().ToTimeSpan().GetNanoSeconds();
}

} // namespace

TunnelDiscoveryService::TunnelDiscoveryService() = default;

void TunnelDiscoveryService::Start() {
    {
        std::scoped_lock lock(m_mutex);
        if (m_started) {
            return;
        }
        m_started = true;
    }

    logger::Log("tunnel discovery controller started state=bypass");

    // The startup probe makes absent-service operation observable.
    // Later attempts are driven only by intercepted traffic or a client CMIF failure.
    RequestForInterceptedTraffic();
}

void TunnelDiscoveryService::Stop() {
    bool was_started = false;
    {
        std::scoped_lock lock(m_mutex);
        was_started = m_started;
        m_started = false;
        m_backoff = {};
        PublishStateLocked();
    }
    logger::Log("tunnel discovery controller stopped prior_started=%u", was_started ? 1U : 0U);
}

void TunnelDiscoveryService::RequestForInterceptedTraffic() {
    bool scheduled = false;
    {
        std::scoped_lock lock(m_mutex);
        if (!m_started) {
            return;
        }
        scheduled = m_backoff.RequestForTraffic(GetMonotonicNanoseconds());
        if (scheduled) {
            PublishStateLocked();
        }
    }
    if (scheduled) {
        logger::Log("tunnel discovery scheduled reason=traffic");
        GetTunnelFlowWorker().RequestDiscoveryAttempt();
    }
}

void TunnelDiscoveryService::ReportTunnelClientFailure() {
    bool invalidated = false;
    {
        std::scoped_lock lock(m_mutex);
        if (!m_started) {
            return;
        }
        invalidated = m_backoff.State() == TunnelAvailabilityState::Ready;
        m_backoff.InvalidateReadyClient(GetMonotonicNanoseconds());
        PublishStateLocked();
    }
    logger::Log("tunnel discovery invalidated prior_state=%s", invalidated ? "ready" : "nonready");
    GetTunnelFlowWorker().RequestTunnelInvalidation();
}

TunnelAvailabilityState TunnelDiscoveryService::GetState() const {
    return m_visible_state.load(std::memory_order_acquire);
}

void TunnelDiscoveryService::CompleteDiscoverySuccess() {
    std::scoped_lock lock(m_mutex);
    if (!m_started || m_backoff.State() != TunnelAvailabilityState::DiscoveryPending) {
        return;
    }
    m_backoff.CompleteSuccess();
    PublishStateLocked();
}

void TunnelDiscoveryService::CompleteDiscoveryFailure() {
    std::uint64_t retry_delay = 0;
    std::uint32_t failures = 0;
    {
        std::scoped_lock lock(m_mutex);
        if (!m_started || m_backoff.State() != TunnelAvailabilityState::DiscoveryPending) {
            return;
        }
        const std::uint64_t now_nanoseconds = GetMonotonicNanoseconds();
        m_backoff.CompleteFailure(now_nanoseconds);
        PublishStateLocked();
        retry_delay = m_backoff.NextRetryNanoseconds() - now_nanoseconds;
        failures = m_backoff.FailureCount();
    }
    logger::Log("tunnel discovery unavailable failures=%u retry_after_ns=%llu", failures, static_cast<unsigned long long>(retry_delay));
}

void TunnelDiscoveryService::PublishStateLocked() {
    m_visible_state.store(m_backoff.State(), std::memory_order_release);
}

TunnelDiscoveryService& GetTunnelDiscoveryService() {
    static TunnelDiscoveryService service;
    return service;
}

} // namespace wgnx::mitm
