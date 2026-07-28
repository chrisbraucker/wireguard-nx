#pragma once

#include "tunnel_discovery_state.hpp"

#include <stratosphere.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace wgnx::mitm {

class TunnelDiscoveryService {
  public:
    TunnelDiscoveryService();

    TunnelDiscoveryService(const TunnelDiscoveryService&) = delete;
    TunnelDiscoveryService& operator=(const TunnelDiscoveryService&) = delete;

    void Start();
    void Stop();

    // This is safe to call from the BSD dispatch path.
    // It updates bounded local state and asks the flow worker to discover the tunnel.
    void RequestForInterceptedTraffic();

    // The flow worker uses this after a client CMIF failure.
    // It publishes bypass before asking the same worker to discard its handles.
    void ReportTunnelClientFailure();

    [[nodiscard]] TunnelAvailabilityState GetState() const;

  private:
    friend class TunnelFlowWorker;

    // Only the flow worker completes a scheduled discovery attempt.
    void CompleteDiscoverySuccess();
    void CompleteDiscoveryFailure();

    void PublishStateLocked();

    ams::os::Mutex m_mutex{false};
    TunnelDiscoveryBackoff m_backoff{};
    std::atomic<TunnelAvailabilityState> m_visible_state{TunnelAvailabilityState::Bypass};
    bool m_started{false};
};

TunnelDiscoveryService& GetTunnelDiscoveryService();

} // namespace wgnx::mitm
