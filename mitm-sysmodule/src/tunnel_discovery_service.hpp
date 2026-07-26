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

    // This is safe to call from the future BSD dispatch path.
    // It only updates bounded local state and signals the worker.
    void RequestForInterceptedTraffic();

    // Future CMIF callers use this after a command failure.
    // The worker owns service-handle closure and reacquisition.
    void ReportTunnelClientFailure();

    [[nodiscard]] TunnelAvailabilityState GetState() const;

  private:
    static void ThreadMain(void* argument);
    void Run();
    void CompleteDiscoveryFailure();
    void PublishStateLocked();

    ams::os::Mutex m_mutex{false};
    ams::os::Event m_wake_event{ams::os::EventClearMode_ManualClear};
    ams::os::ThreadType m_thread{};
    TunnelDiscoveryBackoff m_backoff{};
    std::atomic<TunnelAvailabilityState> m_visible_state{TunnelAvailabilityState::Bypass};
    std::atomic_bool m_attempt_requested{false};
    std::atomic_bool m_client_invalidation_requested{false};
    bool m_started{false};
};

TunnelDiscoveryService& GetTunnelDiscoveryService();

} // namespace wgnx::mitm
