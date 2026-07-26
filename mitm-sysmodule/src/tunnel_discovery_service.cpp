#include "tunnel_discovery_service.hpp"

#include "logger.hpp"

#include "wgnx/tunnel_client.hpp"

#include <array>
#include <memory>

namespace wgnx::mitm {

namespace {

constexpr std::size_t DiscoveryThreadStackBytes = 16 * 1024;
constexpr std::uint32_t RequiredTunnelCapabilities = wgnx::tunnel::CapabilityMask(wgnx::tunnel::Capability::ConnectedIpv4Udp) |
                                                     wgnx::tunnel::CapabilityMask(wgnx::tunnel::Capability::RoutingPolicySnapshot) |
                                                     wgnx::tunnel::CapabilityMask(wgnx::tunnel::Capability::CompletionEvent);

alignas(ams::os::ThreadStackAlignment) constinit std::array<std::byte, DiscoveryThreadStackBytes> g_discovery_thread_stack{};

[[nodiscard]] std::uint64_t GetMonotonicNanoseconds() {
    return ams::os::GetSystemTick().ToTimeSpan().GetNanoSeconds();
}

[[nodiscard]] bool HasRequiredCapabilities(const wgnx::tunnel::Capabilities& capabilities) {
    return capabilities.api_version == wgnx::tunnel::TunApiVersion &&
           (capabilities.capability_mask & RequiredTunnelCapabilities) == RequiredTunnelCapabilities;
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

    R_ABORT_UNLESS(ams::os::CreateThread(std::addressof(m_thread), ThreadMain, this, g_discovery_thread_stack.data(),
                                         g_discovery_thread_stack.size(), ams::os::DefaultThreadPriority));
    ams::os::SetThreadNamePointer(std::addressof(m_thread), "wgnx-tun-discovery");
    ams::os::StartThread(std::addressof(m_thread));
    logger::Log("tunnel discovery worker started state=bypass");

    // The startup probe makes absent-service operation observable.
    // Later attempts are driven only by intercepted traffic or a CMIF failure.
    RequestForInterceptedTraffic();
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
            m_attempt_requested.store(true, std::memory_order_release);
        }
    }
    if (scheduled) {
        m_wake_event.Signal();
    }
}

void TunnelDiscoveryService::ReportTunnelClientFailure() {
    {
        std::scoped_lock lock(m_mutex);
        if (!m_started) {
            return;
        }
        m_backoff.InvalidateReadyClient(GetMonotonicNanoseconds());
        PublishStateLocked();
        m_client_invalidation_requested.store(true, std::memory_order_release);
    }
    m_wake_event.Signal();
}

TunnelAvailabilityState TunnelDiscoveryService::GetState() const {
    return m_visible_state.load(std::memory_order_acquire);
}

void TunnelDiscoveryService::ThreadMain(void* argument) {
    static_cast<TunnelDiscoveryService*>(argument)->Run();
}

void TunnelDiscoveryService::Run() {
    // The worker is intentionally process-lifetime because the sysmodule is resident.
    // It is the only owner of the root and child CMIF sessions.
    wgnx::tunnel::client::ScopedRootService root;
    wgnx::tunnel::client::ScopedClient client;

    for (;;) {
        m_wake_event.Wait();
        m_wake_event.Clear();

        if (m_client_invalidation_requested.exchange(false, std::memory_order_acq_rel)) {
            client.Close();
            root.Close();
            logger::Log("tunnel client invalidated state=bypass");
        }

        if (!m_attempt_requested.exchange(false, std::memory_order_acq_rel)) {
            continue;
        }

        client.Close();
        root.Close();

        if (!wgnx::tunnel::client::IsServiceRunning()) {
            CompleteDiscoveryFailure();
            continue;
        }

        const Result root_result = root.Open();
        if (R_FAILED(root_result)) {
            CompleteDiscoveryFailure();
            continue;
        }

        wgnx::tunnel::Capabilities capabilities{};
        const Result capabilities_result = wgnx::tunnel::client::GetTunCapabilities(root, std::addressof(capabilities));
        if (R_FAILED(capabilities_result) || !HasRequiredCapabilities(capabilities)) {
            root.Close();
            CompleteDiscoveryFailure();
            continue;
        }

        const Result client_result = wgnx::tunnel::client::OpenTunnelClient(root, std::addressof(client));
        if (R_FAILED(client_result)) {
            root.Close();
            CompleteDiscoveryFailure();
            continue;
        }

        const Result client_capabilities_result = wgnx::tunnel::client::GetCapabilities(client, std::addressof(capabilities));
        if (R_FAILED(client_capabilities_result) || !HasRequiredCapabilities(capabilities)) {
            client.Close();
            root.Close();
            CompleteDiscoveryFailure();
            continue;
        }

        {
            std::scoped_lock lock(m_mutex);
            m_backoff.CompleteSuccess();
            PublishStateLocked();
        }
        logger::Log("tunnel client ready api=%u capabilities=0x%08X", capabilities.api_version, capabilities.capability_mask);
    }
}

void TunnelDiscoveryService::CompleteDiscoveryFailure() {
    std::uint64_t retry_delay = 0;
    std::uint32_t failures = 0;
    {
        std::scoped_lock lock(m_mutex);
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
