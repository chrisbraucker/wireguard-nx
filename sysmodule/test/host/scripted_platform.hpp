#pragma once

#include "runtime/autostart_persistence.hpp"
#include "runtime/endpoint_resolver.hpp"
#include "runtime/runtime_coordinator.hpp"
#include "runtime/timer_schedule.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>
#include <vector>

namespace wgnx::test {

// Host-only execution adapter for the runtime event/effect boundary. It does
// not reproduce WireGuard decisions: RuntimeCoordinator remains the production
// state owner, while scripts determine how platform work completes.
class ScriptedPlatform {
  public:
    struct UdpOpenResult {
        wgnx::platform::socket_handle socket{wgnx::platform::InvalidSocket};
        wgnx::platform::socket_error error{wgnx::platform::socket_error::none};
    };

    struct UdpSendResult {
        wgnx::platform::socket_error error{wgnx::platform::socket_error::none};
        std::size_t bytes_sent{0};
    };

    struct UdpReceiveResult {
        enum class Kind : std::uint8_t {
            Datagram = 0,
            Failure,
        };

        Kind kind{Kind::Datagram};
        std::array<std::uint8_t, wgnx::MaxInnerIpv4PacketSize> bytes{};
        std::size_t size{0};
        wgnx::platform::endpoint source{};
        wgnx::platform::socket_error error{wgnx::platform::socket_error::none};
    };

    struct Statistics {
        std::size_t resolve_requests{0};
        std::size_t udp_open_requests{0};
        std::size_t udp_send_requests{0};
        std::size_t udp_receive_requests{0};
        std::size_t udp_close_requests{0};
        std::size_t persistence_attempts{0};
    };

    explicit ScriptedPlatform(wgnx::sysmodule::runtime::RuntimeCoordinator& coordinator, wgnx::platform::ktime_t initial_time = 1'000);

    void QueueResolutionResult(const wgnx::platform::endpoint_resolution_result& result);
    void QueueUdpOpenResult(UdpOpenResult result);
    void QueueUdpSendResult(UdpSendResult result);
    void QueueUdpReceiveResult(UdpReceiveResult result);
    void QueuePersistenceResult(bool success);

    void Execute(const wgnx::sysmodule::runtime::EffectBatch& effects);
    bool CompleteNextResolution();
    bool CompleteNextUdpOpen();
    bool CompleteNextUdpSend();
    bool CompleteNextUdpReceive();
    bool CaptureTimerExpiration(wgnx::wireguard::TimerHook hook);
    bool DeliverCapturedTimer(wgnx::wireguard::TimerHook hook);
    bool CancelResolution(const wgnx::sysmodule::runtime::PeerIdentity& peer);
    bool PersistAutoStart(wgnx::sysmodule::runtime::AutoStartPersistenceState& state,
                          const wgnx::sysmodule::runtime::AutoStartPersistenceRequest& request);

    bool HasPendingResolution() const;
    bool HasPendingUdpOpen() const;
    bool HasPendingUdpSend() const;
    bool HasPendingUdpReceive() const;
    bool IsTimerArmed(wgnx::wireguard::TimerHook hook) const;
    std::span<const wgnx::platform::socket_handle> ClosedSockets() const;
    const Statistics& GetStatistics() const;

  private:
    using RuntimeEffect = wgnx::sysmodule::runtime::RuntimeEffect;
    using EffectBatch = wgnx::sysmodule::runtime::EffectBatch;
    using PeerIdentity = wgnx::sysmodule::runtime::PeerIdentity;

    void ExecuteEffect(const RuntimeEffect& effect, EffectBatch& generated);
    wgnx::platform::endpoint_resolution_result TakeResolutionResult();
    UdpOpenResult TakeUdpOpenResult();
    UdpSendResult TakeUdpSendResult();
    wgnx::platform::ktime_t NextTime();

    wgnx::sysmodule::runtime::RuntimeCoordinator& m_coordinator;
    wgnx::sysmodule::runtime::EndpointResolver m_resolver{};
    wgnx::sysmodule::runtime::TimerSchedule m_timers{};
    std::deque<wgnx::platform::endpoint_resolution_result> m_resolution_results{};
    std::deque<UdpOpenResult> m_udp_open_results{};
    std::deque<UdpSendResult> m_udp_send_results{};
    std::deque<UdpReceiveResult> m_udp_receive_results{};
    std::deque<bool> m_persistence_results{};
    std::deque<wgnx::sysmodule::runtime::OpenUdpBindEffect> m_udp_open_requests{};
    std::deque<wgnx::sysmodule::runtime::SendPendingDatagramEffect> m_udp_send_requests{};
    std::deque<wgnx::sysmodule::runtime::QueueReceiveEffect> m_udp_receive_requests{};
    std::vector<wgnx::platform::socket_handle> m_closed_sockets{};
    Statistics m_statistics{};
    wgnx::platform::ktime_t m_now{0};
    wgnx::platform::socket_handle m_next_socket{100};
};

} // namespace wgnx::test
