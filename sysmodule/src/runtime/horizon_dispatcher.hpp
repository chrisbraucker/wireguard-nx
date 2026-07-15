#pragma once

#include <stratosphere.hpp>

#include "wgnx/platform/work.hpp"
#include "wireguard/timer_coordinator.hpp"

#include <array>
#include <cstddef>

namespace wgnx::sysmodule::runtime {

struct HorizonDispatcherCallbacks {
    wgnx::platform::work_func_t resolve{nullptr};
    wgnx::platform::work_func_t submit_debug_payload{nullptr};
    wgnx::platform::work_func_t submit_inner_packet{nullptr};
    wgnx::platform::work_func_t receive{nullptr};
    void (*protocol_timer)(
        wgnx::wireguard::TimerHook,
        const wgnx::wireguard::TimerToken &){nullptr};
    void (*debug_probe_timeout)(){nullptr};
    void (*network_path_observer)(){nullptr};
};

class HorizonDispatcher {
public:
    void Initialize(
        const HorizonDispatcherCallbacks &callbacks,
        bool enable_network_path_observer,
        wgnx::platform::jiffies_t network_path_observation_interval);

    void QueueResolve();
    void QueueDebugPayloadSubmission();
    void QueueInnerPacketSubmission();
    void QueueReceive();

    void ArmProtocolTimer(
        wgnx::wireguard::TimerHook hook,
        const wgnx::wireguard::TimerToken &token,
        wgnx::platform::jiffies_t deadline);
    void CancelProtocolTimer(wgnx::wireguard::TimerHook hook);
    void CancelAllProtocolTimers();

    void ArmDebugProbeTimeout(wgnx::platform::jiffies_t deadline);
    void CancelDebugProbeTimeout();

private:
    struct ProtocolTimerSlot {
        wgnx::wireguard::TimerHook hook{wgnx::wireguard::TimerHook::RetransmitHandshake};
        wgnx::platform::work_struct work{};
        wgnx::platform::timer_list timer{};
        wgnx::wireguard::TimerToken armed_token{};
        wgnx::wireguard::TimerToken fired_token{};
    };

    static void ProtocolTimerCallback(wgnx::platform::timer_list *timer);
    static void AuxiliaryTimerCallback(wgnx::platform::timer_list *timer);
    static void TimerWorkCallback(wgnx::platform::work_struct *work);

    ProtocolTimerSlot &Slot(wgnx::wireguard::TimerHook hook);
    void QueueProtocolTimer(ProtocolTimerSlot &slot);
    void RunTimerWork(wgnx::platform::work_struct *work);

    static HorizonDispatcher *s_instance;

    HorizonDispatcherCallbacks m_callbacks{};
    wgnx::platform::workqueue_struct *m_resolve_queue{nullptr};
    wgnx::platform::workqueue_struct *m_submission_queue{nullptr};
    wgnx::platform::workqueue_struct *m_receive_queue{nullptr};
    wgnx::platform::workqueue_struct *m_timer_queue{nullptr};
    wgnx::platform::work_struct m_resolve_work{};
    wgnx::platform::work_struct m_debug_submission_work{};
    wgnx::platform::work_struct m_inner_submission_work{};
    wgnx::platform::work_struct m_receive_work{};
    std::array<ProtocolTimerSlot, 4> m_protocol_timers{{
        {.hook = wgnx::wireguard::TimerHook::RetransmitHandshake},
        {.hook = wgnx::wireguard::TimerHook::SendKeepalive},
        {.hook = wgnx::wireguard::TimerHook::Rekey},
        {.hook = wgnx::wireguard::TimerHook::ZeroKeyMaterial},
    }};
    wgnx::platform::work_struct m_debug_timeout_work{};
    wgnx::platform::timer_list m_debug_timeout_timer{};
    wgnx::platform::work_struct m_network_observer_work{};
    wgnx::platform::timer_list m_network_observer_timer{};
    wgnx::platform::jiffies_t m_network_observation_interval{0};
    ams::os::Mutex m_timer_mutex{false};
    bool m_initialized{false};
    bool m_network_observer_enabled{false};
};

} // namespace wgnx::sysmodule::runtime
