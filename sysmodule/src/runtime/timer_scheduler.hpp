#pragma once

#include "runtime/timer_schedule.hpp"
#include "wgnx/platform/sync.hpp"
#include "wgnx/platform/work.hpp"
#include "wgnx/resource_budget.hpp"

#include <array>
#include <cstddef>

namespace wgnx::sysmodule::runtime {

class HorizonDispatcher;

struct TimerSchedulerCallbacks {
    void (*protocol_timer)(wgnx::wireguard::TimerHook, const wgnx::wireguard::TimerToken&){nullptr};
    void (*debug_probe_timeout)(){nullptr};
};

class TimerScheduler {
  public:
    void Initialize(HorizonDispatcher& dispatcher, const TimerSchedulerCallbacks& callbacks);

    void ArmProtocolTimer(const wgnx::wireguard::TimerToken& token, wgnx::wireguard::TimerDeadline deadline);
    void CancelProtocolTimer(const wgnx::wireguard::TimerToken& token);
    void CancelProtocolTimer(wgnx::wireguard::TimerHook hook);
    void CancelAllProtocolTimers();

    void ArmDebugProbeTimeout(wgnx::platform::jiffies_t deadline);
    void CancelDebugProbeTimeout();

  private:
    struct ProtocolTimerSlot {
        wgnx::wireguard::TimerHook hook{wgnx::wireguard::TimerHook::RetransmitHandshake};
        wgnx::platform::work_struct work{};
        wgnx::platform::timer_list timer{};
    };

    static void ProtocolTimerCallback(wgnx::platform::timer_list* timer);
    static void AuxiliaryTimerCallback(wgnx::platform::timer_list* timer);
    static void TimerWorkCallback(wgnx::platform::work_struct* work);

    ProtocolTimerSlot& Slot(wgnx::wireguard::TimerHook hook);
    void QueueProtocolTimer(ProtocolTimerSlot& slot);
    void RunTimerWork(wgnx::platform::work_struct* work);

    static TimerScheduler* s_instance;

    HorizonDispatcher* m_dispatcher{nullptr};
    TimerSchedulerCallbacks m_callbacks{};
    TimerSchedule m_schedule{};
    std::array<ProtocolTimerSlot, wgnx::resource_budget::ProtocolTimerSlots> m_protocol_timers{{
        {.hook = wgnx::wireguard::TimerHook::RetransmitHandshake},
        {.hook = wgnx::wireguard::TimerHook::SendKeepalive},
        {.hook = wgnx::wireguard::TimerHook::NewHandshake},
        {.hook = wgnx::wireguard::TimerHook::ZeroKeyMaterial},
        {.hook = wgnx::wireguard::TimerHook::PersistentKeepalive},
    }};
    wgnx::platform::work_struct m_debug_timeout_work{};
    wgnx::platform::timer_list m_debug_timeout_timer{};
    wgnx::platform::mutex m_operation_mutex{};
    wgnx::platform::mutex m_mutex{};
    bool m_initialized{false};
};

static_assert(sizeof(TimerScheduler) <= wgnx::resource_budget::MaximumTimerSchedulerBytes);

} // namespace wgnx::sysmodule::runtime
