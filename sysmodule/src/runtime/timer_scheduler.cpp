#include "runtime/timer_scheduler.hpp"

#include "runtime/horizon_dispatcher.hpp"

namespace wgnx::sysmodule::runtime {

TimerScheduler *TimerScheduler::s_instance = nullptr;

void TimerScheduler::Initialize(
    HorizonDispatcher &dispatcher,
    const TimerSchedulerCallbacks &callbacks) {
    if (m_initialized) {
        return;
    }

    m_dispatcher = &dispatcher;
    m_callbacks = callbacks;
    wgnx::platform::mutex_init(&m_operation_mutex);
    wgnx::platform::mutex_init(&m_mutex);
    s_instance = this;

    for (auto &slot : m_protocol_timers) {
        wgnx::platform::INIT_WORK(&slot.work, TimerWorkCallback);
        wgnx::platform::timer_setup(&slot.timer, ProtocolTimerCallback);
    }
    wgnx::platform::INIT_WORK(&m_debug_timeout_work, TimerWorkCallback);
    wgnx::platform::timer_setup(&m_debug_timeout_timer, AuxiliaryTimerCallback);
    m_initialized = true;
}

TimerScheduler::ProtocolTimerSlot &TimerScheduler::Slot(
    wgnx::wireguard::TimerHook hook) {
    for (auto &slot : m_protocol_timers) {
        if (slot.hook == hook) {
            return slot;
        }
    }
    return m_protocol_timers.front();
}

void TimerScheduler::ArmProtocolTimer(
    const wgnx::wireguard::TimerToken &token,
    wgnx::wireguard::TimerDeadline deadline) {
    if (!token.IsValid()) {
        return;
    }

    ProtocolTimerSlot &slot = Slot(token.hook);
    wgnx::platform::MutexGuard operation_lock{m_operation_mutex};
    wgnx::platform::timer_delete_sync(&slot.timer);
    bool armed = false;
    {
        wgnx::platform::MutexGuard schedule_lock{m_mutex};
        armed = m_schedule.Arm(token, deadline);
    }
    if (armed) {
        static_cast<void>(wgnx::platform::mod_timer(
            &slot.timer,
            wgnx::wireguard::TimerDeadlineToJiffies(deadline)));
    }
}

void TimerScheduler::CancelProtocolTimer(wgnx::wireguard::TimerHook hook) {
    ProtocolTimerSlot &slot = Slot(hook);
    wgnx::platform::MutexGuard operation_lock{m_operation_mutex};
    wgnx::platform::timer_delete_sync(&slot.timer);
    wgnx::platform::MutexGuard schedule_lock{m_mutex};
    m_schedule.Cancel(hook);
}

void TimerScheduler::CancelProtocolTimer(
    const wgnx::wireguard::TimerToken &token) {
    if (!token.IsValid()) {
        return;
    }

    ProtocolTimerSlot &slot = Slot(token.hook);
    wgnx::platform::MutexGuard operation_lock{m_operation_mutex};
    bool current = false;
    {
        wgnx::platform::MutexGuard schedule_lock{m_mutex};
        current = m_schedule.ArmedToken(token.hook) == token;
    }
    if (current) {
        wgnx::platform::timer_delete_sync(&slot.timer);
        wgnx::platform::MutexGuard schedule_lock{m_mutex};
        static_cast<void>(m_schedule.Cancel(token));
    }
}

void TimerScheduler::CancelAllProtocolTimers() {
    wgnx::platform::MutexGuard operation_lock{m_operation_mutex};
    for (auto &slot : m_protocol_timers) {
        wgnx::platform::timer_delete_sync(&slot.timer);
    }
    wgnx::platform::MutexGuard schedule_lock{m_mutex};
    m_schedule.CancelAll();
}

void TimerScheduler::ArmDebugProbeTimeout(wgnx::platform::jiffies_t deadline) {
    wgnx::platform::MutexGuard operation_lock{m_operation_mutex};
    static_cast<void>(wgnx::platform::mod_timer(&m_debug_timeout_timer, deadline));
}

void TimerScheduler::CancelDebugProbeTimeout() {
    wgnx::platform::MutexGuard operation_lock{m_operation_mutex};
    wgnx::platform::timer_delete(&m_debug_timeout_timer);
}

void TimerScheduler::ProtocolTimerCallback(wgnx::platform::timer_list *timer) {
    if (s_instance == nullptr) {
        return;
    }
    for (auto &slot : s_instance->m_protocol_timers) {
        if (timer == &slot.timer) {
            s_instance->QueueProtocolTimer(slot);
            return;
        }
    }
}

void TimerScheduler::AuxiliaryTimerCallback(wgnx::platform::timer_list *timer) {
    if (s_instance == nullptr || s_instance->m_dispatcher == nullptr) {
        return;
    }
    if (timer == &s_instance->m_debug_timeout_timer) {
        s_instance->m_dispatcher->QueueTimerWork(&s_instance->m_debug_timeout_work);
    }
}

void TimerScheduler::QueueProtocolTimer(ProtocolTimerSlot &slot) {
    if (m_dispatcher == nullptr) {
        return;
    }

    bool captured = false;
    {
        wgnx::platform::MutexGuard schedule_lock{m_mutex};
        captured = m_schedule.CaptureExpiration(slot.hook);
    }
    if (captured) {
        m_dispatcher->QueueTimerWork(&slot.work);
    }
}

void TimerScheduler::TimerWorkCallback(wgnx::platform::work_struct *work) {
    if (s_instance != nullptr) {
        s_instance->RunTimerWork(work);
    }
}

void TimerScheduler::RunTimerWork(wgnx::platform::work_struct *work) {
    for (auto &slot : m_protocol_timers) {
        if (work == &slot.work) {
            wgnx::wireguard::TimerToken token{};
            {
                wgnx::platform::MutexGuard schedule_lock{m_mutex};
                token = m_schedule.TakeDelivery(slot.hook);
            }
            if (token.IsValid() && m_callbacks.protocol_timer != nullptr) {
                m_callbacks.protocol_timer(slot.hook, token);
            }
            return;
        }
    }

    if (work == &m_debug_timeout_work) {
        if (m_callbacks.debug_probe_timeout != nullptr) {
            m_callbacks.debug_probe_timeout();
        }
        return;
    }
}

} // namespace wgnx::sysmodule::runtime
