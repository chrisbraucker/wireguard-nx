#include "runtime/timer_scheduler.hpp"

#include "runtime/horizon_dispatcher.hpp"

namespace wgnx::sysmodule::runtime {

TimerScheduler *TimerScheduler::s_instance = nullptr;

void TimerScheduler::Initialize(
    HorizonDispatcher &dispatcher,
    const TimerSchedulerCallbacks &callbacks,
    bool enable_network_path_observer,
    wgnx::platform::jiffies_t network_path_observation_interval) {
    if (m_initialized) {
        return;
    }

    m_dispatcher = &dispatcher;
    m_callbacks = callbacks;
    m_network_observer_enabled = enable_network_path_observer;
    m_network_observation_interval = network_path_observation_interval;
    wgnx::platform::mutex_init(&m_operation_mutex);
    wgnx::platform::mutex_init(&m_mutex);
    s_instance = this;

    for (auto &slot : m_protocol_timers) {
        wgnx::platform::INIT_WORK(&slot.work, TimerWorkCallback);
        wgnx::platform::timer_setup(&slot.timer, ProtocolTimerCallback);
    }
    wgnx::platform::INIT_WORK(&m_debug_timeout_work, TimerWorkCallback);
    wgnx::platform::timer_setup(&m_debug_timeout_timer, AuxiliaryTimerCallback);
    wgnx::platform::INIT_WORK(&m_network_observer_work, TimerWorkCallback);
    wgnx::platform::timer_setup(&m_network_observer_timer, AuxiliaryTimerCallback);

    if (m_network_observer_enabled) {
        static_cast<void>(wgnx::platform::mod_timer(
            &m_network_observer_timer,
            wgnx::platform::get_jiffies_64() + m_network_observation_interval));
    }
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
    wgnx::platform::mutex_lock(&m_operation_mutex);
    wgnx::platform::timer_delete_sync(&slot.timer);
    wgnx::platform::mutex_lock(&m_mutex);
    const bool armed = m_schedule.Arm(token, deadline);
    wgnx::platform::mutex_unlock(&m_mutex);
    if (armed) {
        static_cast<void>(wgnx::platform::mod_timer(
            &slot.timer,
            wgnx::wireguard::TimerDeadlineToJiffies(deadline)));
    }
    wgnx::platform::mutex_unlock(&m_operation_mutex);
}

void TimerScheduler::CancelProtocolTimer(wgnx::wireguard::TimerHook hook) {
    ProtocolTimerSlot &slot = Slot(hook);
    wgnx::platform::mutex_lock(&m_operation_mutex);
    wgnx::platform::timer_delete_sync(&slot.timer);
    wgnx::platform::mutex_lock(&m_mutex);
    m_schedule.Cancel(hook);
    wgnx::platform::mutex_unlock(&m_mutex);
    wgnx::platform::mutex_unlock(&m_operation_mutex);
}

void TimerScheduler::CancelProtocolTimer(
    const wgnx::wireguard::TimerToken &token) {
    if (!token.IsValid()) {
        return;
    }

    ProtocolTimerSlot &slot = Slot(token.hook);
    wgnx::platform::mutex_lock(&m_operation_mutex);
    wgnx::platform::mutex_lock(&m_mutex);
    const bool current = m_schedule.ArmedToken(token.hook) == token;
    wgnx::platform::mutex_unlock(&m_mutex);
    if (current) {
        wgnx::platform::timer_delete_sync(&slot.timer);
        wgnx::platform::mutex_lock(&m_mutex);
        static_cast<void>(m_schedule.Cancel(token));
        wgnx::platform::mutex_unlock(&m_mutex);
    }
    wgnx::platform::mutex_unlock(&m_operation_mutex);
}

void TimerScheduler::CancelAllProtocolTimers() {
    wgnx::platform::mutex_lock(&m_operation_mutex);
    for (auto &slot : m_protocol_timers) {
        wgnx::platform::timer_delete_sync(&slot.timer);
    }
    wgnx::platform::mutex_lock(&m_mutex);
    m_schedule.CancelAll();
    wgnx::platform::mutex_unlock(&m_mutex);
    wgnx::platform::mutex_unlock(&m_operation_mutex);
}

void TimerScheduler::ArmDebugProbeTimeout(wgnx::platform::jiffies_t deadline) {
    wgnx::platform::mutex_lock(&m_operation_mutex);
    static_cast<void>(wgnx::platform::mod_timer(&m_debug_timeout_timer, deadline));
    wgnx::platform::mutex_unlock(&m_operation_mutex);
}

void TimerScheduler::CancelDebugProbeTimeout() {
    wgnx::platform::mutex_lock(&m_operation_mutex);
    wgnx::platform::timer_delete(&m_debug_timeout_timer);
    wgnx::platform::mutex_unlock(&m_operation_mutex);
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
    } else if (timer == &s_instance->m_network_observer_timer) {
        s_instance->m_dispatcher->QueueTimerWork(&s_instance->m_network_observer_work);
    }
}

void TimerScheduler::QueueProtocolTimer(ProtocolTimerSlot &slot) {
    if (m_dispatcher == nullptr) {
        return;
    }

    wgnx::platform::mutex_lock(&m_mutex);
    const bool captured = m_schedule.CaptureExpiration(slot.hook);
    wgnx::platform::mutex_unlock(&m_mutex);
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
            wgnx::platform::mutex_lock(&m_mutex);
            const auto token = m_schedule.TakeDelivery(slot.hook);
            wgnx::platform::mutex_unlock(&m_mutex);
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
    if (work == &m_network_observer_work && m_network_observer_enabled) {
        if (m_callbacks.network_path_observer != nullptr) {
            m_callbacks.network_path_observer();
        }
        static_cast<void>(wgnx::platform::mod_timer(
            &m_network_observer_timer,
            wgnx::platform::get_jiffies_64() + m_network_observation_interval));
    }
}

} // namespace wgnx::sysmodule::runtime
