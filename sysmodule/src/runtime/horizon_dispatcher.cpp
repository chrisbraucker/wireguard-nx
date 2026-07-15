#include "runtime/horizon_dispatcher.hpp"

#include <memory>

namespace wgnx::sysmodule::runtime {

HorizonDispatcher *HorizonDispatcher::s_instance = nullptr;

void HorizonDispatcher::Initialize(
    const HorizonDispatcherCallbacks &callbacks,
    bool enable_network_path_observer,
    wgnx::platform::jiffies_t network_path_observation_interval) {
    if (m_initialized) {
        return;
    }

    m_callbacks = callbacks;
    m_network_observer_enabled = enable_network_path_observer;
    m_network_observation_interval = network_path_observation_interval;
    s_instance = this;

    m_resolve_queue = wgnx::platform::alloc_ordered_workqueue("wgnx-resolve");
    m_submission_queue = wgnx::platform::alloc_ordered_workqueue("wgnx-submit");
    m_receive_queue = wgnx::platform::alloc_ordered_workqueue("wgnx-recv");
    m_timer_queue = wgnx::platform::alloc_ordered_workqueue("wgnx-timer-act");
    AMS_ABORT_UNLESS(m_resolve_queue != nullptr);
    AMS_ABORT_UNLESS(m_submission_queue != nullptr);
    AMS_ABORT_UNLESS(m_receive_queue != nullptr);
    AMS_ABORT_UNLESS(m_timer_queue != nullptr);

    wgnx::platform::INIT_WORK(&m_resolve_work, m_callbacks.resolve);
    wgnx::platform::INIT_WORK(&m_debug_submission_work, m_callbacks.submit_debug_payload);
    wgnx::platform::INIT_WORK(&m_inner_submission_work, m_callbacks.submit_inner_packet);
    wgnx::platform::INIT_WORK(&m_receive_work, m_callbacks.receive);
    for (auto &slot : m_protocol_timers) {
        wgnx::platform::INIT_WORK(&slot.work, TimerWorkCallback);
        wgnx::platform::timer_setup(&slot.timer, ProtocolTimerCallback);
    }
    wgnx::platform::INIT_WORK(&m_debug_timeout_work, TimerWorkCallback);
    wgnx::platform::timer_setup(&m_debug_timeout_timer, AuxiliaryTimerCallback);

    if (m_network_observer_enabled) {
        wgnx::platform::INIT_WORK(&m_network_observer_work, TimerWorkCallback);
        wgnx::platform::timer_setup(&m_network_observer_timer, AuxiliaryTimerCallback);
        static_cast<void>(wgnx::platform::mod_timer(
            &m_network_observer_timer,
            wgnx::platform::get_jiffies_64() + m_network_observation_interval));
    }
    m_initialized = true;
}

void HorizonDispatcher::QueueResolve() {
    if (m_resolve_queue != nullptr) {
        static_cast<void>(wgnx::platform::queue_work(m_resolve_queue, &m_resolve_work));
    }
}

void HorizonDispatcher::QueueDebugPayloadSubmission() {
    if (m_submission_queue != nullptr) {
        static_cast<void>(wgnx::platform::queue_work(
            m_submission_queue,
            &m_debug_submission_work));
    }
}

void HorizonDispatcher::QueueInnerPacketSubmission() {
    if (m_submission_queue != nullptr) {
        static_cast<void>(wgnx::platform::queue_work(
            m_submission_queue,
            &m_inner_submission_work));
    }
}

void HorizonDispatcher::QueueReceive() {
    if (m_receive_queue != nullptr) {
        static_cast<void>(wgnx::platform::queue_work(m_receive_queue, &m_receive_work));
    }
}

HorizonDispatcher::ProtocolTimerSlot &HorizonDispatcher::Slot(
    wgnx::wireguard::TimerHook hook) {
    for (auto &slot : m_protocol_timers) {
        if (slot.hook == hook) {
            return slot;
        }
    }
    return m_protocol_timers.front();
}

void HorizonDispatcher::ArmProtocolTimer(
    wgnx::wireguard::TimerHook hook,
    const wgnx::wireguard::TimerToken &token,
    wgnx::platform::jiffies_t deadline) {
    ProtocolTimerSlot &slot = Slot(hook);
    wgnx::platform::timer_delete_sync(&slot.timer);
    {
        std::scoped_lock lock(m_timer_mutex);
        slot.armed_token = token;
    }
    static_cast<void>(wgnx::platform::mod_timer(&slot.timer, deadline));
}

void HorizonDispatcher::CancelProtocolTimer(wgnx::wireguard::TimerHook hook) {
    ProtocolTimerSlot &slot = Slot(hook);
    wgnx::platform::timer_delete_sync(&slot.timer);
    std::scoped_lock lock(m_timer_mutex);
    slot.armed_token = {};
}

void HorizonDispatcher::CancelAllProtocolTimers() {
    for (auto &slot : m_protocol_timers) {
        CancelProtocolTimer(slot.hook);
    }
}

void HorizonDispatcher::ArmDebugProbeTimeout(wgnx::platform::jiffies_t deadline) {
    static_cast<void>(wgnx::platform::mod_timer(&m_debug_timeout_timer, deadline));
}

void HorizonDispatcher::CancelDebugProbeTimeout() {
    wgnx::platform::timer_delete(&m_debug_timeout_timer);
}

void HorizonDispatcher::ProtocolTimerCallback(wgnx::platform::timer_list *timer) {
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

void HorizonDispatcher::AuxiliaryTimerCallback(wgnx::platform::timer_list *timer) {
    if (s_instance == nullptr || s_instance->m_timer_queue == nullptr) {
        return;
    }
    wgnx::platform::work_struct *work = nullptr;
    if (timer == &s_instance->m_debug_timeout_timer) {
        work = &s_instance->m_debug_timeout_work;
    } else if (timer == &s_instance->m_network_observer_timer) {
        work = &s_instance->m_network_observer_work;
    }
    if (work != nullptr) {
        static_cast<void>(wgnx::platform::queue_work(s_instance->m_timer_queue, work));
    }
}

void HorizonDispatcher::QueueProtocolTimer(ProtocolTimerSlot &slot) {
    if (m_timer_queue == nullptr) {
        return;
    }
    {
        std::scoped_lock lock(m_timer_mutex);
        slot.fired_token = slot.armed_token;
    }
    static_cast<void>(wgnx::platform::queue_work(m_timer_queue, &slot.work));
}

void HorizonDispatcher::TimerWorkCallback(wgnx::platform::work_struct *work) {
    if (s_instance != nullptr) {
        s_instance->RunTimerWork(work);
    }
}

void HorizonDispatcher::RunTimerWork(wgnx::platform::work_struct *work) {
    for (auto &slot : m_protocol_timers) {
        if (work == &slot.work) {
            wgnx::wireguard::TimerToken token{};
            {
                std::scoped_lock lock(m_timer_mutex);
                token = slot.fired_token;
            }
            if (m_callbacks.protocol_timer != nullptr) {
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
