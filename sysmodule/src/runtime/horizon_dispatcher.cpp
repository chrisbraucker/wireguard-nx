#include "runtime/horizon_dispatcher.hpp"

namespace wgnx::sysmodule::runtime {

void HorizonDispatcher::Initialize(const HorizonDispatcherCallbacks &callbacks) {
    if (m_initialized) {
        return;
    }

    m_callbacks = callbacks;

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

void HorizonDispatcher::QueueTimerWork(wgnx::platform::work_struct *work) {
    if (m_timer_queue != nullptr && work != nullptr) {
        static_cast<void>(wgnx::platform::queue_work(m_timer_queue, work));
    }
}

} // namespace wgnx::sysmodule::runtime
