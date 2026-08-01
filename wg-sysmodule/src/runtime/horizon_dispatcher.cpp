#include "runtime/horizon_dispatcher.hpp"

#include "logger.hpp"
#include "wgnx/resource_budget.hpp"

namespace wgnx::sysmodule::runtime {

void HorizonDispatcher::Initialize(const HorizonDispatcherCallbacks& callbacks) {
    if (m_initialized) {
        return;
    }

    m_callbacks = callbacks;

    m_resolve_queue = wgnx::platform::alloc_ordered_workqueue("wgnx-resolve", wgnx::resource_budget::ResolveWorkSlots);
    m_submission_queue = wgnx::platform::alloc_ordered_workqueue("wgnx-submit", wgnx::resource_budget::SubmissionWorkSlots);
    m_transmit_queue = wgnx::platform::alloc_ordered_workqueue("wgnx-tx", wgnx::resource_budget::TransmitWorkSlots);
    m_receive_queue = wgnx::platform::alloc_ordered_workqueue("wgnx-recv", wgnx::resource_budget::ReceiveWorkSlots);
    m_timer_queue = wgnx::platform::alloc_ordered_workqueue("wgnx-timer-act", wgnx::resource_budget::TimerWorkSlots);
    AMS_ABORT_UNLESS(m_resolve_queue != nullptr);
    AMS_ABORT_UNLESS(m_submission_queue != nullptr);
    AMS_ABORT_UNLESS(m_transmit_queue != nullptr);
    AMS_ABORT_UNLESS(m_receive_queue != nullptr);
    AMS_ABORT_UNLESS(m_timer_queue != nullptr);

    wgnx::platform::INIT_WORK(&m_resolve_work, m_callbacks.resolve);
    wgnx::platform::INIT_WORK(&m_debug_submission_work, m_callbacks.submit_debug_payload);
    wgnx::platform::INIT_WORK(&m_inner_submission_work, m_callbacks.submit_inner_packet);
    wgnx::platform::INIT_WORK(&m_transmit_work, m_callbacks.transmit_datagram);
    wgnx::platform::INIT_WORK(&m_receive_work, m_callbacks.receive);
    m_initialized = true;
}

wgnx::platform::queue_work_result HorizonDispatcher::Queue(
    wgnx::platform::workqueue_struct* queue, wgnx::platform::work_struct* work, const char* name
) {
    const auto result = wgnx::platform::queue_work(queue, work);
    if (result != wgnx::platform::queue_work_result::capacity_exhausted && result != wgnx::platform::queue_work_result::unavailable) {
        return result;
    }

    const auto statistics = wgnx::platform::get_workqueue_statistics(queue);
    logger::Log(
        "Rejected runtime work lane=%s result=%u pending=%zu capacity=%zu high_water=%zu rejected_capacity=%llu rejected_unavailable=%llu",
        name,
        static_cast<unsigned int>(result),
        statistics.pending,
        statistics.capacity,
        statistics.high_watermark,
        static_cast<unsigned long long>(statistics.rejected_capacity),
        static_cast<unsigned long long>(statistics.rejected_unavailable)
    );
    return result;
}

void HorizonDispatcher::QueueResolve() {
    if (m_resolve_queue != nullptr) {
        static_cast<void>(Queue(m_resolve_queue, &m_resolve_work, "resolve"));
    }
}

void HorizonDispatcher::QueueDebugPayloadSubmission() {
    if (m_submission_queue != nullptr) {
        static_cast<void>(Queue(m_submission_queue, &m_debug_submission_work, "submission"));
    }
}

void HorizonDispatcher::QueueInnerPacketSubmission() {
    if (m_submission_queue != nullptr) {
        static_cast<void>(Queue(m_submission_queue, &m_inner_submission_work, "submission"));
    }
}

void HorizonDispatcher::QueuePendingDatagramTransmit() {
    if (m_transmit_queue != nullptr) {
        const auto result = Queue(m_transmit_queue, &m_transmit_work, "transmit");
        AMS_ABORT_UNLESS(
            result != wgnx::platform::queue_work_result::capacity_exhausted && result != wgnx::platform::queue_work_result::unavailable
        );
    }
}

void HorizonDispatcher::QueueReceive() {
    if (m_receive_queue != nullptr) {
        static_cast<void>(Queue(m_receive_queue, &m_receive_work, "receive"));
    }
}

void HorizonDispatcher::QueueTimerWork(wgnx::platform::work_struct* work) {
    if (m_timer_queue != nullptr && work != nullptr) {
        static_cast<void>(Queue(m_timer_queue, work, "timer"));
    }
}

wgnx::platform::workqueue_struct* HorizonDispatcher::QueueForLane(DispatcherWorkLane lane) const {
    switch (lane) {
    case DispatcherWorkLane::Resolve:
        return m_resolve_queue;
    case DispatcherWorkLane::Submission:
        return m_submission_queue;
    case DispatcherWorkLane::Transmit:
        return m_transmit_queue;
    case DispatcherWorkLane::Receive:
        return m_receive_queue;
    case DispatcherWorkLane::Timer:
        return m_timer_queue;
    }
    return nullptr;
}

wgnx::platform::workqueue_statistics HorizonDispatcher::Statistics(DispatcherWorkLane lane) const {
    return wgnx::platform::get_workqueue_statistics(QueueForLane(lane));
}

} // namespace wgnx::sysmodule::runtime
