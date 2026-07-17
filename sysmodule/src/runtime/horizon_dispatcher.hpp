#pragma once

#include <stratosphere.hpp>

#include "wgnx/platform/work.hpp"
namespace wgnx::sysmodule::runtime {

struct HorizonDispatcherCallbacks {
    wgnx::platform::work_func_t resolve{nullptr};
    wgnx::platform::work_func_t submit_debug_payload{nullptr};
    wgnx::platform::work_func_t submit_inner_packet{nullptr};
    wgnx::platform::work_func_t receive{nullptr};
};

class HorizonDispatcher {
public:
    void Initialize(const HorizonDispatcherCallbacks &callbacks);

    void QueueResolve();
    void QueueDebugPayloadSubmission();
    void QueueInnerPacketSubmission();
    void QueueReceive();
    void QueueTimerWork(wgnx::platform::work_struct *work);

private:
    HorizonDispatcherCallbacks m_callbacks{};
    wgnx::platform::workqueue_struct *m_resolve_queue{nullptr};
    wgnx::platform::workqueue_struct *m_submission_queue{nullptr};
    wgnx::platform::workqueue_struct *m_receive_queue{nullptr};
    wgnx::platform::workqueue_struct *m_timer_queue{nullptr};
    wgnx::platform::work_struct m_resolve_work{};
    wgnx::platform::work_struct m_debug_submission_work{};
    wgnx::platform::work_struct m_inner_submission_work{};
    wgnx::platform::work_struct m_receive_work{};
    bool m_initialized{false};
};

} // namespace wgnx::sysmodule::runtime
