#pragma once

#include <stratosphere.hpp>

#include "wgnx/platform/work.hpp"
#include "wgnx/resource_budget.hpp"

namespace wgnx::sysmodule::runtime {

struct HorizonDispatcherCallbacks {
    wgnx::platform::work_func_t resolve{nullptr};
    wgnx::platform::work_func_t submit_debug_payload{nullptr};
    wgnx::platform::work_func_t submit_inner_packet{nullptr};
    wgnx::platform::work_func_t transmit_datagram{nullptr};
    wgnx::platform::work_func_t receive{nullptr};
};

enum class DispatcherWorkLane : std::uint8_t {
    Resolve = 0,
    Submission,
    Transmit,
    Receive,
    Timer,
};

class HorizonDispatcher {
  public:
    void Initialize(const HorizonDispatcherCallbacks& callbacks);

    void QueueResolve();
    void QueueDebugPayloadSubmission();
    void QueueInnerPacketSubmission();
    void QueuePendingDatagramTransmit();
    void QueueReceive();
    void QueueTimerWork(wgnx::platform::work_struct* work);
    [[nodiscard]] wgnx::platform::workqueue_statistics Statistics(DispatcherWorkLane lane) const;

  private:
    [[nodiscard]] wgnx::platform::queue_work_result Queue(wgnx::platform::workqueue_struct* queue, wgnx::platform::work_struct* work,
                                                          const char* name);
    wgnx::platform::workqueue_struct* QueueForLane(DispatcherWorkLane lane) const;

    HorizonDispatcherCallbacks m_callbacks{};
    wgnx::platform::workqueue_struct* m_resolve_queue{nullptr};
    wgnx::platform::workqueue_struct* m_submission_queue{nullptr};
    wgnx::platform::workqueue_struct* m_transmit_queue{nullptr};
    wgnx::platform::workqueue_struct* m_receive_queue{nullptr};
    wgnx::platform::workqueue_struct* m_timer_queue{nullptr};
    wgnx::platform::work_struct m_resolve_work{};
    wgnx::platform::work_struct m_debug_submission_work{};
    wgnx::platform::work_struct m_inner_submission_work{};
    wgnx::platform::work_struct m_transmit_work{};
    wgnx::platform::work_struct m_receive_work{};
    bool m_initialized{false};
};

static_assert(sizeof(HorizonDispatcher) <= wgnx::resource_budget::MaximumHorizonDispatcherBytes);

} // namespace wgnx::sysmodule::runtime
