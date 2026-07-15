#pragma once

#include <cstddef>
#include <cstdint>

namespace wgnx::platform {

using jiffies_t = std::uint64_t;

namespace impl {

constexpr inline std::size_t WorkStorageSize = 64;
constexpr inline std::size_t TimerStorageSize = 64;
constexpr inline std::size_t WorkStorageAlignment = 16;

}

struct work_struct {
    alignas(impl::WorkStorageAlignment) std::byte storage[impl::WorkStorageSize];
};

struct workqueue_struct;

using work_func_t = void (*)(work_struct *work);

void INIT_WORK(work_struct *work, work_func_t func);
workqueue_struct *alloc_ordered_workqueue(const char *name);
void destroy_workqueue(workqueue_struct *wq);
bool queue_work(workqueue_struct *wq, work_struct *work);
void flush_workqueue(workqueue_struct *wq);

/*
 * Deviation from Linux:
 * `HZ` is fixed at 1000 so one jiffy equals one millisecond. The implication
 * is that timer math stays simple and deterministic in userspace-like process
 * context, but it does not preserve a configurable kernel tick rate.
 */
constexpr inline std::uint32_t HZ = 1000;

struct timer_list {
    alignas(impl::WorkStorageAlignment) std::byte storage[impl::TimerStorageSize];
};

using timer_func_t = void (*)(timer_list *timer);

jiffies_t get_jiffies_64();
void timer_setup(timer_list *timer, timer_func_t func);
bool mod_timer(timer_list *timer, jiffies_t expires);
bool timer_pending(const timer_list *timer);
void timer_delete(timer_list *timer);
void timer_delete_sync(timer_list *timer);

} // namespace wgnx::platform
