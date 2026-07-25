#pragma once

#include <cstddef>
#include <cstdint>

namespace wgnx::platform {

using jiffies_t = std::uint64_t;

namespace impl {

constexpr inline std::size_t WorkStorageSize = 64;
constexpr inline std::size_t TimerStorageSize = 64;
constexpr inline std::size_t WorkStorageAlignment = 16;

} // namespace impl

struct work_struct {
    alignas(impl::WorkStorageAlignment) std::byte storage[impl::WorkStorageSize];
};

struct workqueue_struct;

using work_func_t = void (*)(work_struct* work);

enum class queue_work_result : std::uint8_t {
    queued = 0,
    rerun_queued,
    already_pending,
    capacity_exhausted,
    unavailable,
};

[[nodiscard]] constexpr queue_work_result classify_queue_work_request(bool available, bool already_pending, bool running,
                                                                      std::size_t pending, std::size_t capacity) {
    if (!available || capacity == 0) {
        return queue_work_result::unavailable;
    }
    if (already_pending) {
        return queue_work_result::already_pending;
    }
    if (pending >= capacity) {
        return queue_work_result::capacity_exhausted;
    }
    return running ? queue_work_result::rerun_queued : queue_work_result::queued;
}

struct workqueue_statistics {
    std::size_t capacity{0};
    std::size_t pending{0};
    std::size_t high_watermark{0};
    std::uint64_t requests{0};
    std::uint64_t enqueued{0};
    std::uint64_t rerun_queued{0};
    std::uint64_t coalesced{0};
    std::uint64_t rejected_capacity{0};
    std::uint64_t rejected_unavailable{0};
    std::uint64_t completed{0};
};

void INIT_WORK(work_struct* work, work_func_t func);
workqueue_struct* alloc_ordered_workqueue(const char* name, std::size_t pending_capacity);
void destroy_workqueue(workqueue_struct* wq);
[[nodiscard]] queue_work_result queue_work(workqueue_struct* wq, work_struct* work);
[[nodiscard]] workqueue_statistics get_workqueue_statistics(workqueue_struct* wq);
void flush_workqueue(workqueue_struct* wq);

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

using timer_func_t = void (*)(timer_list* timer);

jiffies_t get_jiffies_64();
void timer_setup(timer_list* timer, timer_func_t func);
bool mod_timer(timer_list* timer, jiffies_t expires);
bool timer_pending(const timer_list* timer);
void timer_delete(timer_list* timer);
void timer_delete_sync(timer_list* timer);

} // namespace wgnx::platform
