#include "wgnx/platform/work.hpp"

#include "wgnx/platform/clock.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <new>
#include <utility>

#include <stratosphere.hpp>

namespace wgnx::platform {

constexpr inline std::size_t WorkqueueThreadStackSize = 16 * 1024;
constexpr inline std::size_t TimerThreadStackSize = 16 * 1024;
constexpr inline s32 WorkerThreadPriority = ams::os::DefaultThreadPriority;
constexpr inline std::size_t WorkqueueNameSize = 32;
constexpr inline ktime_t NSEC_PER_JIFFY = NSEC_PER_SEC / HZ;
constexpr inline std::size_t MaxOrderedWorkqueues = 4;

struct WorkqueueSlot;
struct workqueue_struct;

struct WorkInternal {
    work_func_t func{nullptr};
    WorkInternal *next{nullptr};
    workqueue_struct *owner{nullptr};
    bool queued{false};
    bool running{false};
    bool rerun{false};
};

struct workqueue_struct {
    ams::os::Mutex mutex{false};
    ams::os::ConditionVariable cv{};
    WorkInternal *head{nullptr};
    WorkInternal *tail{nullptr};
    std::size_t active_count{0};
    bool stopping{false};
    void *stack{nullptr};
    std::size_t stack_size{0};
    WorkqueueSlot *slot{nullptr};
    ams::os::ThreadType thread{};
    char name[WorkqueueNameSize]{};
};

struct WorkqueueSlot {
    alignas(workqueue_struct) std::byte storage[sizeof(workqueue_struct)];
    alignas(ams::os::ThreadStackAlignment) std::byte stack[WorkqueueThreadStackSize];
    bool in_use{false};
};

struct TimerInternal {
    timer_func_t func{nullptr};
    TimerInternal *next{nullptr};
    jiffies_t expires{0};
    bool armed{false};
    bool running{false};
};

struct TimerManager {
    ams::os::Mutex mutex{false};
    ams::os::ConditionVariable cv{};
    TimerInternal *head{nullptr};
    bool stopping{false};
    bool started{false};
    alignas(ams::os::ThreadStackAlignment) std::byte stack[TimerThreadStackSize]{};
    ams::os::ThreadType thread{};
};

namespace {

constinit TimerManager g_timer_manager = {};
ams::os::Mutex g_workqueue_pool_mutex(false);
constinit WorkqueueSlot g_workqueue_slots[MaxOrderedWorkqueues] = {};

static_assert(sizeof(WorkInternal) <= sizeof(work_struct));
static_assert(alignof(WorkInternal) <= alignof(work_struct));

static_assert(sizeof(TimerInternal) <= sizeof(timer_list));
static_assert(alignof(TimerInternal) <= alignof(timer_list));

template<typename Impl, typename Public>
Impl *GetImpl(Public *object) {
    return std::launder(reinterpret_cast<Impl *>(object->storage));
}

template<typename Impl, typename Public>
const Impl *GetImpl(const Public *object) {
    return std::launder(reinterpret_cast<const Impl *>(object->storage));
}

void EnqueueWorkLocked(workqueue_struct *wq, WorkInternal *work) {
    work->next = nullptr;
    if (wq->tail != nullptr) {
        wq->tail->next = work;
    } else {
        wq->head = work;
    }
    wq->tail = work;
    work->queued = true;
    work->owner = wq;
}

WorkInternal *DequeueWorkLocked(workqueue_struct *wq) {
    WorkInternal *work = wq->head;
    if (work == nullptr) {
        return nullptr;
    }

    wq->head = work->next;
    if (wq->head == nullptr) {
        wq->tail = nullptr;
    }

    work->next = nullptr;
    work->queued = false;
    work->running = true;
    ++wq->active_count;
    return work;
}

void WorkqueueThreadMain(void *argument) {
    auto *wq = static_cast<workqueue_struct *>(argument);
    while (true) {
        wq->mutex.lock();
        while (!wq->stopping && wq->head == nullptr) {
            wq->cv.Wait(*wq->mutex.GetBase());
        }

        if (wq->stopping && wq->head == nullptr) {
            wq->mutex.unlock();
            break;
        }

        WorkInternal *work = DequeueWorkLocked(wq);
        wq->mutex.unlock();
        if (work == nullptr) {
            continue;
        }

        work->func(reinterpret_cast<work_struct *>(work));

        wq->mutex.lock();
        work->running = false;
        --wq->active_count;
        if (work->rerun && !wq->stopping) {
            work->rerun = false;
            EnqueueWorkLocked(wq, work);
            wq->cv.Signal();
        }
        wq->cv.Broadcast();
        wq->mutex.unlock();
    }
}

void RemoveTimerLocked(TimerInternal *timer) {
    TimerInternal **current = std::addressof(g_timer_manager.head);
    while (*current != nullptr) {
        if (*current == timer) {
            *current = timer->next;
            timer->next = nullptr;
            return;
        }
        current = std::addressof((*current)->next);
    }
}

void InsertTimerLocked(TimerInternal *timer) {
    TimerInternal **current = std::addressof(g_timer_manager.head);
    while (*current != nullptr && (*current)->expires <= timer->expires) {
        current = std::addressof((*current)->next);
    }

    timer->next = *current;
    *current = timer;
}

void TimerThreadMain(void *) {
    while (true) {
        g_timer_manager.mutex.lock();
        while (!g_timer_manager.stopping && g_timer_manager.head == nullptr) {
            g_timer_manager.cv.Wait(*g_timer_manager.mutex.GetBase());
        }

        if (g_timer_manager.stopping && g_timer_manager.head == nullptr) {
            g_timer_manager.mutex.unlock();
            break;
        }

        const jiffies_t now = get_jiffies_64();
        TimerInternal *timer = g_timer_manager.head;
        if (timer != nullptr && timer->expires > now) {
            const jiffies_t wait_jiffies = timer->expires - now;
            const auto timeout = ams::TimeSpan::FromMilliSeconds(static_cast<s64>(wait_jiffies));
            g_timer_manager.cv.TimedWait(*g_timer_manager.mutex.GetBase(), timeout);
            g_timer_manager.mutex.unlock();
            continue;
        }

        if (timer == nullptr) {
            g_timer_manager.mutex.unlock();
            continue;
        }

        g_timer_manager.head = timer->next;
        timer->next = nullptr;
        timer->armed = false;
        timer->running = true;
        g_timer_manager.mutex.unlock();

        timer->func(reinterpret_cast<timer_list *>(timer));

        g_timer_manager.mutex.lock();
        timer->running = false;
        g_timer_manager.cv.Broadcast();
        g_timer_manager.mutex.unlock();
    }
}

void EnsureTimerManagerStarted() {
    g_timer_manager.mutex.lock();
    if (g_timer_manager.started) {
        g_timer_manager.mutex.unlock();
        return;
    }

    R_ABORT_UNLESS(ams::os::CreateThread(
        std::addressof(g_timer_manager.thread),
        TimerThreadMain,
        nullptr,
        g_timer_manager.stack,
        sizeof(g_timer_manager.stack),
        WorkerThreadPriority));
    ams::os::SetThreadNamePointer(std::addressof(g_timer_manager.thread), "wgnx-timer");
    ams::os::StartThread(std::addressof(g_timer_manager.thread));
    g_timer_manager.started = true;
    g_timer_manager.mutex.unlock();
}

} // namespace

void INIT_WORK(work_struct *work, work_func_t func) {
    auto *impl = GetImpl<WorkInternal>(work);
    *impl = {};
    impl->func = func;
}

workqueue_struct *alloc_ordered_workqueue(const char *name) {
    WorkqueueSlot *slot = nullptr;
    {
        std::scoped_lock lock(g_workqueue_pool_mutex);
        for (auto &candidate : g_workqueue_slots) {
            if (!candidate.in_use) {
                candidate.in_use = true;
                slot = std::addressof(candidate);
                break;
            }
        }
    }

    if (slot == nullptr) {
        return nullptr;
    }

    auto *wq = new (slot->storage) workqueue_struct();
    wq->stack = slot->stack;
    wq->stack_size = WorkqueueThreadStackSize;
    wq->slot = slot;

    if (name != nullptr) {
        std::snprintf(wq->name, sizeof(wq->name), "%s", name);
    }

    /*
     * Deviation from Linux:
     * This implementation always creates a single ordered worker thread. There
     * is no support for workqueue flags, per-cpu queues, or parallel workers.
     * The implication is that call sites map cleanly to ordered queue usage,
     * but high-concurrency kernel workqueue behavior is intentionally absent.
     *
     * Deviation from Linux:
     * Workqueues are allocated from a fixed static pool with preallocated
     * thread stacks instead of dynamic stack allocation. The implication is
     * that creation is more predictable on Horizon, but the number of queues is
     * capped by `MaxOrderedWorkqueues`.
     */
    const ams::Result create_rc = ams::os::CreateThread(
        std::addressof(wq->thread),
        WorkqueueThreadMain,
        wq,
        wq->stack,
        wq->stack_size,
        WorkerThreadPriority);
    if (R_FAILED(create_rc)) {
        wq->~workqueue_struct();
        std::scoped_lock lock(g_workqueue_pool_mutex);
        slot->in_use = false;
        return nullptr;
    }

    ams::os::SetThreadNamePointer(std::addressof(wq->thread), wq->name[0] != '\0' ? wq->name : "wgnx-work");
    ams::os::StartThread(std::addressof(wq->thread));
    return wq;
}

void destroy_workqueue(workqueue_struct *wq) {
    if (wq == nullptr) {
        return;
    }

    flush_workqueue(wq);
    wq->mutex.lock();
    wq->stopping = true;
    wq->cv.Broadcast();
    wq->mutex.unlock();
    ams::os::WaitThread(std::addressof(wq->thread));
    ams::os::DestroyThread(std::addressof(wq->thread));
    WorkqueueSlot *slot = wq->slot;
    wq->~workqueue_struct();
    if (slot != nullptr) {
        std::scoped_lock lock(g_workqueue_pool_mutex);
        slot->in_use = false;
    }
}

bool queue_work(workqueue_struct *wq, work_struct *work) {
    if (wq == nullptr || work == nullptr) {
        return false;
    }

    auto *impl = GetImpl<WorkInternal>(work);
    wq->mutex.lock();

    bool queued = false;
    if (impl->queued || impl->rerun) {
        queued = false;
    } else if (impl->running) {
        impl->rerun = true;
        queued = true;
    } else {
        EnqueueWorkLocked(wq, impl);
        queued = true;
        wq->cv.Signal();
    }

    wq->mutex.unlock();
    return queued;
}

void flush_workqueue(workqueue_struct *wq) {
    if (wq == nullptr) {
        return;
    }

    wq->mutex.lock();
    while (wq->head != nullptr || wq->active_count != 0) {
        wq->cv.Wait(*wq->mutex.GetBase());
    }
    wq->mutex.unlock();
}

jiffies_t get_jiffies_64() {
    return static_cast<jiffies_t>(std::max<ktime_t>(0, ktime_get_coarse_boottime_ns() / NSEC_PER_JIFFY));
}

void timer_setup(timer_list *timer, timer_func_t func) {
    auto *impl = GetImpl<TimerInternal>(timer);
    *impl = {};
    impl->func = func;
}

bool mod_timer(timer_list *timer, jiffies_t expires) {
    if (timer == nullptr) {
        return false;
    }

    EnsureTimerManagerStarted();

    auto *impl = GetImpl<TimerInternal>(timer);
    g_timer_manager.mutex.lock();
    const bool was_pending = impl->armed;
    if (impl->armed) {
        RemoveTimerLocked(impl);
    }

    impl->expires = expires;
    impl->armed = true;
    InsertTimerLocked(impl);
    g_timer_manager.cv.Broadcast();
    g_timer_manager.mutex.unlock();
    return was_pending;
}

bool timer_pending(const timer_list *timer) {
    if (timer == nullptr) {
        return false;
    }

    return GetImpl<TimerInternal>(timer)->armed;
}

void timer_delete(timer_list *timer) {
    if (timer == nullptr) {
        return;
    }

    /*
     * Deviation from Linux:
     * `timer_delete` only disarms the timer and does not synchronize with an
     * in-flight callback. The implication is that future call sites that need
     * strict callback completion guarantees must use a stronger primitive.
     */
    auto *impl = GetImpl<TimerInternal>(timer);
    g_timer_manager.mutex.lock();
    if (impl->armed) {
        RemoveTimerLocked(impl);
        impl->armed = false;
    }
    g_timer_manager.cv.Broadcast();
    g_timer_manager.mutex.unlock();
}

} // namespace wgnx::platform
