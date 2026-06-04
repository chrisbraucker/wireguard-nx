#pragma once

#include <cstddef>
#include <cstdint>

namespace wgnx::platform {

namespace impl {

constexpr inline std::size_t LockStorageSize = 128;
constexpr inline std::size_t LockStorageAlignment = 16;

}

/*
 * Deviation from Linux:
 * These lock wrappers use opaque fixed-size storage so that `common` stays
 * free of Horizon/Atmosphere headers. The implication is that these objects
 * are larger and less transparent than upstream kernel lock structs, but they
 * can still be embedded directly in future engine-facing types.
 */
struct mutex {
    alignas(impl::LockStorageAlignment) std::byte storage[impl::LockStorageSize];
};

/*
 * Deviation from Linux:
 * `spinlock_t` is process-context mutual exclusion only. It does not disable
 * interrupts or model softirq/preemption semantics, because those execution
 * contexts do not exist in the same form in this sysmodule environment.
 */
struct spinlock_t {
    alignas(impl::LockStorageAlignment) std::byte storage[impl::LockStorageSize];
};

/*
 * Deviation from Linux:
 * `rw_semaphore` maps to a reader/writer mutex. The interface shape matches
 * upstream call sites, but fairness and wakeup behavior are whatever the
 * Atmosphere lock implementation provides.
 */
struct rw_semaphore {
    alignas(impl::LockStorageAlignment) std::byte storage[impl::LockStorageSize];
};

void mutex_init(mutex *lock);
void mutex_lock(mutex *lock);
bool mutex_trylock(mutex *lock);
void mutex_unlock(mutex *lock);

void spin_lock_init(spinlock_t *lock);
void spin_lock(spinlock_t *lock);
bool spin_trylock(spinlock_t *lock);
void spin_unlock(spinlock_t *lock);

void init_rwsem(rw_semaphore *lock);
void down_read(rw_semaphore *lock);
void up_read(rw_semaphore *lock);
void down_write(rw_semaphore *lock);
void up_write(rw_semaphore *lock);

} // namespace wgnx::platform
