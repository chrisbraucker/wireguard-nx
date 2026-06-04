#include "wgnx/platform/sync.hpp"

#include <new>
#include <utility>

#include <stratosphere.hpp>

namespace wgnx::platform {

namespace {

template<typename Impl, typename Wrapper>
Impl *GetImpl(Wrapper *wrapper) {
    return std::launder(reinterpret_cast<Impl *>(wrapper->storage));
}

template<typename Impl, typename Wrapper>
const Impl *GetImpl(const Wrapper *wrapper) {
    return std::launder(reinterpret_cast<const Impl *>(wrapper->storage));
}

static_assert(sizeof(ams::os::Mutex) <= sizeof(mutex));
static_assert(alignof(ams::os::Mutex) <= alignof(mutex));

static_assert(sizeof(ams::os::BusyMutex) <= sizeof(spinlock_t));
static_assert(alignof(ams::os::BusyMutex) <= alignof(spinlock_t));

static_assert(sizeof(ams::os::ReaderWriterBusyMutex) <= sizeof(rw_semaphore));
static_assert(alignof(ams::os::ReaderWriterBusyMutex) <= alignof(rw_semaphore));

} // namespace

void mutex_init(mutex *lock) {
    new (lock->storage) ams::os::Mutex(false);
}

void mutex_lock(mutex *lock) {
    GetImpl<ams::os::Mutex>(lock)->lock();
}

bool mutex_trylock(mutex *lock) {
    return GetImpl<ams::os::Mutex>(lock)->try_lock();
}

void mutex_unlock(mutex *lock) {
    GetImpl<ams::os::Mutex>(lock)->unlock();
}

void spin_lock_init(spinlock_t *lock) {
    new (lock->storage) ams::os::BusyMutex();
}

void spin_lock(spinlock_t *lock) {
    GetImpl<ams::os::BusyMutex>(lock)->lock();
}

bool spin_trylock(spinlock_t *lock) {
    return GetImpl<ams::os::BusyMutex>(lock)->try_lock();
}

void spin_unlock(spinlock_t *lock) {
    GetImpl<ams::os::BusyMutex>(lock)->unlock();
}

void init_rwsem(rw_semaphore *lock) {
    new (lock->storage) ams::os::ReaderWriterBusyMutex();
}

void down_read(rw_semaphore *lock) {
    GetImpl<ams::os::ReaderWriterBusyMutex>(lock)->AcquireReadLock();
}

void up_read(rw_semaphore *lock) {
    GetImpl<ams::os::ReaderWriterBusyMutex>(lock)->ReleaseReadLock();
}

void down_write(rw_semaphore *lock) {
    GetImpl<ams::os::ReaderWriterBusyMutex>(lock)->AcquireWriteLock();
}

void up_write(rw_semaphore *lock) {
    GetImpl<ams::os::ReaderWriterBusyMutex>(lock)->ReleaseWriteLock();
}

} // namespace wgnx::platform
