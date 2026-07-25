#include "platform/horizon/network_path_service.hpp"

#include <switch/kernel/event.h>
#include <switch/services/nifm.h>

#include <limits>
#include <memory>
#include <cstring>

namespace wgnx::sysmodule::platform::horizon {

namespace {

alignas(
    ams::os::ThreadStackAlignment) constinit std::array<std::byte, wgnx::resource_budget::NifmPathThreadStackBytes> g_network_path_stack{};

NifmRequest* Request(std::array<std::byte, 96>& storage) {
    static_assert(sizeof(NifmRequest) <= 96);
    static_assert(alignof(NifmRequest) <= 16);
    return std::launder(reinterpret_cast<NifmRequest*>(storage.data()));
}

constexpr std::uint32_t SystemRequestRequirementPreset = 0x0B;
constexpr std::uint8_t PersistentRequestEnabled = 1;

Result SetRequestRequirementPreset(NifmRequest* request, std::uint32_t preset) {
    serviceAssumeDomain(std::addressof(request->s));
    return serviceDispatchIn(std::addressof(request->s), 6, preset);
}

Result SetRequestPersistent(NifmRequest* request) {
    // `nim` uses IRequest command 12 to preserve an internet request across
    // transient application state changes. libnx does not expose this command,
    // so keep its one-byte bool ABI explicit at this Horizon-only boundary.
    serviceAssumeDomain(std::addressof(request->s));
    return serviceDispatchIn(std::addressof(request->s), 12, PersistentRequestEnabled);
}

Result GetRequestStateDirect(NifmRequest* request, NifmRequestState* out_state) {
    // libnx's public getter first probes the autoclear state event. The worker
    // below already consumed that event, so using the getter here would return
    // its cached state instead of refreshing it through IRequest command 0.
    serviceAssumeDomain(std::addressof(request->s));
    return serviceDispatchOut(std::addressof(request->s), 0, *out_state);
}

Result GetRequestResultDirect(NifmRequest* request) {
    serviceAssumeDomain(std::addressof(request->s));
    return serviceDispatch(std::addressof(request->s), 1);
}

wgnx::platform::network_path_raw_state MapRawState(NifmRequestState state) {
    switch (state) {
    case NifmRequestState_Invalid:
        return wgnx::platform::network_path_raw_state::invalid;
    case NifmRequestState_Unknown1:
        return wgnx::platform::network_path_raw_state::pending;
    case NifmRequestState_OnHold:
        return wgnx::platform::network_path_raw_state::on_hold;
    case NifmRequestState_Available:
        return wgnx::platform::network_path_raw_state::available;
    case NifmRequestState_Unknown4:
        return wgnx::platform::network_path_raw_state::unknown4;
    case NifmRequestState_Unknown5:
        return wgnx::platform::network_path_raw_state::unknown5;
    }
    return wgnx::platform::network_path_raw_state::invalid;
}

} // namespace

NetworkPathService::~NetworkPathService() {
    Stop(m_request_generation);
}

bool NetworkPathService::Start(std::uint32_t request_generation, ObservationCallback callback, void* callback_context) {
    if (request_generation == 0 || callback == nullptr) {
        return false;
    }

    Stop(m_request_generation);
    std::scoped_lock lock(m_mutex);
    if (R_FAILED(nifmInitialize(NifmServiceType_System))) {
        return false;
    }
    m_nifm_initialized = true;

    NifmRequest zeroed_request{};
    std::memcpy(m_request_storage.data(), std::addressof(zeroed_request), sizeof(zeroed_request));
    auto* request = Request(m_request_storage);
    if (R_FAILED(nifmCreateRequest(request, true))) {
        nifmExit();
        m_nifm_initialized = false;
        return false;
    }
    const Result requirement_result = SetRequestRequirementPreset(request, SystemRequestRequirementPreset);
    if (R_FAILED(requirement_result)) {
        nifmRequestClose(request);
        nifmExit();
        m_nifm_initialized = false;
        return false;
    }
    if (R_FAILED(SetRequestPersistent(request))) {
        nifmRequestClose(request);
        nifmExit();
        m_nifm_initialized = false;
        return false;
    }
    if (R_FAILED(nifmRequestSubmit(request))) {
        nifmRequestClose(request);
        nifmExit();
        m_nifm_initialized = false;
        return false;
    }

    m_callback = callback;
    m_callback_context = callback_context;
    m_request_generation = request_generation;
    m_available = false;
    m_stopping.store(false, std::memory_order_release);
    m_request_open = true;
    R_ABORT_UNLESS(ams::os::CreateThread(std::addressof(m_thread), ThreadMain, this, g_network_path_stack.data(),
                                         g_network_path_stack.size(), ams::os::DefaultThreadPriority));
    ams::os::SetThreadNamePointer(std::addressof(m_thread), "wgnx-nifm");
    ams::os::StartThread(std::addressof(m_thread));
    m_thread_started = true;
    return true;
}

void NetworkPathService::Stop(std::uint32_t request_generation) {
    {
        std::scoped_lock lock(m_mutex);
        if (!m_request_open || request_generation == 0 || request_generation != m_request_generation) {
            return;
        }
        m_stopping.store(true, std::memory_order_release);
        static_cast<void>(nifmRequestCancel(Request(m_request_storage)));
    }

    if (m_thread_started) {
        ams::os::WaitThread(std::addressof(m_thread));
        ams::os::DestroyThread(std::addressof(m_thread));
    }

    std::scoped_lock lock(m_mutex);
    if (!m_request_open || request_generation != m_request_generation) {
        return;
    }
    auto* request = Request(m_request_storage);
    nifmRequestClose(request);
    m_request_open = false;
    m_thread_started = false;
    m_available = false;
    m_callback = nullptr;
    m_callback_context = nullptr;
    if (m_nifm_initialized) {
        nifmExit();
        m_nifm_initialized = false;
    }
}

void NetworkPathService::ThreadMain(void* argument) {
    static_cast<NetworkPathService*>(argument)->Run();
}

void NetworkPathService::Run() {
    PublishCurrentObservation();
    while (!m_stopping.load(std::memory_order_acquire)) {
        Event* event = nullptr;
        {
            std::scoped_lock lock(m_mutex);
            if (!m_request_open) {
                return;
            }
            event = std::addressof(Request(m_request_storage)->event_request_state);
        }
        const Result wait_result = eventWait(event, std::numeric_limits<u64>::max());
        if (m_stopping.load(std::memory_order_acquire)) {
            return;
        }
        if (R_SUCCEEDED(wait_result)) {
            PublishCurrentObservation();
            continue;
        }

        // An invalidated request event must not turn the dedicated worker into
        // a hot loop. The next activation creates a fresh request.
        return;
    }
}

void NetworkPathService::PublishCurrentObservation() {
    wgnx::platform::network_path_observation observation{};
    ObservationCallback callback = nullptr;
    void* callback_context = nullptr;
    {
        std::scoped_lock lock(m_mutex);
        if (!m_request_open || m_stopping.load(std::memory_order_acquire)) {
            return;
        }
        NifmRequestState state{};
        const Result state_result = GetRequestStateDirect(Request(m_request_storage), std::addressof(state));
        observation.raw_state = MapRawState(state);
        observation.state_result = state_result;
        observation.operation_result = R_SUCCEEDED(state_result) ? GetRequestResultDirect(Request(m_request_storage)) : state_result;
        observation.request_generation = m_request_generation;
        observation.availability = wgnx::platform::classify_network_path_state(observation.raw_state, observation.state_result);
        m_available = observation.availability == wgnx::platform::network_path_availability::available;
        callback = m_callback;
        callback_context = m_callback_context;
    }
    if (callback != nullptr) {
        callback(callback_context, observation);
    }
}

} // namespace wgnx::sysmodule::platform::horizon
