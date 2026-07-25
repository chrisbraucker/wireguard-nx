#pragma once

#include "wgnx/platform/network_path.hpp"
#include "wgnx/resource_budget.hpp"

#include <stratosphere.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace wgnx::sysmodule::platform::horizon {

class NetworkPathService {
  public:
    using ObservationCallback = void (*)(void* context, const wgnx::platform::network_path_observation& observation);

    NetworkPathService() = default;
    ~NetworkPathService();

    NetworkPathService(const NetworkPathService&) = delete;
    NetworkPathService& operator=(const NetworkPathService&) = delete;

    // This runs on the deep CMIF activation stack. Keep synchronous diagnostics
    // out of this path; request-state observations are emitted by the worker.
    [[nodiscard]] bool Start(std::uint32_t request_generation, ObservationCallback callback, void* callback_context);
    void Stop(std::uint32_t request_generation);

  private:
    static void ThreadMain(void* argument);
    void Run();
    void PublishCurrentObservation();

    // Raw libnx objects remain entirely in the Horizon implementation.
    alignas(16) std::array<std::byte, 96> m_request_storage{};
    mutable ams::os::Mutex m_mutex{false};
    ams::os::ThreadType m_thread{};
    ObservationCallback m_callback{nullptr};
    void* m_callback_context{nullptr};
    std::uint32_t m_request_generation{0};
    std::atomic<bool> m_stopping{false};
    bool m_request_open{false};
    bool m_thread_started{false};
    bool m_available{false};
    bool m_nifm_initialized{false};
};

} // namespace wgnx::sysmodule::platform::horizon
