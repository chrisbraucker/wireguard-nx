#include "bsd_mitm_server.hpp"

#include "bsd_mitm_service.hpp"
#include "logger.hpp"

#include <stratosphere.hpp>

#include <atomic>
#include <cstddef>
#include <memory>

namespace wgnx::mitm {

namespace {

struct BsdMitmServerOptions {
    static constexpr std::size_t PointerBufferSize = 0x1000;
    static constexpr std::size_t MaxDomains = 8;
    static constexpr std::size_t MaxDomainObjects = 32;
    static constexpr bool CanDeferInvokeRequest = false;
    static constexpr bool CanManageMitmServers = true;
};

constexpr std::size_t MaximumSessions = 4;
constexpr std::size_t ServerThreadStackBytes = 32 * 1024;
constexpr std::size_t ObjectHeapBytes = 32 * 1024;

alignas(ams::os::MemoryPageSize) constinit std::byte g_object_heap[ObjectHeapBytes]{};
constinit ams::lmem::HeapHandle g_object_heap_handle = nullptr;
constinit ams::sf::ExpHeapMemoryResource g_object_memory_resource;
constinit ams::os::SdkMutex g_start_mutex;

class BsdMitmServerManager final : public ams::sf::hipc::ServerManager<1, BsdMitmServerOptions, MaximumSessions> {
  private:
    ams::Result OnNeedsToAccept(const int port_index, Server* server) override {
        AMS_ABORT_UNLESS(port_index == 0);

        std::shared_ptr<::Service> forward_service;
        ams::sm::MitmProcessInfo client_info{};
        server->AcknowledgeMitmSession(std::addressof(forward_service), std::addressof(client_info));
        logger::Log("bsd:s MITM acknowledge pid=%llu program_id=0x%016llX", static_cast<unsigned long long>(client_info.process_id.value),
                    static_cast<unsigned long long>(client_info.program_id.value));

        std::shared_ptr<::Service> local_forward = forward_service;
        auto service = ams::sf::CreateSharedObjectEmplaced<IBsdSystemService, BsdMitmService>(
            static_cast<ams::MemoryResource*>(std::addressof(g_object_memory_resource)), std::move(local_forward), client_info);
        R_RETURN(this->AcceptMitmImpl(server, std::move(service), std::move(forward_service)));
    }
};

constinit ams::util::TypedStorage<BsdMitmServerManager> g_server_manager_storage{};
constinit BsdMitmServerManager* g_server_manager = nullptr;
alignas(ams::os::ThreadStackAlignment) constinit std::byte g_server_thread_stack[ServerThreadStackBytes]{};
constinit ams::os::ThreadType g_server_thread{};
constinit std::atomic_bool g_server_running = false;
constinit bool g_server_thread_started = false;

void LogMitmState(const char* phase) {
    bool installed = false;
    const ams::Result rc = ams::sm::mitm::HasMitm(std::addressof(installed), ams::sm::ServiceName::Encode("bsd:s"));
    logger::Log("bsd:s MITM state phase=%s rc=0x%08X installed=%u", phase, rc.GetValue(), installed ? 1U : 0U);
}

void ServerThreadMain(void*) {
    logger::Log("bsd:s MITM server loop entered");
    g_server_manager->LoopProcess();
    logger::Log("bsd:s MITM server loop exited");
    g_server_running.store(false, std::memory_order_release);
}

} // namespace

bool StartBsdMitmServer() {
    std::scoped_lock lock(g_start_mutex);
    if (g_server_manager != nullptr) {
        return g_server_running.load(std::memory_order_acquire);
    }

    LogMitmState("before_register");
    g_object_heap_handle = ams::lmem::CreateExpHeap(g_object_heap, sizeof(g_object_heap), ams::lmem::CreateOption_ThreadSafe);
    if (g_object_heap_handle == nullptr) {
        logger::Log("bsd:s MITM object heap creation failed");
        return false;
    }
    g_object_memory_resource.Attach(g_object_heap_handle);

    g_server_manager = ams::util::ConstructAt(g_server_manager_storage);
    const ams::Result register_result = g_server_manager->RegisterMitmServer<BsdMitmService>(0, ams::sm::ServiceName::Encode("bsd:s"));
    if (R_FAILED(register_result)) {
        logger::Log("RegisterMitmServer(bsd:s) failed rc=0x%08X", register_result.GetValue());
        // The failed registration may mean another process owns bsd:s.
        // Do not attempt residual cleanup against an owner we cannot identify.
        g_server_manager = nullptr;
        return false;
    }
    LogMitmState("after_register");

    const ams::Result thread_result =
        ams::os::CreateThread(std::addressof(g_server_thread), ServerThreadMain, nullptr, g_server_thread_stack,
                              sizeof(g_server_thread_stack), ams::os::DefaultThreadPriority);
    if (R_FAILED(thread_result)) {
        logger::Log("CreateThread(wgnx-bsd-mitm) failed rc=0x%08X", thread_result.GetValue());
        return false;
    }
    ams::os::SetThreadNamePointer(std::addressof(g_server_thread), "wgnx-bsd-mitm");
    g_server_running.store(true, std::memory_order_release);
    ams::os::StartThread(std::addressof(g_server_thread));
    g_server_thread_started = true;
    logger::Log("bsd:s MITM registered requester-only server stack=%zu object_heap=%zu", ServerThreadStackBytes, ObjectHeapBytes);
    return true;
}

void StopBsdMitmServer() {
    std::scoped_lock lock(g_start_mutex);
    if (g_server_manager == nullptr) {
        logger::Log("bsd:s MITM shutdown skipped state=not_started");
        return;
    }

    logger::Log("bsd:s MITM shutdown requesting server-loop stop");
    g_server_manager->RequestStopProcessing();
    if (g_server_thread_started) {
        ams::os::WaitThread(std::addressof(g_server_thread));
        ams::os::DestroyThread(std::addressof(g_server_thread));
        g_server_thread_started = false;
        logger::Log("bsd:s MITM shutdown server thread joined");
    }

    // ServerManager owns the bsd:s install and uninstalls it while destroying its managed server.
    // No code below this point may issue UninstallMitm or ClearFutureMitm for bsd:s.
    LogMitmState("before_manager_destroy");
    logger::Log("bsd:s MITM shutdown destroying server manager");
    ams::util::DestroyAt(g_server_manager_storage);
    g_server_manager = nullptr;
    g_server_running.store(false, std::memory_order_release);

    if (g_object_heap_handle != nullptr) {
        ams::lmem::DestroyExpHeap(g_object_heap_handle);
        g_object_heap_handle = nullptr;
    }
    logger::Log("bsd:s MITM shutdown complete");
}

bool IsBsdMitmServerRunning() {
    return g_server_running.load(std::memory_order_acquire);
}

} // namespace wgnx::mitm
