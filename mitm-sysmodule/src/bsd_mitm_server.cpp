#include "bsd_mitm_server.hpp"

#include "bsd_mitm_service.hpp"
#include "logger.hpp"
#include "terminal_server_lifecycle.hpp"

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
constexpr ams::sm::ServiceName BsdServiceName = ams::sm::ServiceName::Encode("bsd:s");

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
// This becomes true only after this process successfully installs bsd:s.
// It prevents a failed registration from ever uninstalling another MITM owner.
constinit bool g_bsd_mitm_registration_owned = false;
constinit TerminalServerLifecycle g_server_lifecycle{};

void LogMitmState(const char* phase) {
    bool installed = false;
    const ams::Result rc = ams::sm::mitm::HasMitm(std::addressof(installed), BsdServiceName);
    logger::Log("bsd:s MITM state phase=%s rc=0x%08X installed=%u", phase, rc.GetValue(), installed ? 1U : 0U);
}

void UninstallOwnedBsdMitmRegistration() {
    if (!g_bsd_mitm_registration_owned) {
        logger::Log("bsd:s MITM shutdown uninstall skipped state=not_owner");
        return;
    }

    LogMitmState("before_unregister");
    const ams::Result uninstall_result = ams::sm::mitm::UninstallMitm(BsdServiceName);
    logger::Log("bsd:s MITM shutdown UninstallMitm rc=0x%08X", uninstall_result.GetValue());
    LogMitmState("after_unregister");

    // Retain the manager rather than invoking its destructor, which repeats this
    // operation through an opaque post-dispatch path that has aborted on-device.
    // An unsuccessful unregister remains visible in the diagnostic state above.
    if (R_SUCCEEDED(uninstall_result)) {
        g_bsd_mitm_registration_owned = false;
    }
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
    const ams::Result register_result = g_server_manager->RegisterMitmServer<BsdMitmService>(0, BsdServiceName);
    if (R_FAILED(register_result)) {
        logger::Log("RegisterMitmServer(bsd:s) failed rc=0x%08X", register_result.GetValue());
        // The failed registration may mean another process owns bsd:s.
        // Do not attempt residual cleanup against an owner we cannot identify.
        g_server_manager = nullptr;
        return false;
    }
    g_bsd_mitm_registration_owned = true;
    LogMitmState("after_register");

    const ams::Result thread_result =
        ams::os::CreateThread(std::addressof(g_server_thread), ServerThreadMain, nullptr, g_server_thread_stack,
                              sizeof(g_server_thread_stack), ams::os::DefaultThreadPriority);
    if (R_FAILED(thread_result)) {
        logger::Log("CreateThread(wgnx-bsd-mitm) failed rc=0x%08X", thread_result.GetValue());
        UninstallOwnedBsdMitmRegistration();
        // The manager cannot be safely destroyed after it has installed a MITM.
        // It remains terminally retained even though its server loop never started.
        g_server_manager = nullptr;
        return false;
    }
    ams::os::SetThreadNamePointer(std::addressof(g_server_thread), "wgnx-bsd-mitm");
    g_server_running.store(true, std::memory_order_release);
    AMS_ABORT_UNLESS(g_server_lifecycle.BeginServing());
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

    AMS_ABORT_UNLESS(g_server_lifecycle.BeginStopping());
    logger::Log("bsd:s MITM shutdown requesting server-loop stop");
    g_server_manager->RequestStopProcessing();
    if (g_server_thread_started) {
        ams::os::WaitThread(std::addressof(g_server_thread));
        ams::os::DestroyThread(std::addressof(g_server_thread));
        g_server_thread_started = false;
        AMS_ABORT_UNLESS(g_server_lifecycle.MarkServerThreadJoined());
        logger::Log("bsd:s MITM shutdown server thread joined");
    }

    // The manager destructor invokes UninstallMitm from a post-dispatch path that
    // has aborted on-device, so the manager itself must remain alive until exit.
    // SM does not reliably remove a retained MITM registration when this process
    // exits, so explicitly relinquish the registration after dispatch has stopped.
    UninstallOwnedBsdMitmRegistration();

    // Keep the manager and its object heap alive until process exit because active
    // session objects are allocated from that heap and remain manager-owned.
    // This module never declares a future MITM, so ClearFutureMitm is not needed.
    logger::Log("bsd:s MITM shutdown retaining terminal server manager and object heap for process exit");
    g_server_manager = nullptr;
    g_server_running.store(false, std::memory_order_release);
    AMS_ABORT_UNLESS(g_server_lifecycle.RetainForProcessExit());
}

bool IsBsdMitmServerRunning() {
    return g_server_running.load(std::memory_order_acquire);
}

} // namespace wgnx::mitm
