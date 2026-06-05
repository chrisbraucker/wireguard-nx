#include <stratosphere.hpp>
#include <switch.h>

#include "ipc_service.hpp"
#include "logger.hpp"
#include "wireguard/debug_harness.hpp"

namespace ams {
    void Main()
    {
        wgnx::sysmodule::logger::Initialize();
        wgnx::sysmodule::logger::Log("Main entered");
        static_cast<void>(wgnx::wireguard::RunMessageSelfTest());
        static_cast<void>(wgnx::wireguard::RunPrimitiveSelfTest());
        static_cast<void>(wgnx::wireguard::RunCoreSelfTest());
        wgnx::sysmodule::logger::Log("Starting IPC server");
        wgnx::sysmodule::RunIpcServer();
    }
}
