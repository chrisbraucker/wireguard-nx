#include <stratosphere.hpp>
#include <switch.h>

#include "ipc_service.hpp"
#include "logger.hpp"

namespace ams {
    void Main()
    {
        wgnx::sysmodule::logger::Initialize();
        wgnx::sysmodule::logger::Log("Main entered");
        wgnx::sysmodule::logger::Log("Starting IPC server");
        wgnx::sysmodule::RunIpcServer();
    }
}
