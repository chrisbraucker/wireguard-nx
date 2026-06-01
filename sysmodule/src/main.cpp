#include <stratosphere.hpp>
#include <switch.h>

#define INNER_HEAP_SIZE 0x80000

#include "ipc_service.hpp"
#include "logger.hpp"

namespace ams {
    void Main()
    {
        wgnx::sysmodule::logger::Initialize();
        wgnx::sysmodule::logger::Log("Main entered");
        wgnx::sysmodule::RunIpcServer();
    }
}
