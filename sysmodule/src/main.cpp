#include <stratosphere.hpp>
#include <switch.h>

#define INNER_HEAP_SIZE 0x80000

#include "ipc_service.hpp"

namespace ams {
    void Main()
    {
        wgnx::sysmodule::RunIpcServer();
    }
}
