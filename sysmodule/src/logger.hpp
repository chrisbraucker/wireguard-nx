#pragma once

#include <stratosphere.hpp>

namespace wgnx::sysmodule::logger {

void Initialize();
void Log(const char *fmt, ...);

} // namespace wgnx::sysmodule::logger
