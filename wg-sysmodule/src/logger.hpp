#pragma once

#include <stratosphere.hpp>

namespace wgnx::sysmodule::logger {

void Initialize();
// Records a bounded diagnostic line without performing platform or filesystem
// I/O. This is safe for state-owner paths that hold the daemon mutex.
void Log(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
// Emits queued diagnostics. Call only after releasing runtime state locks.
void Flush();

} // namespace wgnx::sysmodule::logger
