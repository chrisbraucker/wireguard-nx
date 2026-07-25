#pragma once

namespace wgnx::sysmodule::logger {

void Initialize();
void Log(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

} // namespace wgnx::sysmodule::logger
