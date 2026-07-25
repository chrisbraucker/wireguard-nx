#pragma once

#include <stratosphere.hpp>

namespace wgnx::mitm::logger {

void Initialize();
void Log(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

} // namespace wgnx::mitm::logger
