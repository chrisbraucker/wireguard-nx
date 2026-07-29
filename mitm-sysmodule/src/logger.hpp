#pragma once

#include <stratosphere.hpp>

namespace wgnx::mitm::logger {

void Initialize();
void Log(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
// Packet-path diagnostics are disabled unless MITM_PACKET_DIAGNOSTICS=1 is
// supplied to the target build.
void LogPacket(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

} // namespace wgnx::mitm::logger
