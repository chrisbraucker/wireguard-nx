#pragma once

#include <cstdint>

namespace wgnx::sysmodule::ip {

void SetLwipHostTimeForTests(std::uint32_t now_ms);

} // namespace wgnx::sysmodule::ip
