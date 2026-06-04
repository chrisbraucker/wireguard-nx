#pragma once

#include <cstddef>
#include <cstdint>

namespace wgnx::platform {

void get_random_bytes(void *dst, std::size_t size);
std::uint32_t get_random_u32();
std::uint32_t get_random_u32_below(std::uint32_t ceil);

} // namespace wgnx::platform
