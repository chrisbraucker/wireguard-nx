#pragma once

#include <cstddef>

namespace ams::crypto {

void ClearMemory(void* mem, std::size_t size);
bool IsSameBytes(const void* lhs, const void* rhs, std::size_t size);

} // namespace ams::crypto
