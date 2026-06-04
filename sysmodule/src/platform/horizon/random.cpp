#include "wgnx/platform/random.hpp"

#include <stratosphere.hpp>

namespace wgnx::platform {

void get_random_bytes(void *dst, std::size_t size) {
    ams::os::GenerateRandomBytes(dst, size);
}

std::uint32_t get_random_u32() {
    std::uint32_t value = 0;
    get_random_bytes(std::addressof(value), sizeof(value));
    return value;
}

std::uint32_t get_random_u32_below(std::uint32_t ceil) {
    if (ceil == 0) {
        return 0;
    }

    return ams::os::GenerateRandomU32(ceil);
}

} // namespace wgnx::platform
