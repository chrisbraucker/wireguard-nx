#include "wireguard/index_allocator.hpp"

#include "wgnx/platform/random.hpp"

namespace wgnx::wireguard {

void wg_index_allocator_init(wg_index_allocator *allocator) {
    if (allocator == nullptr) {
        return;
    }

    allocator->last_index = 0;
}

std::uint32_t wg_index_allocator_next(wg_index_allocator *allocator) {
    if (allocator == nullptr) {
        return 0;
    }

    static std::uint32_t g_next_index = 0;
    if (g_next_index == 0) {
        g_next_index = wgnx::platform::get_random_u32();
        if (g_next_index == 0) {
            g_next_index = 1;
        }
    }

    const std::uint32_t result = g_next_index++;
    if (g_next_index == 0) {
        g_next_index = 1;
    }

    allocator->last_index = result;
    return result;
}

} // namespace wgnx::wireguard
