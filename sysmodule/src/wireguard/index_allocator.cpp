#include "wireguard/index_allocator.hpp"

namespace wgnx::wireguard {

void wg_index_allocator_init(wg_index_allocator *allocator) {
    if (allocator == nullptr) {
        return;
    }

    allocator->next_index = 1;
}

std::uint32_t wg_index_allocator_next(wg_index_allocator *allocator) {
    if (allocator == nullptr) {
        return 0;
    }

    const std::uint32_t result = allocator->next_index++;
    if (allocator->next_index == 0) {
        allocator->next_index = 1;
    }
    return result;
}

} // namespace wgnx::wireguard
