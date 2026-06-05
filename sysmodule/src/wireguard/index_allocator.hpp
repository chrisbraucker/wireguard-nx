#pragma once

#include <cstdint>

namespace wgnx::wireguard {

struct wg_index_allocator {
    std::uint32_t next_index{1};
};

void wg_index_allocator_init(wg_index_allocator *allocator);
std::uint32_t wg_index_allocator_next(wg_index_allocator *allocator);

} // namespace wgnx::wireguard
