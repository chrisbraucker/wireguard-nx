#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace wgnx::platform {

/*
 * Deviation from Linux:
 * `packet_buffer` is a lightweight mutable byte span rather than a full
 * `sk_buff` analogue. The implication is that Milestone 4 parsing code can be
 * written against a stable packet view now, while queue metadata and headroom
 * semantics remain future transport concerns.
 */
struct packet_buffer {
    std::uint8_t *data{nullptr};
    std::size_t len{0};
    std::size_t capacity{0};
};

inline void packet_init(packet_buffer *packet, void *data, std::size_t capacity) {
    if (packet == nullptr) {
        return;
    }

    packet->data = static_cast<std::uint8_t *>(data);
    packet->len = 0;
    packet->capacity = capacity;
}

inline void packet_clear(packet_buffer *packet) {
    if (packet == nullptr) {
        return;
    }

    packet->len = 0;
}

inline bool packet_set_len(packet_buffer *packet, std::size_t len) {
    if (packet == nullptr || len > packet->capacity) {
        return false;
    }

    packet->len = len;
    return true;
}

template<std::size_t Capacity>
struct static_packet_buffer {
    std::array<std::uint8_t, Capacity> storage{};
    packet_buffer packet{};

    static_packet_buffer() {
        packet_init(&packet, storage.data(), storage.size());
    }
};

} // namespace wgnx::platform
