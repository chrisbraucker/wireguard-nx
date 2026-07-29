#pragma once

#include <cstddef>

namespace wgnx::mitm {

// This state is intentionally independent from the payload slots.
// It defines when BSD may accept another nonblocking send and when POLLOUT is valid.
struct TunnelFlowSubmissionState {
    bool writable{true};
    bool closed{};
    std::size_t queued{};

    [[nodiscard]] constexpr bool CanAccept(const std::size_t capacity) const {
        return !closed && writable && queued < capacity;
    }

    [[nodiscard]] constexpr bool CanSubmit() const {
        return !closed && writable && queued != 0;
    }

    constexpr void Enqueue() {
        ++queued;
    }

    constexpr void Retire(const std::size_t count) {
        queued -= count;
    }

    constexpr void NoteQueueFull() {
        writable = false;
    }

    constexpr void NoteWritable() {
        if (!closed) {
            writable = true;
        }
    }

    constexpr void Close() {
        closed = true;
        writable = false;
    }
};

} // namespace wgnx::mitm
