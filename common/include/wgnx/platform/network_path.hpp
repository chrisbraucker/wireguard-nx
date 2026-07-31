#pragma once

#include <cstdint>

namespace wgnx::platform {

// This is deliberately not an Internet-reachability result. It answers only
// whether Horizon currently permits trying to use a local network path.
enum class network_path_availability : std::uint8_t {
    unknown = 0,
    unavailable,
    available,
};

enum class network_path_raw_state : std::uint32_t {
    invalid = 0,
    pending = 1,
    on_hold = 2,
    available = 3,
    unknown4 = 4,
    unknown5 = 5,
};

struct network_path_observation {
    network_path_availability availability{network_path_availability::unknown};
    network_path_raw_state raw_state{network_path_raw_state::invalid};
    std::uint32_t state_result{0};
    std::uint32_t operation_result{0};
    std::uint32_t request_generation{0};

    constexpr bool operator==(const network_path_observation&) const = default;
};

[[nodiscard]] constexpr network_path_availability
classify_network_path_state(network_path_raw_state state, std::uint32_t state_result = 0) {
    // A failed observation is indeterminate. NIFM only becomes authoritative
    // after a confirmed request state has been read successfully.
    if (state_result != 0) {
        return network_path_availability::unknown;
    }

    switch (state) {
    case network_path_raw_state::available:
        return network_path_availability::available;
    // The 20.5.0 IRequest state machine initializes at Pending and enters
    // OnHold after submission while NIFM cannot currently admit the
    // request. They are therefore authoritative only for local socket
    // ownership: do not transmit until NIFM reports Available again.
    // They neither identify a physical interface nor establish remote
    // WireGuard-peer reachability.
    case network_path_raw_state::pending:
    case network_path_raw_state::on_hold:
        return network_path_availability::unavailable;
    case network_path_raw_state::invalid:
    case network_path_raw_state::unknown4:
    case network_path_raw_state::unknown5:
        return network_path_availability::unknown;
    }
    return network_path_availability::unknown;
}

constexpr const char* get_network_path_availability_name(network_path_availability availability) {
    switch (availability) {
    case network_path_availability::unknown:
        return "unknown";
    case network_path_availability::unavailable:
        return "unavailable";
    case network_path_availability::available:
        return "available";
    }
    return "unknown";
}

} // namespace wgnx::platform
