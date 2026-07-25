#include "platform/resolver_serialization.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > 16 * 1024)
        return 0;
    wgnx::platform::endpoint endpoint{};
    static_cast<void>(
        wgnx::platform::resolver_serialization::parse_horizon_addrinfo_result(std::span<const std::uint8_t>{data, size}, endpoint));
    return 0;
}
