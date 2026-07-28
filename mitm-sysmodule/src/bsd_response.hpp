#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace wgnx::mitm {

// libnx's _bsdDispatchImpl always decodes the first two CMIF words as this envelope.
struct BsdResultAndErrno {
    std::int32_t result{};
    std::int32_t error{};
};

static_assert(std::is_standard_layout_v<BsdResultAndErrno>);
static_assert(sizeof(BsdResultAndErrno) == sizeof(std::int32_t) * 2);
static_assert(offsetof(BsdResultAndErrno, result) == 0);
static_assert(offsetof(BsdResultAndErrno, error) == sizeof(std::int32_t));

struct BsdResultAndAddressLength {
    BsdResultAndErrno response{};
    std::uint32_t address_size{};
};

static_assert(std::is_standard_layout_v<BsdResultAndAddressLength>);
static_assert(sizeof(BsdResultAndAddressLength) == sizeof(std::int32_t) * 3);
static_assert(offsetof(BsdResultAndAddressLength, response) == 0);
static_assert(offsetof(BsdResultAndAddressLength, address_size) == sizeof(BsdResultAndErrno));

} // namespace wgnx::mitm
