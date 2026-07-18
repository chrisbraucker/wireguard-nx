#pragma once

#include <array>
#include <string_view>

namespace wgnx::fuzz {

struct FuzzSeed {
    std::string_view relative_path;
    std::string_view bytes;
};

// Keep non-text corpus inputs reviewable in source. The writer materializes
// these exact bytes beneath out/ only for a fuzzing run.
inline constexpr char kHandshakeInitiationSeed[] = "\x01\x00\x00\x00\x0a";
inline constexpr char kTransportDataSeed[] = "\x04\x00\x00\x00\x0a";
inline constexpr char kInvalidIpVersionSeed[] = "\x78\x0a";
inline constexpr char kValidIpv4Seed[] =
    "\x45\x00\x00\x14\x00\x00\x00\x00\x40\x11\x8e\xfa\xc0\xa8\x01\x02"
    "\xc6\x33\x64\x01";
inline constexpr char kValidIpv6Seed[] =
    "\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00";

inline constexpr std::array<FuzzSeed, 5> kBinaryFuzzSeeds{{
    {"message_admission/type-initiation",
     {kHandshakeInitiationSeed, sizeof(kHandshakeInitiationSeed) - 1}},
    {"message_admission/type-transport",
     {kTransportDataSeed, sizeof(kTransportDataSeed) - 1}},
    {"inner_ip/invalid-version",
     {kInvalidIpVersionSeed, sizeof(kInvalidIpVersionSeed) - 1}},
    {"inner_ip/valid-ipv4", {kValidIpv4Seed, sizeof(kValidIpv4Seed) - 1}},
    {"inner_ip/valid-ipv6", {kValidIpv6Seed, sizeof(kValidIpv6Seed) - 1}},
}};

} // namespace wgnx::fuzz
