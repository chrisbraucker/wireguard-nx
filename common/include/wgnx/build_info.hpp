#pragma once

#ifndef WGNX_VERSION
#define WGNX_VERSION "unknown"
#endif

#ifndef WGNX_BUILD_ID
#define WGNX_BUILD_ID "unknown"
#endif

namespace wgnx::build_info {

inline constexpr char Version[] = WGNX_VERSION;
inline constexpr char BuildId[] = WGNX_BUILD_ID;
inline constexpr char VersionWithBuild[] = WGNX_VERSION "-" WGNX_BUILD_ID;

} // namespace wgnx::build_info
