#pragma once

#include <cstddef>

#include <stratosphere.hpp>

namespace wgnx::sysmodule::fs_runtime {

ams::Result EnsureReady();
ams::Result ReadTextFile(const char *path, char *dst, std::size_t dst_size, std::size_t *out_size);

} // namespace wgnx::sysmodule::fs_runtime
