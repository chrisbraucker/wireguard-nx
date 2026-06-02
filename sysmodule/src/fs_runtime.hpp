#pragma once

#include <cstddef>

#include <stratosphere.hpp>

namespace wgnx::sysmodule::fs_runtime {

ams::Result EnsureReady();
ams::Result ResolveSdPath(char *out_path, std::size_t out_path_size, const char *path);
ams::Result ReadTextFile(const char *path, char *dst, std::size_t dst_size, std::size_t *out_size);
ams::Result WriteTextFile(const char *path, const char *src, std::size_t src_size);
ams::Result DeleteFileIfExists(const char *path);
ams::Result EnsureDirectoryExists(const char *path);

} // namespace wgnx::sysmodule::fs_runtime
