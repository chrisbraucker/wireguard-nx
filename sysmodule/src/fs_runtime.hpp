#pragma once

#include <cstddef>
#include <span>
#include <string_view>

#include <stratosphere.hpp>

namespace wgnx::sysmodule::fs_runtime {

ams::Result EnsureReady();
ams::Result ResolveSdPath(std::span<char> out_path, std::string_view path);
ams::Result ReadTextFile(std::string_view path, std::span<char> dst, std::size_t *out_size);
ams::Result WriteTextFile(std::string_view path, std::string_view src);
ams::Result DeleteFileIfExists(std::string_view path);
ams::Result EnsureDirectoryExists(std::string_view path);

} // namespace wgnx::sysmodule::fs_runtime
