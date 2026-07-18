#include "fs_runtime.hpp"
#include "wgnx/resource_budget.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <span>
#include <string_view>

namespace wgnx::sysmodule::fs_runtime {

namespace {

constexpr const char *SdMountName = "sdmc";

alignas(ams::os::MemoryPageSize) constinit
    u8 g_fs_heap[wgnx::resource_budget::FilesystemHeapBytes] = {};
constinit ams::lmem::HeapHandle g_fs_heap_handle = nullptr;
constinit bool g_fs_core_ready = false;
constinit bool g_fs_ready = false;

void *AllocateForFs(size_t size) {
    return ams::lmem::AllocateFromExpHeap(g_fs_heap_handle, size);
}

void DeallocateForFs(void *ptr, size_t size) {
    AMS_UNUSED(size);
    ams::lmem::FreeToExpHeap(g_fs_heap_handle, ptr);
}

int ToPrintfLength(std::string_view value) {
    return static_cast<int>(value.size());
}

} // namespace

ams::Result EnsureReady() {
    if (g_fs_ready) {
        R_SUCCEED();
    }

    if (!g_fs_core_ready) {
        ams::fs::InitializeForSystem();
        ams::fs::SetEnabledAutoAbort(false);

        g_fs_heap_handle = ams::lmem::CreateExpHeap(g_fs_heap, sizeof(g_fs_heap), ams::lmem::CreateOption_None);
        AMS_ABORT_UNLESS(g_fs_heap_handle != nullptr);

        ams::fs::SetAllocator(AllocateForFs, DeallocateForFs);
        g_fs_core_ready = true;
    }

    const ams::Result mount_rc = ams::fs::MountSdCard(SdMountName);
    R_UNLESS(R_SUCCEEDED(mount_rc) || ams::fs::ResultMountNameAlreadyExists::Includes(mount_rc), mount_rc);
    g_fs_ready = true;
    R_SUCCEED();
}

ams::Result ResolveSdPath(std::span<char> out_path, std::string_view path) {
    R_UNLESS(!out_path.empty(), ams::fs::ResultInvalidSize());
    R_UNLESS(!path.empty(), ams::fs::ResultInvalidPathFormat());

    R_TRY(EnsureReady());

    if (path.find(':') != std::string_view::npos) {
        const int written = std::snprintf(out_path.data(), out_path.size(), "%.*s", ToPrintfLength(path), path.data());
        R_UNLESS(written > 0 && static_cast<std::size_t>(written) < out_path.size(), ams::fs::ResultTooLongPath());
        R_SUCCEED();
    }

    R_UNLESS(path.front() == '/', ams::fs::ResultInvalidPathFormat());

    const int written = std::snprintf(
        out_path.data(),
        out_path.size(),
        "%s:%.*s",
        SdMountName,
        ToPrintfLength(path),
        path.data());
    R_UNLESS(written > 0 && static_cast<std::size_t>(written) < out_path.size(), ams::fs::ResultTooLongPath());
    R_SUCCEED();
}

ams::Result ReadTextFile(std::string_view path, std::span<char> dst, std::size_t *out_size) {
    R_UNLESS(!dst.empty(), ams::fs::ResultInvalidSize());

    std::array<char, ams::fs::MountNameLengthMax + ams::fs::EntryNameLengthMax + 4> resolved_path = {};
    R_TRY(ResolveSdPath(resolved_path, path));

    ams::fs::FileHandle file;
    R_TRY(ams::fs::OpenFile(std::addressof(file), resolved_path.data(), ams::fs::OpenMode_Read));
    ON_SCOPE_EXIT { ams::fs::CloseFile(file); };

    s64 file_size = 0;
    R_TRY(ams::fs::GetFileSize(std::addressof(file_size), file));
    R_UNLESS(file_size >= 0, ams::fs::ResultInvalidSize());

    const std::size_t read_size = static_cast<std::size_t>(file_size);
    R_UNLESS(read_size < dst.size(), ams::fs::ResultTooLargeSize());

    if (read_size > 0) {
        R_TRY(ams::fs::ReadFile(file, 0, dst.data(), read_size));
    }

    dst[read_size] = '\0';
    if (out_size != nullptr) {
        *out_size = read_size;
    }

    R_SUCCEED();
}

ams::Result WriteTextFile(std::string_view path, std::string_view src) {
    std::array<char, ams::fs::MountNameLengthMax + ams::fs::EntryNameLengthMax + 4> resolved_path = {};
    R_TRY(ResolveSdPath(resolved_path, path));

    R_TRY_CATCH(ams::fs::CreateFile(resolved_path.data(), 0)) {
        R_CATCH(ams::fs::ResultPathAlreadyExists) {
        }
    } R_END_TRY_CATCH;

    ams::fs::FileHandle file;
    R_TRY(ams::fs::OpenFile(std::addressof(file), resolved_path.data(), ams::fs::OpenMode_ReadWrite));
    ON_SCOPE_EXIT { ams::fs::CloseFile(file); };

    R_TRY(ams::fs::SetFileSize(file, static_cast<s64>(src.size())));
    if (!src.empty()) {
        R_TRY(ams::fs::WriteFile(file, 0, src.data(), src.size(), ams::fs::WriteOption::Flush));
    } else {
        R_TRY(ams::fs::FlushFile(file));
    }

    R_SUCCEED();
}

ams::Result DeleteFileIfExists(std::string_view path) {
    std::array<char, ams::fs::MountNameLengthMax + ams::fs::EntryNameLengthMax + 4> resolved_path = {};
    R_TRY(ResolveSdPath(resolved_path, path));

    R_TRY_CATCH(ams::fs::DeleteFile(resolved_path.data())) {
        R_CATCH(ams::fs::ResultPathNotFound) {
        }
    } R_END_TRY_CATCH;

    R_SUCCEED();
}

ams::Result EnsureDirectoryExists(std::string_view path) {
    std::array<char, ams::fs::MountNameLengthMax + ams::fs::EntryNameLengthMax + 4> resolved_path = {};
    R_TRY(ResolveSdPath(resolved_path, path));

    R_TRY_CATCH(ams::fs::CreateDirectory(resolved_path.data())) {
        R_CATCH(ams::fs::ResultPathAlreadyExists) {
        }
    } R_END_TRY_CATCH;

    R_SUCCEED();
}

} // namespace wgnx::sysmodule::fs_runtime
