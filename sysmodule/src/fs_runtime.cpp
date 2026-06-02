#include "fs_runtime.hpp"

namespace wgnx::sysmodule::fs_runtime {

namespace {

alignas(ams::os::MemoryPageSize) constinit u8 g_fs_heap[32 * 1024] = {};
constinit ams::lmem::HeapHandle g_fs_heap_handle = nullptr;
constinit bool g_fs_ready = false;

void *AllocateForFs(size_t size) {
    return ams::lmem::AllocateFromExpHeap(g_fs_heap_handle, size);
}

void DeallocateForFs(void *ptr, size_t size) {
    AMS_UNUSED(size);
    ams::lmem::FreeToExpHeap(g_fs_heap_handle, ptr);
}

} // namespace

ams::Result EnsureReady() {
    if (g_fs_ready) {
        R_SUCCEED();
    }

    ams::fs::InitializeForSystem();
    ams::fs::SetEnabledAutoAbort(false);

    g_fs_heap_handle = ams::lmem::CreateExpHeap(g_fs_heap, sizeof(g_fs_heap), ams::lmem::CreateOption_None);
    AMS_ABORT_UNLESS(g_fs_heap_handle != nullptr);

    ams::fs::SetAllocator(AllocateForFs, DeallocateForFs);
    g_fs_ready = true;
    R_SUCCEED();
}

ams::Result ReadTextFile(const char *path, char *dst, std::size_t dst_size, std::size_t *out_size) {
    R_UNLESS(path != nullptr, ams::fs::ResultNullptrArgument());
    R_UNLESS(dst != nullptr, ams::fs::ResultNullptrArgument());
    R_UNLESS(dst_size > 0, ams::fs::ResultInvalidSize());

    R_TRY(EnsureReady());

    ams::fs::FileHandle file;
    R_TRY(ams::fs::OpenFile(std::addressof(file), path, ams::fs::OpenMode_Read));
    ON_SCOPE_EXIT { ams::fs::CloseFile(file); };

    s64 file_size = 0;
    R_TRY(ams::fs::GetFileSize(std::addressof(file_size), file));
    R_UNLESS(file_size >= 0, ams::fs::ResultInvalidSize());

    const std::size_t read_size = static_cast<std::size_t>(file_size);
    R_UNLESS(read_size < dst_size, ams::fs::ResultTooLargeSize());

    if (read_size > 0) {
        R_TRY(ams::fs::ReadFile(file, 0, dst, read_size));
    }

    dst[read_size] = '\0';
    if (out_size != nullptr) {
        *out_size = read_size;
    }

    R_SUCCEED();
}

} // namespace wgnx::sysmodule::fs_runtime
