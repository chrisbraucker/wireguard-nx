#include "logger.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace wgnx::sysmodule::logger {

namespace {

constexpr const char *SdMountName = "sdmc";
constexpr const char *RootLogDirectory = "sdmc:/atmosphere";
constexpr const char *LogDirectory = "sdmc:/atmosphere/logs";
constexpr const char *LogFilePath = "sdmc:/atmosphere/logs/wgnx-sysmodule.log";

enum class FileBackendState : std::uint8_t {
    Uninitialized,
    Ready,
    Disabled,
};

bool g_logger_initialized = false;
FileBackendState g_file_backend_state = FileBackendState::Uninitialized;
alignas(ams::os::MemoryPageSize) constinit u8 g_fs_heap[32 * 1024] = {};
constinit ams::lmem::HeapHandle g_fs_heap_handle = nullptr;
bool g_fs_ready = false;

void EmitDebugString(const char *line, size_t line_size) {
    if (line == nullptr || line_size == 0) {
        return;
    }

    (void)::svcOutputDebugString(line, line_size);
}

void *AllocateForFs(size_t size) {
    return ams::lmem::AllocateFromExpHeap(g_fs_heap_handle, size);
}

void DeallocateForFs(void *ptr, size_t size) {
    AMS_UNUSED(size);
    ams::lmem::FreeToExpHeap(g_fs_heap_handle, ptr);
}

void EnsureFsReady() {
    if (g_fs_ready) {
        return;
    }

    ams::fs::InitializeForSystem();
    ams::fs::SetEnabledAutoAbort(false);

    g_fs_heap_handle = ams::lmem::CreateExpHeap(g_fs_heap, sizeof(g_fs_heap), ams::lmem::CreateOption_None);
    AMS_ABORT_UNLESS(g_fs_heap_handle != nullptr);

    ams::fs::SetAllocator(AllocateForFs, DeallocateForFs);
    g_fs_ready = true;
}

bool EnsureDirectoryExists(const char *path) {
    const ams::Result rc = ams::fs::CreateDirectory(path);
    return R_SUCCEEDED(rc) || ams::fs::ResultPathAlreadyExists::Includes(rc);
}

void EnsureFileBackendInitialized() {
    if (g_file_backend_state != FileBackendState::Uninitialized) {
        return;
    }

    EnsureFsReady();
    ams::Result rc = ams::fs::MountSdCard(SdMountName);
    if (R_FAILED(rc) && !ams::fs::ResultMountNameAlreadyExists::Includes(rc)) {
        g_file_backend_state = FileBackendState::Disabled;
        return;
    }

    if (!EnsureDirectoryExists(RootLogDirectory) || !EnsureDirectoryExists(LogDirectory)) {
        g_file_backend_state = FileBackendState::Disabled;
        return;
    }

    rc = ams::fs::CreateFile(LogFilePath, 0);
    if (R_FAILED(rc) && !ams::fs::ResultPathAlreadyExists::Includes(rc)) {
        g_file_backend_state = FileBackendState::Disabled;
        return;
    }

    g_file_backend_state = FileBackendState::Ready;
}

void WriteLineToFile(const char *line, size_t line_size) {
    EnsureFileBackendInitialized();
    if (g_file_backend_state != FileBackendState::Ready || line == nullptr || line_size == 0) {
        return;
    }

    ams::fs::FileHandle file;
    const ams::Result open_rc = ams::fs::OpenFile(
        std::addressof(file),
        LogFilePath,
        ams::fs::OpenMode_Write | ams::fs::OpenMode_AllowAppend);
    if (R_FAILED(open_rc)) {
        g_file_backend_state = FileBackendState::Disabled;
        return;
    }
    ON_SCOPE_EXIT { ams::fs::CloseFile(file); };

    s64 file_size = 0;
    if (R_FAILED(ams::fs::GetFileSize(std::addressof(file_size), file))) {
        g_file_backend_state = FileBackendState::Disabled;
        return;
    }

    if (R_FAILED(ams::fs::WriteFile(file, file_size, line, line_size, ams::fs::WriteOption::Flush))) {
        g_file_backend_state = FileBackendState::Disabled;
    }
}

} // namespace

void Initialize() {
    if (g_logger_initialized) {
        return;
    }

    g_logger_initialized = true;
    const char *banner = "\n=== wgnx sysmodule boot ===\n";
    EmitDebugString(banner, std::strlen(banner));
    WriteLineToFile(banner, std::strlen(banner));
}

void Log(const char *fmt, ...) {
    char message[512];
    va_list args;
    va_start(args, fmt);
    const int written = std::vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    if (written <= 0) {
        return;
    }

    char line[640];
    const auto tick = static_cast<unsigned long long>(svcGetSystemTick());
    const int line_written = std::snprintf(line, sizeof(line), "[%llu] %s\n", tick, message);
    if (line_written <= 0) {
        return;
    }

    const size_t line_size = static_cast<size_t>((line_written < static_cast<int>(sizeof(line))) ? line_written : (sizeof(line) - 1));
    EmitDebugString(line, line_size);
    WriteLineToFile(line, line_size);
}

} // namespace wgnx::sysmodule::logger
