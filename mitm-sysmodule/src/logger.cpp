#include "logger.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>

namespace wgnx::mitm::logger {

namespace {

constexpr const char* SdMountName = "sdmc";
constexpr const char* LogDirectory = "sdmc:/wgnx";
constexpr const char* LogFilePath = "sdmc:/wgnx/wgnx-mitm-sysmodule.log";
constexpr std::size_t FilesystemHeapBytes = 8 * 1024;

alignas(ams::os::MemoryPageSize) constinit u8 g_filesystem_heap[FilesystemHeapBytes] = {};
constinit ams::lmem::HeapHandle g_filesystem_heap_handle = nullptr;
constinit bool g_filesystem_ready = false;
ams::os::Mutex g_log_mutex(false);

void* AllocateForFilesystem(size_t size) {
    return ams::lmem::AllocateFromExpHeap(g_filesystem_heap_handle, size);
}

void DeallocateForFilesystem(void* ptr, size_t size) {
    AMS_UNUSED(size);
    ams::lmem::FreeToExpHeap(g_filesystem_heap_handle, ptr);
}

bool EnsureFilesystemReady() {
    if (g_filesystem_ready) {
        return true;
    }

    ams::fs::InitializeForSystem();
    ams::fs::SetEnabledAutoAbort(false);
    g_filesystem_heap_handle = ams::lmem::CreateExpHeap(g_filesystem_heap, sizeof(g_filesystem_heap), ams::lmem::CreateOption_None);
    if (g_filesystem_heap_handle == nullptr) {
        return false;
    }
    ams::fs::SetAllocator(AllocateForFilesystem, DeallocateForFilesystem);

    const ams::Result mount_rc = ams::fs::MountSdCard(SdMountName);
    if (R_FAILED(mount_rc) && !ams::fs::ResultMountNameAlreadyExists::Includes(mount_rc)) {
        return false;
    }
    const ams::Result directory_rc = ams::fs::CreateDirectory(LogDirectory);
    if (R_FAILED(directory_rc) && !ams::fs::ResultPathAlreadyExists::Includes(directory_rc)) {
        return false;
    }
    const ams::Result file_rc = ams::fs::CreateFile(LogFilePath, 0);
    if (R_FAILED(file_rc) && !ams::fs::ResultPathAlreadyExists::Includes(file_rc)) {
        return false;
    }

    g_filesystem_ready = true;
    return true;
}

void WriteLine(const char* line, std::size_t line_size) {
    if (!EnsureFilesystemReady()) {
        return;
    }

    ams::fs::FileHandle file;
    if (R_FAILED(ams::fs::OpenFile(std::addressof(file), LogFilePath, ams::fs::OpenMode_Write | ams::fs::OpenMode_AllowAppend))) {
        g_filesystem_ready = false;
        return;
    }
    ON_SCOPE_EXIT {
        ams::fs::CloseFile(file);
    };

    s64 offset = 0;
    if (R_FAILED(ams::fs::GetFileSize(std::addressof(offset), file)) ||
        R_FAILED(ams::fs::WriteFile(file, offset, line, line_size, ams::fs::WriteOption::Flush))) {
        g_filesystem_ready = false;
    }
}

} // namespace

void Initialize() {
    Log("=== wgnx MITM sysmodule boot ===");
}

void Log(const char* fmt, ...) {
    char message[384] = {};
    va_list args;
    va_start(args, fmt);
    const int written = std::vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    if (written <= 0) {
        return;
    }

    const std::size_t message_size = static_cast<std::size_t>(written < static_cast<int>(sizeof(message)) ? written : sizeof(message) - 1);
    char line[448] = {};
    const int line_written = std::snprintf(
        line,
        sizeof(line),
        "[%llu] %.*s\n",
        static_cast<unsigned long long>(svcGetSystemTick()),
        static_cast<int>(message_size),
        message
    );
    if (line_written <= 0) {
        return;
    }
    const std::size_t line_size = static_cast<std::size_t>(line_written < static_cast<int>(sizeof(line)) ? line_written : sizeof(line) - 1);
    static_cast<void>(svcOutputDebugString(line, line_size));

    std::scoped_lock lock(g_log_mutex);
    WriteLine(line, line_size);
}

void LogPacket(const char* fmt, ...) {
#if WGNX_MITM_PACKET_DIAGNOSTICS
    char message[384] = {};
    va_list args;
    va_start(args, fmt);
    const int written = std::vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    if (written <= 0) {
        return;
    }

    Log("%.*s", static_cast<int>(written < static_cast<int>(sizeof(message)) ? written : sizeof(message) - 1), message);
#else
    static_cast<void>(fmt);
#endif
}

} // namespace wgnx::mitm::logger
