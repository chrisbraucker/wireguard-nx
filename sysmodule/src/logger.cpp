#include "logger.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>

#include "fs_runtime.hpp"

namespace wgnx::sysmodule::logger {

namespace {

constexpr const char *SdMountName = "sdmc";
constexpr const char *LogDirectory = "sdmc:/wgnx";
constexpr const char *LogFilePath = "sdmc:/wgnx/wgnx-sysmodule.log";

enum class FileBackendState : std::uint8_t {
    Uninitialized,
    Ready,
};

bool g_logger_initialized = false;
FileBackendState g_file_backend_state = FileBackendState::Uninitialized;
ams::os::Mutex g_file_backend_mutex(false);

void EmitDebugString(const char *line, size_t line_size) {
    if (line == nullptr || line_size == 0) {
        return;
    }

    (void)::svcOutputDebugString(line, line_size);
}

void EmitFileBackendFailure(const char *operation, ams::Result rc) {
    char line[192];
    const int written = std::snprintf(
        line,
        sizeof(line),
        "wgnx logger file backend failure: operation=%s rc=0x%08x; will retry\n",
        operation,
        static_cast<u32>(rc.GetValue()));
    if (written <= 0) {
        return;
    }

    const size_t line_size = static_cast<size_t>(
        (written < static_cast<int>(sizeof(line))) ? written : (sizeof(line) - 1));
    EmitDebugString(line, line_size);
}

bool EnsureFileBackendInitializedLocked() {
    if (g_file_backend_state != FileBackendState::Uninitialized) {
        return true;
    }

    ams::Result rc = fs_runtime::EnsureReady();
    if (R_FAILED(rc)) {
        EmitFileBackendFailure("fs_runtime::EnsureReady", rc);
        return false;
    }

    rc = ams::fs::MountSdCard(SdMountName);
    if (R_FAILED(rc) && !ams::fs::ResultMountNameAlreadyExists::Includes(rc)) {
        EmitFileBackendFailure("MountSdCard", rc);
        return false;
    }

    rc = ams::fs::CreateDirectory(LogDirectory);
    if (R_FAILED(rc) && !ams::fs::ResultPathAlreadyExists::Includes(rc)) {
        EmitFileBackendFailure("CreateDirectory", rc);
        return false;
    }

    rc = ams::fs::CreateFile(LogFilePath, 0);
    if (R_FAILED(rc) && !ams::fs::ResultPathAlreadyExists::Includes(rc)) {
        EmitFileBackendFailure("CreateFile", rc);
        return false;
    }

    g_file_backend_state = FileBackendState::Ready;
    return true;
}

void WriteLineToFileLocked(const char *line, size_t line_size) {
    if (line == nullptr || line_size == 0 || !EnsureFileBackendInitializedLocked()) {
        return;
    }

    ams::fs::FileHandle file;
    const ams::Result open_rc = ams::fs::OpenFile(
        std::addressof(file),
        LogFilePath,
        ams::fs::OpenMode_Write | ams::fs::OpenMode_AllowAppend);
    if (R_FAILED(open_rc)) {
        EmitFileBackendFailure("OpenFile", open_rc);
        g_file_backend_state = FileBackendState::Uninitialized;
        return;
    }
    ON_SCOPE_EXIT { ams::fs::CloseFile(file); };

    s64 file_size = 0;
    const ams::Result size_rc = ams::fs::GetFileSize(std::addressof(file_size), file);
    if (R_FAILED(size_rc)) {
        EmitFileBackendFailure("GetFileSize", size_rc);
        g_file_backend_state = FileBackendState::Uninitialized;
        return;
    }

    const ams::Result write_rc = ams::fs::WriteFile(file, file_size, line, line_size, ams::fs::WriteOption::Flush);
    if (R_FAILED(write_rc)) {
        EmitFileBackendFailure("WriteFile", write_rc);
        g_file_backend_state = FileBackendState::Uninitialized;
    }
}

void WriteLineToFile(const char *line, size_t line_size) {
    std::scoped_lock lock(g_file_backend_mutex);
    WriteLineToFileLocked(line, line_size);
}

} // namespace

void Initialize() {
    std::scoped_lock lock(g_file_backend_mutex);
    if (g_logger_initialized) {
        return;
    }

    g_logger_initialized = true;
    const char *banner = "\n=== wgnx sysmodule boot ===\n";
    EmitDebugString(banner, std::strlen(banner));
    WriteLineToFileLocked(banner, std::strlen(banner));
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
