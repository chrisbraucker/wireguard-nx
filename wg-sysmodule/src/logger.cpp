#include "logger.hpp"

#include <cstdarg>
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <mutex>

#include "fs_runtime.hpp"

namespace wgnx::sysmodule::logger {

namespace {

constexpr const char* SdMountName = "sdmc";
constexpr const char* LogDirectory = "sdmc:/wgnx";
constexpr const char* LogFilePath = "sdmc:/wgnx/wgnx-sysmodule.log";
constexpr std::size_t PendingLogCapacity = 16;
constexpr std::size_t MaximumQueuedMessageSize = 512;
constexpr std::size_t MaximumFormattedLineSize = 640;

enum class FileBackendState : std::uint8_t {
    Uninitialized,
    Ready,
};

bool g_logger_initialized = false;
FileBackendState g_file_backend_state = FileBackendState::Uninitialized;
struct PendingLogLine {
    std::array<char, MaximumQueuedMessageSize> bytes{};
    std::size_t size{0};
};

std::array<PendingLogLine, PendingLogCapacity> g_pending_logs{};
std::size_t g_pending_head = 0;
std::size_t g_pending_count = 0;
std::size_t g_dropped_log_count = 0;
ams::os::Mutex g_pending_log_mutex(false);
ams::os::Mutex g_file_backend_mutex(false);

void EmitDebugString(const char* line, size_t line_size) {
    if (line == nullptr || line_size == 0) {
        return;
    }

    (void)::svcOutputDebugString(line, line_size);
}

void EmitFileBackendFailure(const char* operation, ams::Result rc) {
    char line[192];
    const int written = std::snprintf(
        line,
        sizeof(line),
        "wgnx logger file backend failure: operation=%s rc=0x%08x; will retry\n",
        operation,
        static_cast<u32>(rc.GetValue())
    );
    if (written <= 0) {
        return;
    }

    const size_t line_size = static_cast<size_t>((written < static_cast<int>(sizeof(line))) ? written : (sizeof(line) - 1));
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

void WriteLineToFileLocked(const char* line, size_t line_size) {
    if (line == nullptr || line_size == 0 || !EnsureFileBackendInitializedLocked()) {
        return;
    }

    ams::fs::FileHandle file;
    const ams::Result open_rc =
        ams::fs::OpenFile(std::addressof(file), LogFilePath, ams::fs::OpenMode_Write | ams::fs::OpenMode_AllowAppend);
    if (R_FAILED(open_rc)) {
        EmitFileBackendFailure("OpenFile", open_rc);
        g_file_backend_state = FileBackendState::Uninitialized;
        return;
    }
    ON_SCOPE_EXIT {
        ams::fs::CloseFile(file);
    };

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

void WriteLineToFile(const char* line, size_t line_size) {
    std::scoped_lock lock(g_file_backend_mutex);
    WriteLineToFileLocked(line, line_size);
}

void EnqueueLine(const char* line, std::size_t line_size) {
    if (line == nullptr || line_size == 0) {
        return;
    }

    std::scoped_lock lock(g_pending_log_mutex);
    if (g_pending_count == PendingLogCapacity) {
        g_pending_head = (g_pending_head + 1) % PendingLogCapacity;
        --g_pending_count;
        ++g_dropped_log_count;
    }

    const std::size_t index = (g_pending_head + g_pending_count) % PendingLogCapacity;
    auto& entry = g_pending_logs[index];
    entry.size = std::min(line_size, entry.bytes.size());
    std::memcpy(entry.bytes.data(), line, entry.size);
    ++g_pending_count;
}

bool TakePendingLine(PendingLogLine& out_line) {
    std::scoped_lock lock(g_pending_log_mutex);
    if (g_pending_count == 0) {
        return false;
    }

    out_line = g_pending_logs[g_pending_head];
    g_pending_head = (g_pending_head + 1) % PendingLogCapacity;
    --g_pending_count;
    return true;
}

std::size_t TakeDroppedLogCount() {
    std::scoped_lock lock(g_pending_log_mutex);
    const std::size_t dropped = g_dropped_log_count;
    g_dropped_log_count = 0;
    return dropped;
}

} // namespace

void Initialize() {
    std::scoped_lock lock(g_file_backend_mutex);
    if (g_logger_initialized) {
        return;
    }

    g_logger_initialized = true;
    const char* banner = "=== wgnx sysmodule boot ===";
    EnqueueLine(banner, std::strlen(banner));
}

void Log(const char* fmt, ...) {
    char message[512];
    va_list args;
    va_start(args, fmt);
    const int written = std::vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    if (written <= 0) {
        return;
    }

    const size_t message_size = static_cast<size_t>(std::min(written, static_cast<int>(sizeof(message) - 1)));
    EnqueueLine(message, message_size);
}

void LogPacket(const char* fmt, ...) {
#if WGNX_PACKET_DIAGNOSTICS
    char message[512];
    va_list args;
    va_start(args, fmt);
    const int written = std::vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    if (written <= 0) {
        return;
    }

    const size_t message_size = static_cast<size_t>(std::min(written, static_cast<int>(sizeof(message) - 1)));
    EnqueueLine(message, message_size);
#else
    static_cast<void>(fmt);
#endif
}

void Flush() {
    const std::size_t dropped = TakeDroppedLogCount();
    if (dropped != 0) {
        char notice[128]{};
        const int written = std::snprintf(notice, sizeof(notice), "wgnx logger dropped %zu buffered diagnostic line(s)\n", dropped);
        if (written > 0) {
            const std::size_t notice_size = static_cast<std::size_t>(std::min(written, static_cast<int>(sizeof(notice) - 1)));
            EmitDebugString(notice, notice_size);
            WriteLineToFile(notice, notice_size);
        }
    }

    PendingLogLine line{};
    while (TakePendingLine(line)) {
        char formatted[MaximumFormattedLineSize]{};
        const auto tick = static_cast<unsigned long long>(svcGetSystemTick());
        const int written =
            std::snprintf(formatted, sizeof(formatted), "[%llu] %.*s\n", tick, static_cast<int>(line.size), line.bytes.data());
        if (written <= 0) {
            continue;
        }
        const std::size_t formatted_size = static_cast<std::size_t>(std::min(written, static_cast<int>(sizeof(formatted) - 1)));
        EmitDebugString(formatted, formatted_size);
        WriteLineToFile(formatted, formatted_size);
    }
}

} // namespace wgnx::sysmodule::logger
