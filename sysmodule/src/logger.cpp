#include "logger.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>

namespace wgnx::sysmodule::logger {

namespace {

constexpr const char *LogDirectory = "sdmc:/atmosphere/logs";
constexpr const char *LogFilePath = "sdmc:/atmosphere/logs/wgnx-sysmodule.log";
std::mutex g_log_mutex;

void EnsureLogFile() {
    ams::Result rc = ams::fs::CreateDirectory("sdmc:/atmosphere");
    if (R_FAILED(rc) && !ams::fs::ResultPathAlreadyExists::Includes(rc)) {
        return;
    }

    rc = ams::fs::CreateDirectory(LogDirectory);
    if (R_FAILED(rc) && !ams::fs::ResultPathAlreadyExists::Includes(rc)) {
        return;
    }

    rc = ams::fs::CreateFile(LogFilePath, 0);
    if (R_FAILED(rc) && !ams::fs::ResultPathAlreadyExists::Includes(rc)) {
        return;
    }
}

void WriteLineLocked(const char *line, size_t line_size) {
    EnsureLogFile();

    ams::fs::FileHandle file;
    if (R_FAILED(ams::fs::OpenFile(std::addressof(file), LogFilePath, ams::fs::OpenMode_Write))) {
        return;
    }
    ON_SCOPE_EXIT { ams::fs::CloseFile(file); };

    s64 file_size = 0;
    if (R_FAILED(ams::fs::GetFileSize(std::addressof(file_size), file))) {
        return;
    }

    if (R_FAILED(ams::fs::SetFileSize(file, file_size + static_cast<s64>(line_size)))) {
        return;
    }

    (void)ams::fs::WriteFile(file, file_size, line, line_size, ams::fs::WriteOption::Flush);
}

} // namespace

void Initialize() {
    std::scoped_lock lock{g_log_mutex};
    static bool initialized = false;
    if (initialized) {
        return;
    }

    initialized = true;
    const char *banner = "\n=== wgnx sysmodule boot ===\n";
    WriteLineLocked(banner, std::strlen(banner));
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

    const size_t line_size = static_cast<size_t>(std::min<int>(line_written, sizeof(line) - 1));
    std::scoped_lock lock{g_log_mutex};
    WriteLineLocked(line, line_size);
}

} // namespace wgnx::sysmodule::logger
