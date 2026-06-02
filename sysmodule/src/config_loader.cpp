#include "config_loader.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <string_view>

#include "fs_runtime.hpp"
#include "logger.hpp"
#include "wgnx/paths.hpp"

namespace wgnx::sysmodule {

namespace {

constexpr std::size_t MaxConfigBytes = 16 * 1024;
constexpr std::size_t MaxAutoStartBytes = sizeof(wgnx::PeerInfo::name);
constexpr std::size_t MaxConfigFiles = wgnx::MaxPeers;
constexpr std::size_t MaxConfigPathBytes = sizeof(wgnx::ConfigPath) + 1 + ams::fs::EntryNameLengthMax + 1;

struct ConfigFileCandidate {
    char file_name[ams::fs::EntryNameLengthMax + 1];
    char peer_name[sizeof(wgnx::PeerInfo::name)];
};

bool HasConfSuffix(const char *name) {
    if (name == nullptr) {
        return false;
    }

    const std::size_t length = std::strlen(name);
    return length > 5 && std::strcmp(name + length - 5, ".conf") == 0;
}

bool ExtractPeerName(char *out_name, std::size_t out_name_size, const char *file_name) {
    if (out_name == nullptr || out_name_size == 0 || file_name == nullptr) {
        return false;
    }

    const std::size_t length = std::strlen(file_name);
    if (length <= 5) {
        return false;
    }

    const std::size_t stem_length = length - 5;
    if (stem_length == 0 || stem_length >= out_name_size) {
        return false;
    }

    std::memcpy(out_name, file_name, stem_length);
    out_name[stem_length] = '\0';
    return true;
}

bool BuildConfigPath(char *out_path, std::size_t out_path_size, const char *file_name) {
    if (out_path == nullptr || out_path_size == 0 || file_name == nullptr) {
        return false;
    }

    const int written = std::snprintf(out_path, out_path_size, "%s/%s", wgnx::ConfigPath, file_name);
    return written > 0 && static_cast<std::size_t>(written) < out_path_size;
}

bool LoadConnectionFile(wgnx::PeerConfigEntry *out, const ConfigFileCandidate &candidate) {
    if (out == nullptr) {
        return false;
    }

    std::array<char, MaxConfigBytes + 1> buffer{};
    std::array<char, MaxConfigPathBytes> path{};
    if (!BuildConfigPath(path.data(), path.size(), candidate.file_name)) {
        logger::Log("Config path for '%s' is too long", candidate.file_name);
        return false;
    }

    std::size_t size = 0;
    const ams::Result rc = fs_runtime::ReadTextFile(path.data(), buffer.data(), buffer.size(), &size);
    if (R_FAILED(rc)) {
        logger::Log("Connection config '%s' could not be read: rc=0x%08x", path.data(), static_cast<u32>(rc.GetValue()));
        return false;
    }

    wgnx::ConfigParseError error{};
    const std::string_view text(buffer.data(), size);
    if (!wgnx::config::ParseConnectionConfig(out, text, &error)) {
        logger::Log("Config '%s' parse failed at line %zu: %s", path.data(), error.line, error.message);
        return false;
    }

    std::snprintf(out->name, sizeof(out->name), "%s", candidate.peer_name);
    logger::Log("Loaded connection '%s' from '%s'", out->name, path.data());
    return true;
}

} // namespace

bool LoadPeerConfig(wgnx::PeerConfigSet *out) {
    if (out == nullptr) {
        return false;
    }

    *out = {};
    R_ABORT_UNLESS(R_SUCCEEDED(fs_runtime::EnsureReady()));

    ams::fs::DirectoryHandle dir;
    const ams::Result open_rc = ams::fs::OpenDirectory(std::addressof(dir), wgnx::ConfigPath, ams::fs::OpenDirectoryMode_All);
    if (R_FAILED(open_rc)) {
        logger::Log("Config directory '%s' could not be opened: rc=0x%08x", wgnx::ConfigPath, static_cast<u32>(open_rc.GetValue()));
        return false;
    }
    ON_SCOPE_EXIT { ams::fs::CloseDirectory(dir); };

    std::array<ConfigFileCandidate, MaxConfigFiles> candidates{};
    std::size_t candidate_count = 0;
    std::size_t skipped_count = 0;

    while (true) {
        s64 read_count = 0;
        ams::fs::DirectoryEntry entry{};
        const ams::Result read_rc = ams::fs::ReadDirectory(std::addressof(read_count), std::addressof(entry), dir, 1);
        if (R_FAILED(read_rc)) {
            logger::Log("Failed reading config directory '%s': rc=0x%08x", wgnx::ConfigPath, static_cast<u32>(read_rc.GetValue()));
            return false;
        }
        if (read_count == 0) {
            break;
        }
        if (entry.type == ams::fs::DirectoryEntryType_Directory) {
            logger::Log("Ignoring subdirectory '%s/%s': nested config folders are not supported", wgnx::ConfigPath, entry.name);
            continue;
        }
        if (!HasConfSuffix(entry.name)) {
            continue;
        }
        if (candidate_count >= candidates.size()) {
            ++skipped_count;
            logger::Log("Skipping extra config '%s': max peer count is %zu", entry.name, candidates.size());
            continue;
        }

        auto &candidate = candidates[candidate_count];
        std::snprintf(candidate.file_name, sizeof(candidate.file_name), "%s", entry.name);
        if (!ExtractPeerName(candidate.peer_name, sizeof(candidate.peer_name), candidate.file_name)) {
            ++skipped_count;
            logger::Log("Skipping config '%s': filename stem is empty or too long", entry.name);
            continue;
        }

        ++candidate_count;
    }

    for (std::size_t i = 0; i < candidate_count; ++i) {
        for (std::size_t j = i + 1; j < candidate_count; ++j) {
            if (std::strcmp(candidates[j].file_name, candidates[i].file_name) < 0) {
                const auto tmp = candidates[i];
                candidates[i] = candidates[j];
                candidates[j] = tmp;
            }
        }
    }

    for (std::size_t i = 0; i < candidate_count; ++i) {
        wgnx::PeerConfigEntry entry{};
        if (!LoadConnectionFile(std::addressof(entry), candidates[i])) {
            ++skipped_count;
            continue;
        }

        out->peers[out->peer_count++] = entry;
    }

    logger::Log("Loaded %zu connection(s) from '%s' (%zu skipped)", out->peer_count, wgnx::ConfigPath, skipped_count);
    return true;
}

bool LoadAutoStartPeerName(char *out_name, std::size_t out_name_size) {
    if (out_name == nullptr || out_name_size == 0) {
        return false;
    }

    out_name[0] = '\0';

    std::array<char, MaxAutoStartBytes + 1> buffer{};
    std::size_t size = 0;
    const ams::Result rc = fs_runtime::ReadTextFile(wgnx::AutoStartPath, buffer.data(), buffer.size(), &size);
    if (R_FAILED(rc)) {
        logger::Log("Autostart file '%s' could not be read: rc=0x%08x", wgnx::AutoStartPath, static_cast<u32>(rc.GetValue()));
        return false;
    }

    std::size_t end = size;
    while (end > 0 && (buffer[end - 1] == '\n' || buffer[end - 1] == '\r' || buffer[end - 1] == ' ' || buffer[end - 1] == '\t')) {
        --end;
    }

    std::size_t begin = 0;
    while (begin < end && (buffer[begin] == ' ' || buffer[begin] == '\t')) {
        ++begin;
    }

    if (begin == end) {
        logger::Log("Autostart file '%s' is empty", wgnx::AutoStartPath);
        return false;
    }

    const std::size_t trimmed_size = end - begin;
    if (trimmed_size >= out_name_size) {
        logger::Log("Autostart peer name in '%s' is too long", wgnx::AutoStartPath);
        return false;
    }

    std::memcpy(out_name, buffer.data() + begin, trimmed_size);
    out_name[trimmed_size] = '\0';
    logger::Log("Loaded autostart peer '%s' from '%s'", out_name, wgnx::AutoStartPath);
    return true;
}

} // namespace wgnx::sysmodule
