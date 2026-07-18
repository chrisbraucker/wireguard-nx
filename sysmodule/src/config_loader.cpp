#include "config_loader.hpp"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string_view>

#include <stratosphere/util/util_ini.hpp>

#include "config_text_validation.hpp"
#include "fs_runtime.hpp"
#include "logger.hpp"
#include "wgnx/paths.hpp"

namespace wgnx::sysmodule {

namespace {

constexpr std::size_t MaxConfigBytes = 16 * 1024;
constexpr std::size_t MaxAutoStartBytes = sizeof(wgnx::PeerInfo::name);
constexpr std::size_t MaxConfigFiles = wgnx::MaxPeers;
constexpr std::size_t MaxResolvedPathBytes = ams::fs::MountNameLengthMax + ams::fs::EntryNameLengthMax + 4;

struct ConfigParseError {
    std::size_t line{0};
    char message[96]{};
};

struct ConfigFileCandidate {
    char file_name[ams::fs::EntryNameLengthMax + 1];
    char peer_name[sizeof(wgnx::PeerInfo::name)];
};

struct ConnectionParseContext {
    wgnx::PeerConfigEntry *out;
    ConfigParseError *error;
    bool saw_private_key{false};
    bool saw_address{false};
    bool saw_listen_port{false};
    bool saw_dns{false};
    bool saw_mtu{false};
    bool saw_public_key{false};
    bool saw_preshared_key{false};
    bool saw_allowed_ips{false};
    bool saw_endpoint{false};
    bool saw_persistent_keepalive{false};
};

constinit std::array<char, MaxConfigBytes + 1> g_config_buffer = {};
constinit std::array<ConfigFileCandidate, MaxConfigFiles> g_candidates = {};

void SetError(ConfigParseError *error, std::size_t line, const char *message) {
    if (error == nullptr) {
        return;
    }

    error->line = line;
    std::snprintf(error->message, sizeof(error->message), "%s", message);
}

template<std::size_t Size>
bool CopyField(std::array<char, Size> &dst, const char *value, ConfigParseError *error, std::size_t line, const char *field_name) {
    if (value == nullptr) {
        SetError(error, line, "value is null");
        return false;
    }

    const std::size_t length = std::strlen(value);
    if (length >= Size) {
        char message[sizeof(ConfigParseError::message)] = {};
        std::snprintf(message, sizeof(message), "%s is too long", field_name);
        SetError(error, line, message);
        return false;
    }

    std::memcpy(dst.data(), value, length + 1);
    return true;
}

bool ParseUnsignedField(std::uint16_t *out, const char *value, ConfigParseError *error, std::size_t line, const char *field_name) {
    if (out == nullptr) {
        SetError(error, line, "numeric output pointer is null");
        return false;
    }
    if (value == nullptr || value[0] == '\0') {
        SetError(error, line, "numeric value is empty");
        return false;
    }

    char *end = nullptr;
    errno = 0;
    const unsigned long parsed = std::strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed > 0xFFFFul) {
        char message[sizeof(ConfigParseError::message)] = {};
        std::snprintf(message, sizeof(message), "%s must be an unsigned 16-bit integer", field_name);
        SetError(error, line, message);
        return false;
    }

    *out = static_cast<std::uint16_t>(parsed);
    return true;
}

int HandleConnectionConfig(void *user_ctx, const char *section, const char *name, const char *value) {
    auto *ctx = static_cast<ConnectionParseContext *>(user_ctx);
    if (ctx == nullptr || ctx->out == nullptr) {
        return 0;
    }

    if (std::strcmp(section, "Interface") == 0) {
        if (std::strcmp(name, "PrivateKey") == 0) {
            if (ctx->saw_private_key) {
                SetError(ctx->error, 0, "multiple Interface.PrivateKey values are not supported");
                return 0;
            }

            if (!CopyField(ctx->out->private_key, value, ctx->error, 0, "PrivateKey")) {
                return 0;
            }

            ctx->out->field_flags |= wgnx::PeerConfigField_PrivateKey;
            ctx->saw_private_key = true;
            return 1;
        }

        if (std::strcmp(name, "Address") == 0) {
            if (ctx->saw_address) {
                SetError(ctx->error, 0, "multiple Interface.Address values are not supported");
                return 0;
            }

            if (!CopyField(ctx->out->address, value, ctx->error, 0, "Address")) {
                return 0;
            }

            ctx->saw_address = true;
            return 1;
        }

        if (std::strcmp(name, "ListenPort") == 0) {
            if (ctx->saw_listen_port) {
                SetError(ctx->error, 0, "multiple Interface.ListenPort values are not supported");
                return 0;
            }

            if (!ParseUnsignedField(&ctx->out->listen_port, value, ctx->error, 0, "ListenPort")) {
                return 0;
            }

            ctx->out->field_flags |= wgnx::PeerConfigField_ListenPort;
            ctx->saw_listen_port = true;
            return 1;
        }

        if (std::strcmp(name, "DNS") == 0) {
            if (ctx->saw_dns) {
                SetError(ctx->error, 0, "multiple Interface.DNS values are not supported");
                return 0;
            }

            if (!CopyField(ctx->out->dns, value, ctx->error, 0, "DNS")) {
                return 0;
            }

            ctx->out->field_flags |= wgnx::PeerConfigField_Dns;
            ctx->saw_dns = true;
            return 1;
        }

        if (std::strcmp(name, "MTU") == 0) {
            if (ctx->saw_mtu) {
                SetError(ctx->error, 0, "multiple Interface.MTU values are not supported");
                return 0;
            }

            if (!ParseUnsignedField(&ctx->out->mtu, value, ctx->error, 0, "MTU")) {
                return 0;
            }

            ctx->out->field_flags |= wgnx::PeerConfigField_Mtu;
            ctx->saw_mtu = true;
            return 1;
        }

        return 1;
    }

    if (std::strcmp(section, "Peer") == 0) {
        if (std::strcmp(name, "PublicKey") == 0) {
            if (ctx->saw_public_key) {
                SetError(ctx->error, 0, "multiple Peer.PublicKey values are not supported");
                return 0;
            }

            if (!CopyField(ctx->out->public_key, value, ctx->error, 0, "PublicKey")) {
                return 0;
            }

            ctx->out->field_flags |= wgnx::PeerConfigField_PublicKey;
            ctx->saw_public_key = true;
            return 1;
        }

        if (std::strcmp(name, "PresharedKey") == 0) {
            if (ctx->saw_preshared_key) {
                SetError(ctx->error, 0, "multiple Peer.PresharedKey values are not supported");
                return 0;
            }

            if (!CopyField(ctx->out->preshared_key, value, ctx->error, 0, "PresharedKey")) {
                return 0;
            }

            ctx->out->field_flags |= wgnx::PeerConfigField_PresharedKey;
            ctx->saw_preshared_key = true;
            return 1;
        }

        if (std::strcmp(name, "AllowedIPs") == 0) {
            if (ctx->saw_allowed_ips) {
                SetError(ctx->error, 0, "multiple Peer.AllowedIPs values are not supported");
                return 0;
            }

            if (!CopyField(ctx->out->allowed_ips, value, ctx->error, 0, "AllowedIPs")) {
                return 0;
            }

            ctx->out->field_flags |= wgnx::PeerConfigField_AllowedIps;
            ctx->saw_allowed_ips = true;
            return 1;
        }

        if (std::strcmp(name, "Endpoint") == 0) {
            if (ctx->saw_endpoint) {
                SetError(ctx->error, 0, "multiple Peer.Endpoint values are not supported");
                return 0;
            }

            if (!CopyField(ctx->out->endpoint, value, ctx->error, 0, "Endpoint")) {
                return 0;
            }

            ctx->saw_endpoint = true;
            return 1;
        }

        if (std::strcmp(name, "PersistentKeepalive") == 0) {
            if (ctx->saw_persistent_keepalive) {
                SetError(ctx->error, 0, "multiple Peer.PersistentKeepalive values are not supported");
                return 0;
            }

            if (!ParseUnsignedField(&ctx->out->persistent_keepalive, value, ctx->error, 0, "PersistentKeepalive")) {
                return 0;
            }

            ctx->out->field_flags |= wgnx::PeerConfigField_PersistentKeepalive;
            ctx->saw_persistent_keepalive = true;
            return 1;
        }

        return 1;
    }

    return 1;
}

bool ValidateSectionLayout(const char *text, ConfigParseError *error) {
    if (text == nullptr) {
        SetError(error, 0, "config text is null");
        return false;
    }

    const ConfigLayoutValidation validation = ValidateConnectionConfigLayout(text);
    if (!validation.IsValid()) {
        SetError(
            error,
            validation.line,
            GetConfigLayoutErrorMessage(validation.error));
        return false;
    }
    return true;
}

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

    *out = {};

    std::array<char, MaxResolvedPathBytes> config_path = {};
    if (!BuildConfigPath(config_path.data(), config_path.size(), candidate.file_name)) {
        logger::Log("Config path for '%s' is too long", candidate.file_name);
        return false;
    }

    std::array<char, MaxResolvedPathBytes> resolved_path = {};
    const ams::Result resolve_rc = fs_runtime::ResolveSdPath(resolved_path, config_path.data());
    if (R_FAILED(resolve_rc)) {
        logger::Log("Connection config path '%s' is invalid: rc=0x%08x", config_path.data(), static_cast<u32>(resolve_rc.GetValue()));
        return false;
    }

    std::size_t size = 0;
    const ams::Result read_rc = fs_runtime::ReadTextFile(config_path.data(), g_config_buffer, &size);
    if (R_FAILED(read_rc)) {
        logger::Log("Connection config '%s' could not be read: rc=0x%08x", resolved_path.data(), static_cast<u32>(read_rc.GetValue()));
        return false;
    }

    ConfigParseError error{};
    if (!ValidateSectionLayout(g_config_buffer.data(), &error)) {
        logger::Log("Config '%s' parse failed at line %zu: %s", resolved_path.data(), error.line, error.message);
        return false;
    }

    ConnectionParseContext ctx = {
        .out = out,
        .error = &error,
    };

    const int parse_rc = ams::util::ini::ParseString(g_config_buffer.data(), std::addressof(ctx), HandleConnectionConfig);
    if (parse_rc != 0) {
        if (error.message[0] == '\0') {
            SetError(&error, static_cast<std::size_t>(parse_rc), "invalid INI syntax");
        } else if (error.line == 0) {
            error.line = static_cast<std::size_t>(parse_rc);
        }

        logger::Log("Config '%s' parse failed at line %zu: %s", resolved_path.data(), error.line, error.message);
        return false;
    }

    if (!ctx.saw_address) {
        logger::Log("Config '%s' is missing Interface.Address", resolved_path.data());
        return false;
    }
    if (!ctx.saw_private_key) {
        logger::Log("Config '%s' is missing Interface.PrivateKey", resolved_path.data());
        return false;
    }
    if (!ctx.saw_public_key) {
        logger::Log("Config '%s' is missing Peer.PublicKey", resolved_path.data());
        return false;
    }
    if (!ctx.saw_allowed_ips) {
        logger::Log("Config '%s' is missing Peer.AllowedIPs", resolved_path.data());
        return false;
    }
    if (!ctx.saw_endpoint) {
        logger::Log("Config '%s' is missing Peer.Endpoint", resolved_path.data());
        return false;
    }

    std::snprintf(out->name.data(), out->name.size(), "%s", candidate.peer_name);
    logger::Log(
        "Loaded connection '%s' from '%s'",
        out->name.data(),
        resolved_path.data());
    return true;
}

} // namespace

bool LoadPeerConfig(wgnx::PeerConfigSet *out) {
    if (out == nullptr) {
        return false;
    }

    *out = {};
    const ams::Result ensure_rc = fs_runtime::EnsureReady();
    if (R_FAILED(ensure_rc)) {
        logger::Log("Filesystem runtime could not be initialized: rc=0x%08x", static_cast<u32>(ensure_rc.GetValue()));
        return false;
    }

    std::array<char, MaxResolvedPathBytes> config_dir_path = {};
    const ams::Result resolve_rc = fs_runtime::ResolveSdPath(config_dir_path, wgnx::ConfigPath);
    if (R_FAILED(resolve_rc)) {
        logger::Log("Config directory path '%s' is invalid: rc=0x%08x", wgnx::ConfigPath, static_cast<u32>(resolve_rc.GetValue()));
        return false;
    }

    ams::fs::DirectoryHandle dir;
    const ams::Result open_rc = ams::fs::OpenDirectory(std::addressof(dir), config_dir_path.data(), ams::fs::OpenDirectoryMode_All);
    if (R_FAILED(open_rc)) {
        if (ams::fs::ResultPathNotFound::Includes(open_rc)) {
            logger::Log("Config directory '%s' does not exist; no peers configured", wgnx::ConfigPath);
            return true;
        }

        logger::Log("Config directory '%s' could not be opened: rc=0x%08x", config_dir_path.data(), static_cast<u32>(open_rc.GetValue()));
        return false;
    }
    ON_SCOPE_EXIT { ams::fs::CloseDirectory(dir); };

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
        if (candidate_count >= g_candidates.size()) {
            ++skipped_count;
            logger::Log("Skipping extra config '%s': max peer count is %zu", entry.name, g_candidates.size());
            continue;
        }

        auto &candidate = g_candidates[candidate_count];
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
            if (std::strcmp(g_candidates[j].file_name, g_candidates[i].file_name) < 0) {
                const auto tmp = g_candidates[i];
                g_candidates[i] = g_candidates[j];
                g_candidates[j] = tmp;
            }
        }
    }

    for (std::size_t i = 0; i < candidate_count; ++i) {
        wgnx::PeerConfigEntry entry{};
        if (!LoadConnectionFile(std::addressof(entry), g_candidates[i])) {
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
    const ams::Result rc = fs_runtime::ReadTextFile(wgnx::AutoStartPath, buffer, &size);
    if (R_FAILED(rc)) {
        if (!ams::fs::ResultPathNotFound::Includes(rc)) {
            logger::Log("Autostart file '%s' could not be read: rc=0x%08x", wgnx::AutoStartPath, static_cast<u32>(rc.GetValue()));
        }
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

ams::Result StoreAutoStartPeerName(const char *name) {
    R_TRY(fs_runtime::EnsureDirectoryExists("/config"));
    R_TRY(fs_runtime::EnsureDirectoryExists(wgnx::ConfigPath));

    if (name == nullptr || name[0] == '\0') {
        R_TRY(fs_runtime::DeleteFileIfExists(wgnx::AutoStartPath));
        logger::Log("Cleared autostart peer");
        R_SUCCEED();
    }

    const std::size_t length = std::strlen(name);
    R_UNLESS(length < sizeof(wgnx::PeerInfo::name), ams::fs::ResultTooLongPath());
    R_TRY(fs_runtime::WriteTextFile(wgnx::AutoStartPath, std::string_view{name, length}));
    logger::Log("Stored autostart peer '%s'", name);
    R_SUCCEED();
}

} // namespace wgnx::sysmodule
