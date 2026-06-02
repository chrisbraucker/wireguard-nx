#pragma once

#include <array>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string_view>

#include "wgnx/protocol.hpp"

namespace wgnx {

struct PeerConfigEntry {
    char name[sizeof(PeerInfo::name)];
    char address[sizeof(PeerInfo::address)];
    char endpoint[sizeof(PeerInfo::endpoint)];
};

struct PeerConfigSet {
    std::array<PeerConfigEntry, MaxPeers> peers{};
    std::size_t peer_count{0};
};

struct ConfigParseError {
    std::size_t line{0};
    char message[96]{};
};

namespace config {

namespace impl {

enum class Section {
    None,
    Interface,
    Peer,
};

inline std::string_view Trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.front() == '\r')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
        value.remove_suffix(1);
    }
    return value;
}

inline std::string_view StripInlineComment(std::string_view value) {
    const std::size_t hash = value.find('#');
    const std::size_t semicolon = value.find(';');

    std::size_t pos = std::string_view::npos;
    if (hash != std::string_view::npos) {
        pos = hash;
    }
    if (semicolon != std::string_view::npos && (pos == std::string_view::npos || semicolon < pos)) {
        pos = semicolon;
    }

    if (pos != std::string_view::npos) {
        value = value.substr(0, pos);
    }

    return Trim(value);
}

inline bool Equals(std::string_view lhs, std::string_view rhs) {
    return lhs == rhs;
}

inline void SetError(ConfigParseError *error, std::size_t line, const char *message) {
    if (error == nullptr) {
        return;
    }

    error->line = line;
    std::snprintf(error->message, sizeof(error->message), "%s", message);
}

template<std::size_t Size>
inline bool CopyField(char (&dst)[Size], std::string_view value, ConfigParseError *error, std::size_t line, const char *field_name) {
    if (value.size() >= Size) {
        char message[sizeof(ConfigParseError::message)] = {};
        std::snprintf(message, sizeof(message), "%s is too long", field_name);
        SetError(error, line, message);
        return false;
    }

    std::memcpy(dst, value.data(), value.size());
    dst[value.size()] = '\0';
    return true;
}

inline bool IsKnownInterfaceKey(std::string_view key) {
    return Equals(key, "Address") ||
           Equals(key, "PrivateKey") ||
           Equals(key, "ListenPort") ||
           Equals(key, "DNS") ||
           Equals(key, "MTU") ||
           Equals(key, "Table") ||
           Equals(key, "PreUp") ||
           Equals(key, "PostUp") ||
           Equals(key, "PreDown") ||
           Equals(key, "PostDown") ||
           Equals(key, "SaveConfig") ||
           Equals(key, "FwMark");
}

inline bool IsKnownPeerKey(std::string_view key) {
    return Equals(key, "PublicKey") ||
           Equals(key, "PresharedKey") ||
           Equals(key, "AllowedIPs") ||
           Equals(key, "Endpoint") ||
           Equals(key, "PersistentKeepalive");
}

} // namespace impl

inline bool ParseConnectionConfig(PeerConfigEntry *out, std::string_view text, ConfigParseError *error) {
    if (out == nullptr) {
        impl::SetError(error, 0, "output buffer is null");
        return false;
    }

    *out = {};
    if (error != nullptr) {
        *error = {};
    }

    impl::Section section = impl::Section::None;
    bool saw_interface = false;
    bool saw_peer = false;
    bool saw_address = false;
    bool saw_endpoint = false;
    bool saw_multiple_peers = false;
    std::size_t line_number = 0;
    std::size_t offset = 0;

    while (offset <= text.size()) {
        const std::size_t line_end = text.find('\n', offset);
        std::string_view line = line_end == std::string_view::npos ? text.substr(offset) : text.substr(offset, line_end - offset);
        offset = line_end == std::string_view::npos ? text.size() + 1 : line_end + 1;
        ++line_number;

        line = impl::Trim(line);
        if (line.empty() || line.front() == '#' || line.front() == ';') {
            continue;
        }

        if (line.front() == '[') {
            const std::size_t close = line.find(']');
            if (close == std::string_view::npos) {
                impl::SetError(error, line_number, "section header is missing ']'");
                return false;
            }

            const std::string_view section_name = impl::Trim(line.substr(1, close - 1));
            const std::string_view trailing = impl::Trim(line.substr(close + 1));
            if (!trailing.empty()) {
                impl::SetError(error, line_number, "unexpected text after section header");
                return false;
            }

            if (impl::Equals(section_name, "Interface")) {
                section = impl::Section::Interface;
                saw_interface = true;
                continue;
            }

            if (impl::Equals(section_name, "Peer")) {
                if (saw_peer) {
                    saw_multiple_peers = true;
                }
                section = impl::Section::Peer;
                saw_peer = true;
                continue;
            }

            impl::SetError(error, line_number, "unsupported section");
            return false;
        }

        if (section == impl::Section::None) {
            impl::SetError(error, line_number, "key-value pair appears before any section");
            return false;
        }

        const std::size_t equals = line.find('=');
        if (equals == std::string_view::npos) {
            impl::SetError(error, line_number, "expected key=value");
            return false;
        }

        const std::string_view key = impl::Trim(line.substr(0, equals));
        const std::string_view value = impl::StripInlineComment(line.substr(equals + 1));
        if (key.empty()) {
            impl::SetError(error, line_number, "key is empty");
            return false;
        }

        if (section == impl::Section::Interface) {
            if (!impl::IsKnownInterfaceKey(key)) {
                impl::SetError(error, line_number, "unsupported [Interface] key");
                return false;
            }

            if (impl::Equals(key, "Address")) {
                if (!impl::CopyField(out->address, value, error, line_number, "Address")) {
                    return false;
                }
                saw_address = true;
            }
            continue;
        }

        if (!impl::IsKnownPeerKey(key)) {
            impl::SetError(error, line_number, "unsupported [Peer] key");
            return false;
        }

        if (impl::Equals(key, "Endpoint")) {
            if (!impl::CopyField(out->endpoint, value, error, line_number, "Endpoint")) {
                return false;
            }
            saw_endpoint = true;
        }
    }

    if (!saw_interface) {
        impl::SetError(error, 0, "missing [Interface] section");
        return false;
    }
    if (!saw_peer) {
        impl::SetError(error, 0, "missing [Peer] section");
        return false;
    }
    if (saw_multiple_peers) {
        impl::SetError(error, 0, "multiple [Peer] sections are not supported yet");
        return false;
    }
    if (!saw_address) {
        impl::SetError(error, 0, "missing Interface.Address");
        return false;
    }
    if (!saw_endpoint) {
        impl::SetError(error, 0, "missing Peer.Endpoint");
        return false;
    }

    return true;
}

} // namespace config

} // namespace wgnx
