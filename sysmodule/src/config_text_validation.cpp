#include "config_text_validation.hpp"

namespace wgnx::sysmodule {

namespace {

std::string_view TrimConfigWhitespace(std::string_view value) {
    while (!value.empty() &&
           (value.front() == ' ' || value.front() == '\t' || value.front() == '\r')) {
        value.remove_prefix(1);
    }
    while (!value.empty() &&
           (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
        value.remove_suffix(1);
    }
    return value;
}

} // namespace

ConfigLayoutValidation ValidateConnectionConfigLayout(std::string_view text) {
    std::size_t interface_sections = 0;
    std::size_t peer_sections = 0;
    std::size_t line_number = 0;
    std::string_view remaining = text;

    while (true) {
        const std::size_t line_end = remaining.find('\n');
        std::string_view line =
            line_end == std::string_view::npos ? remaining : remaining.substr(0, line_end);
        remaining = line_end == std::string_view::npos
                        ? std::string_view{}
                        : remaining.substr(line_end + 1);
        ++line_number;

        line = TrimConfigWhitespace(line);
        if (!line.empty() && line.front() == '[') {
            const std::size_t close = line.find(']');
            if (close == std::string_view::npos) {
                return {
                    .error = ConfigLayoutError::MissingSectionTerminator,
                    .line = line_number,
                };
            }

            const std::string_view section_name =
                TrimConfigWhitespace(line.substr(1, close - 1));
            if (section_name == "Interface") {
                ++interface_sections;
                if (interface_sections > 1) {
                    return {
                        .error = ConfigLayoutError::MultipleInterfaceSections,
                        .line = line_number,
                    };
                }
            } else if (section_name == "Peer") {
                ++peer_sections;
                if (peer_sections > 1) {
                    return {
                        .error = ConfigLayoutError::MultiplePeerSections,
                        .line = line_number,
                    };
                }
            }
        }

        if (line_end == std::string_view::npos) {
            break;
        }
    }

    if (interface_sections == 0) {
        return {.error = ConfigLayoutError::MissingInterfaceSection};
    }
    if (peer_sections == 0) {
        return {.error = ConfigLayoutError::MissingPeerSection};
    }
    return {};
}

const char *GetConfigLayoutErrorMessage(ConfigLayoutError error) {
    switch (error) {
        case ConfigLayoutError::None: return "none";
        case ConfigLayoutError::MissingSectionTerminator:
            return "section header is missing ']'";
        case ConfigLayoutError::MultipleInterfaceSections:
            return "multiple [Interface] sections are not supported";
        case ConfigLayoutError::MultiplePeerSections:
            return "multiple [Peer] sections are not supported";
        case ConfigLayoutError::MissingInterfaceSection:
            return "missing [Interface] section";
        case ConfigLayoutError::MissingPeerSection:
            return "missing [Peer] section";
    }
    return "unknown config layout error";
}

} // namespace wgnx::sysmodule
