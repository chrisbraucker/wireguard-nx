#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace wgnx::sysmodule {

enum class ConfigLayoutError : std::uint8_t {
    None = 0,
    MissingSectionTerminator,
    MultipleInterfaceSections,
    MultiplePeerSections,
    MissingInterfaceSection,
    MissingPeerSection,
};

struct ConfigLayoutValidation {
    ConfigLayoutError error{ConfigLayoutError::None};
    std::size_t line{0};

    [[nodiscard]] constexpr bool IsValid() const {
        return error == ConfigLayoutError::None;
    }
};

ConfigLayoutValidation ValidateConnectionConfigLayout(std::string_view text);
const char* GetConfigLayoutErrorMessage(ConfigLayoutError error);

} // namespace wgnx::sysmodule
