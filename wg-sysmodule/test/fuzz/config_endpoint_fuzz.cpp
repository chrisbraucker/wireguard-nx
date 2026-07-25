#include "config_text_validation.hpp"
#include "platform/endpoint_parser.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > 16 * 1024) {
        return 0;
    }

    const std::string_view input{reinterpret_cast<const char*>(data), size};
    static_cast<void>(wgnx::sysmodule::ValidateConnectionConfigLayout(input));

    wgnx::platform::EndpointTextParts endpoint{};
    if (wgnx::platform::ParseEndpointText(input, &endpoint)) {
        static_cast<void>(wgnx::platform::ParseEndpointPort(endpoint.service.data()));
    }
    return 0;
}
