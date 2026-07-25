#pragma once

#include <stratosphere.hpp>

namespace wgnx::mitm {

struct MitmStatus {
    std::uint32_t api_version;
    std::uint32_t flags;
    std::uint32_t registered_mitm_servers;
    std::uint32_t enabled_bsd_system_client_mask;
};

} // namespace wgnx::mitm

#define WGNX_I_MITM_CONTROL_SERVICE_INTERFACE_INFO(C, H)                                                                                   \
    AMS_SF_METHOD_INFO(C, H, 0, ams::Result, GetStatus, (ams::sf::Out<wgnx::mitm::MitmStatus> out), (out), ams::hos::Version_Min,          \
                       ams::hos::Version_Max)                                                                                              \
    AMS_SF_METHOD_INFO(C, H, 1, ams::Result, SetBsdSystemPolicyEnabled, (bool enabled), (enabled), ams::hos::Version_Min,                  \
                       ams::hos::Version_Max)                                                                                              \
    AMS_SF_METHOD_INFO(C, H, 2, ams::Result, SetBsdSystemClientEnabled, (std::uint32_t client, bool enabled), (client, enabled),           \
                       ams::hos::Version_Min, ams::hos::Version_Max)

AMS_SF_DEFINE_INTERFACE(wgnx::mitm, IMitmControlService, WGNX_I_MITM_CONTROL_SERVICE_INTERFACE_INFO, 0x57474D43);

namespace wgnx::mitm {

constexpr inline std::uint32_t MitmControlApiVersion = 1;
constexpr inline std::uint32_t MitmStatusFlag_BsdSystemPolicyRequested = 1U << 0;
constexpr inline std::uint32_t MitmStatusFlag_BsdSystemInterceptionInstalled = 1U << 1;

class ControlService {
  public:
    ams::Result GetStatus(ams::sf::Out<MitmStatus> out);
    ams::Result SetBsdSystemPolicyEnabled(bool enabled);
    ams::Result SetBsdSystemClientEnabled(std::uint32_t client, bool enabled);
};

static_assert(IsIMitmControlService<ControlService>);

void RunControlServer();

} // namespace wgnx::mitm
