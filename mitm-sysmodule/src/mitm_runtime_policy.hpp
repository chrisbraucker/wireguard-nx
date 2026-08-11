#pragma once

#include "mitm_policy.hpp"

#include <cstdint>

namespace wgnx::mitm {

// The development default enables only the requester-forwarder target.
// Changes apply to future bsd:s session admission and do not disrupt a live flow.
[[nodiscard]] bool IsBsdSystemPolicyEnabled();
[[nodiscard]] std::uint32_t GetEnabledBsdSystemClientMask();
[[nodiscard]] bool IsToolboxBsdSystemInterceptionEnabled();
void SetBsdSystemPolicyEnabledForRuntime(bool enabled);
[[nodiscard]] bool SetBsdSystemClientEnabledForRuntime(BsdSystemClient client, bool enabled);

} // namespace wgnx::mitm
