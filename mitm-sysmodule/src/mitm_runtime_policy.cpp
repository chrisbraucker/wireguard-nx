#include "mitm_runtime_policy.hpp"

#include <atomic>

namespace wgnx::mitm {

namespace {

constinit std::atomic_bool g_bsd_system_policy_enabled = true;
constinit std::atomic_uint32_t g_enabled_bsd_system_client_mask = BsdSystemClientMask(BsdSystemClient::RequesterForwarder);

} // namespace

bool IsBsdSystemPolicyEnabled() {
    return g_bsd_system_policy_enabled.load(std::memory_order_acquire);
}

std::uint32_t GetEnabledBsdSystemClientMask() {
    return g_enabled_bsd_system_client_mask.load(std::memory_order_acquire);
}

bool IsRequesterBsdSystemInterceptionEnabled() {
    return IsBsdSystemPolicyEnabled() && (GetEnabledBsdSystemClientMask() & BsdSystemClientMask(BsdSystemClient::RequesterForwarder)) != 0;
}

void SetBsdSystemPolicyEnabledForRuntime(bool enabled) {
    g_bsd_system_policy_enabled.store(enabled, std::memory_order_release);
}

bool SetBsdSystemClientEnabledForRuntime(const BsdSystemClient client, const bool enabled) {
    const std::uint32_t mask = BsdSystemClientMask(client);
    if (mask == 0) {
        return false;
    }
    if (enabled) {
        g_enabled_bsd_system_client_mask.fetch_or(mask, std::memory_order_acq_rel);
    } else {
        g_enabled_bsd_system_client_mask.fetch_and(~mask, std::memory_order_acq_rel);
    }
    return true;
}

} // namespace wgnx::mitm
