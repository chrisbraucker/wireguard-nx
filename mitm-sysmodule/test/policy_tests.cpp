#include "mitm_policy.hpp"
#include "tunnel_discovery_tests.hpp"

#include <cstdio>

namespace {

bool Check(bool condition, const char* detail) {
    if (condition) {
        return true;
    }

    std::fprintf(stderr, "check failed: %s\n", detail);
    return false;
}

} // namespace

int main() {
    using namespace wgnx::mitm;

    BsdSystemPolicy disabled{};
    BsdSystemPolicy enabled{};
    enabled.enabled = true;

    BsdSystemPolicy requester_only{.enabled = true};
    const bool requester_enabled = SetBsdSystemClientEnabled(requester_only, BsdSystemClient::RequesterForwarder, true);

    BsdSystemPolicy configurable_clients{.enabled = true};
    bool all_configurable_clients_are_individually_toggleable = true;
    for (std::uint32_t client = static_cast<std::uint32_t>(BsdSystemClient::Npns);
         client <= static_cast<std::uint32_t>(BsdSystemClient::RequesterForwarder); ++client) {
        const auto system_client = static_cast<BsdSystemClient>(client);
        all_configurable_clients_are_individually_toggleable =
            all_configurable_clients_are_individually_toggleable && SetBsdSystemClientEnabled(configurable_clients, system_client, true) &&
            ShouldInterceptBsdSystem(configurable_clients, 0x0100000000001234ULL, system_client) &&
            SetBsdSystemClientEnabled(configurable_clients, system_client, false) &&
            !ShouldInterceptBsdSystem(configurable_clients, 0x0100000000001234ULL, system_client);
    }

    const bool passed =
        Check(!ShouldInterceptBsdSystem(disabled, 0x0100000000001234ULL, BsdSystemClient::Unknown), "disabled policy admitted a client") &&
        Check(!ShouldInterceptBsdSystem(enabled, WireGuardProgramId, BsdSystemClient::Unknown), "WireGuard process was not excluded") &&
        Check(!ShouldInterceptBsdSystem(enabled, MitmProgramId, BsdSystemClient::Unknown), "MITM process was not excluded") &&
        Check(!ShouldInterceptBsdSystem(enabled, 0x0100000000001234ULL, BsdSystemClient::Nim), "denylisted system client was admitted") &&
        Check(requester_enabled && ShouldInterceptBsdSystem(requester_only, 0x05720820ABC97000ULL, BsdSystemClient::RequesterForwarder),
              "enabled requester forwarder was rejected") &&
        Check(all_configurable_clients_are_individually_toggleable, "system-client policy flags were not independently toggleable") &&
        Check(!SetBsdSystemClientEnabled(requester_only, BsdSystemClient::Unknown, true), "unknown system client was configurable") &&
        Check(!IsConfigurableBsdSystemClient(99), "out-of-range system client was configurable") &&
        Check(ShouldInterceptBsdSystem(enabled, 0x0100000000001234ULL, BsdSystemClient::Unknown), "ordinary client was rejected") &&
        Check(RunTunnelDiscoveryTests(), "tunnel discovery state machine failed");

    std::printf("RESULT passed=%u\n", static_cast<unsigned>(passed));
    return passed ? 0 : 1;
}
