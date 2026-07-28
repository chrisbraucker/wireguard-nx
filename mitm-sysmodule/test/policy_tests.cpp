#include "bsd_endpoint.hpp"
#include "bsd_response.hpp"
#include "mitm_policy.hpp"
#include "tunnel_open_disposition.hpp"
#include "tunnel_discovery_tests.hpp"

#include <array>
#include <bit>
#include <cerrno>
#include <cstdio>

namespace {

bool Check(bool condition, const char* detail) {
    if (condition) {
        return true;
    }

    std::fprintf(stderr, "check failed: %s\n", detail);
    return false;
}

bool RunBsdEndpointTests() {
    using namespace wgnx::mitm;

    BsdSockAddrIn zero_initialized_requester_endpoint{};
    zero_initialized_requester_endpoint.length = 0;
    zero_initialized_requester_endpoint.family = BsdAddressFamilyInet;
    zero_initialized_requester_endpoint.port = StoreBigEndian16(29000);
    zero_initialized_requester_endpoint.address[0] = 10;
    zero_initialized_requester_endpoint.address[1] = 251;
    zero_initialized_requester_endpoint.address[2] = 0;
    zero_initialized_requester_endpoint.address[3] = 2;

    BsdIpv4Endpoint decoded{};
    const auto zero_length_input =
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(std::addressof(zero_initialized_requester_endpoint)),
                                      sizeof(zero_initialized_requester_endpoint)};
    const bool accepts_zero_initialized_requester_endpoint = DecodeBsdIpv4Endpoint(zero_length_input, std::addressof(decoded)) &&
                                                             decoded.address == std::array<std::uint8_t, 4>{10, 251, 0, 2} &&
                                                             decoded.port == 29000;

    BsdSockAddrIn explicit_length_endpoint = zero_initialized_requester_endpoint;
    explicit_length_endpoint.length = sizeof(explicit_length_endpoint);
    const auto explicit_length_input = std::span<const std::uint8_t>{
        reinterpret_cast<const std::uint8_t*>(std::addressof(explicit_length_endpoint)), sizeof(explicit_length_endpoint)};
    const bool accepts_explicit_length_endpoint = DecodeBsdIpv4Endpoint(explicit_length_input, std::addressof(decoded));

    BsdSockAddrIn malformed_length_endpoint = explicit_length_endpoint;
    malformed_length_endpoint.length = sizeof(malformed_length_endpoint) - 1;
    const auto malformed_length_input = std::span<const std::uint8_t>{
        reinterpret_cast<const std::uint8_t*>(std::addressof(malformed_length_endpoint)), sizeof(malformed_length_endpoint)};
    const bool rejects_short_nonzero_length = !DecodeBsdIpv4Endpoint(malformed_length_input, std::addressof(decoded));

    BsdSockAddrIn malformed_family_endpoint = explicit_length_endpoint;
    malformed_family_endpoint.family = 0;
    const auto malformed_family_input = std::span<const std::uint8_t>{
        reinterpret_cast<const std::uint8_t*>(std::addressof(malformed_family_endpoint)), sizeof(malformed_family_endpoint)};
    const bool rejects_non_ipv4_family = !DecodeBsdIpv4Endpoint(malformed_family_input, std::addressof(decoded));

    BsdSockAddrIn zero_port_endpoint = explicit_length_endpoint;
    zero_port_endpoint.port = 0;
    const auto zero_port_input = std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(std::addressof(zero_port_endpoint)),
                                                               sizeof(zero_port_endpoint)};
    const bool rejects_zero_port = !DecodeBsdIpv4Endpoint(zero_port_input, std::addressof(decoded));

    const auto short_input = std::span<const std::uint8_t>{zero_length_input.data(), zero_length_input.size() - 1};
    const bool rejects_short_buffer = !DecodeBsdIpv4Endpoint(short_input, std::addressof(decoded));

    std::array<std::uint8_t, sizeof(BsdSockAddrIn)> encoded{};
    const bool encodes_explicit_length = EncodeBsdIpv4Endpoint({.address = {10, 251, 0, 2}, .port = 29000}, encoded) &&
                                         encoded[0] == sizeof(BsdSockAddrIn) && encoded[1] == BsdAddressFamilyInet;

    return Check(accepts_zero_initialized_requester_endpoint, "zero-initialized libnx sockaddr_in was rejected") &&
           Check(accepts_explicit_length_endpoint, "explicit sockaddr_in length was rejected") &&
           Check(rejects_short_nonzero_length, "short nonzero sockaddr_in length was accepted") &&
           Check(rejects_non_ipv4_family, "non-IPv4 sockaddr_in family was accepted") &&
           Check(rejects_zero_port, "zero port was accepted") && Check(rejects_short_buffer, "short sockaddr_in buffer was accepted") &&
           Check(encodes_explicit_length, "encoded sockaddr_in did not set the required header fields");
}

bool RunBsdResponseLayoutTests() {
    using namespace wgnx::mitm;

    const auto success_words = std::bit_cast<std::array<std::int32_t, 2>>(BsdResultAndErrno{.result = 48, .error = 0});
    const auto failure_words = std::bit_cast<std::array<std::int32_t, 2>>(BsdResultAndErrno{.result = -1, .error = EAGAIN});
    const auto address_words =
        std::bit_cast<std::array<std::int32_t, 3>>(BsdResultAndAddressLength{.response = {.result = 0, .error = 0}, .address_size = 16});

    return Check(success_words == std::array<std::int32_t, 2>{48, 0}, "BSD success response did not encode result before errno") &&
           Check(failure_words == std::array<std::int32_t, 2>{-1, EAGAIN}, "BSD failure response did not encode result before errno") &&
           Check(address_words == std::array<std::int32_t, 3>{0, 0, 16},
                 "BSD address response did not encode result, errno, and address length in order");
}

bool RunTunnelOpenDispositionTests() {
    using namespace wgnx::mitm;
    using wgnx::tunnel::ProtocolStatus;

    return Check(ClassifyTunnelOpenStatus(ProtocolStatus::Success) == TunnelOpenDisposition::Tunnel,
                 "successful tunnel flow open was not classified as tunneled") &&
           Check(ClassifyTunnelOpenStatus(ProtocolStatus::RouteNotCovered) == TunnelOpenDisposition::Direct,
                 "uncovered route was not classified as direct") &&
           Check(ClassifyTunnelOpenStatus(ProtocolStatus::PeerUnavailable) == TunnelOpenDisposition::Direct &&
                     ClassifyTunnelOpenStatus(ProtocolStatus::TransportUnavailable) == TunnelOpenDisposition::Direct,
                 "temporary tunnel unavailability was not classified as direct") &&
           Check(ClassifyTunnelOpenStatus(ProtocolStatus::TunnelBlockedByPolicy) == TunnelOpenDisposition::Blocked,
                 "leak-protection block was not classified as blocked") &&
           Check(ClassifyTunnelOpenStatus(ProtocolStatus::QueueFull) == TunnelOpenDisposition::Error,
                 "unexpected tunnel status was not classified as an error");
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
        Check(IsRequesterForwarderProgram(RequesterForwarderProgramId), "requester forwarder title ID was not recognized") &&
        Check(!IsRequesterForwarderProgram(WireGuardProgramId), "WireGuard title ID was mistaken for requester") &&
        Check(ShouldInterceptRequesterBsdSession(), "requester BSD session was rejected") &&
        Check(requester_enabled &&
                  ShouldInterceptBsdSystem(requester_only, RequesterForwarderProgramId, BsdSystemClient::RequesterForwarder),
              "enabled requester forwarder was rejected") &&
        Check(all_configurable_clients_are_individually_toggleable, "system-client policy flags were not independently toggleable") &&
        Check(!SetBsdSystemClientEnabled(requester_only, BsdSystemClient::Unknown, true), "unknown system client was configurable") &&
        Check(!IsConfigurableBsdSystemClient(99), "out-of-range system client was configurable") &&
        Check(ShouldInterceptBsdSystem(enabled, 0x0100000000001234ULL, BsdSystemClient::Unknown), "ordinary client was rejected") &&
        Check(RunBsdEndpointTests(), "BSD IPv4 endpoint codec failed") &&
        Check(RunBsdResponseLayoutTests(), "BSD response layout failed") &&
        Check(RunTunnelOpenDispositionTests(), "tunnel open disposition mapping failed") &&
        Check(RunTunnelDiscoveryTests(), "tunnel discovery state machine failed");

    std::printf("RESULT passed=%u\n", static_cast<unsigned>(passed));
    return passed ? 0 : 1;
}
