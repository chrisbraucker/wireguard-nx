#include "platform_tests.hpp"

#include "test_framework.hpp"
#include "wgnx/platform/network_path.hpp"
#include "wgnx/platform/udp.hpp"
#include "wgnx/platform/work.hpp"
#include "platform/resolver_serialization.hpp"

#include <array>
#include <cstdint>

namespace wgnx::test {

void TestNetworkPathClassification(TestContext& context) {
    using namespace wgnx::platform;

    WGNX_TEST_REQUIRE(context,
                      classify_network_path_state(network_path_raw_state::available) == network_path_availability::available &&
                          classify_network_path_state(network_path_raw_state::on_hold) == network_path_availability::unavailable &&
                          classify_network_path_state(network_path_raw_state::pending) == network_path_availability::unavailable &&
                          classify_network_path_state(network_path_raw_state::invalid) == network_path_availability::unknown &&
                          classify_network_path_state(network_path_raw_state::unknown4) == network_path_availability::unknown &&
                          classify_network_path_state(network_path_raw_state::unknown5) == network_path_availability::unknown &&
                          classify_network_path_state(network_path_raw_state::available, 1) == network_path_availability::unknown,
                      "NIFM request states did not preserve the local-path authority model");
}

void TestUdpReceiveClassification(TestContext& context) {
    using namespace wgnx::platform;

    endpoint source{
        .family = address_family::inet,
        .port = 51820,
        .address = {10, 13, 13, 1},
    };
    const auto datagram = classify_udp_receive_result(32, udp_receive_native_condition::none, 0, source);
    WGNX_TEST_REQUIRE(context,
                      datagram.disposition == udp_receive_disposition::datagram && datagram.bytes_received == 32 &&
                          datagram.source.family == address_family::inet && datagram.source.port == 51820 &&
                          datagram.source.address[0] == 10 && datagram.source.address[1] == 13 && datagram.source.address[2] == 13 &&
                          datagram.source.address[3] == 1 && datagram.error == socket_error::none && datagram.native_result == 32 &&
                          datagram.native_error == 0,
                      "successful receive did not preserve datagram facts");

    const auto empty_datagram = classify_udp_receive_result(0, udp_receive_native_condition::none, 0, source);
    WGNX_TEST_REQUIRE(context,
                      empty_datagram.disposition == udp_receive_disposition::datagram && empty_datagram.bytes_received == 0 &&
                          empty_datagram.source.port == 51820 && empty_datagram.error == socket_error::none,
                      "zero-length UDP datagram was conflated with a retry");

    constexpr std::array RetryConditions{
        udp_receive_native_condition::would_block,
        udp_receive_native_condition::timed_out,
        udp_receive_native_condition::interrupted,
    };
    constexpr std::array<std::uint32_t, RetryConditions.size()> NativeErrors{
        11,
        60,
        4,
    };
    for (std::size_t index = 0; index < RetryConditions.size(); ++index) {
        const auto retry = classify_udp_receive_result(-1, RetryConditions[index], NativeErrors[index], source);
        WGNX_TEST_REQUIRE(
            context,
            retry.disposition == udp_receive_disposition::retry && retry.retry_reason == udp_receive_retry_reason::native_transient &&
                retry.native_condition == RetryConditions[index] && retry.bytes_received == 0 &&
                retry.source.family == address_family::unspecified && retry.error == socket_error::none && retry.native_result == -1 &&
                retry.native_error == NativeErrors[index] && !udp_receive_retry_requires_pacing(retry),
            "retryable receive did not preserve its closed outcome");
    }

    const auto missing_errno = classify_udp_receive_result(-1, udp_receive_native_condition::none, 0, source);
    WGNX_TEST_REQUIRE(context,
                      missing_errno.disposition == udp_receive_disposition::retry &&
                          missing_errno.retry_reason == udp_receive_retry_reason::missing_native_error &&
                          missing_errno.native_condition == udp_receive_native_condition::none && missing_errno.bytes_received == 0 &&
                          missing_errno.source.family == address_family::unspecified && missing_errno.error == socket_error::none &&
                          missing_errno.native_result == -1 && missing_errno.native_error == 0 &&
                          udp_receive_retry_requires_pacing(missing_errno),
                      "negative receive without a native error did not become a paced retry");

    const auto failure = classify_udp_receive_result(-1, udp_receive_native_condition::other, 54, source);
    WGNX_TEST_REQUIRE(context,
                      failure.disposition == udp_receive_disposition::failure && failure.retry_reason == udp_receive_retry_reason::none &&
                          failure.native_condition == udp_receive_native_condition::other && failure.bytes_received == 0 &&
                          failure.source.family == address_family::unspecified && failure.error == socket_error::receive_failed &&
                          failure.native_result == -1 && failure.native_error == 54,
                      "terminal receive did not preserve failure diagnostics");
}

void TestWorkqueueAdmission(TestContext& context) {
    using wgnx::platform::classify_queue_work_request;
    using wgnx::platform::queue_work_result;

    WGNX_TEST_REQUIRE(context,
                      classify_queue_work_request(true, false, false, 0, 1) == queue_work_result::queued &&
                          classify_queue_work_request(true, false, true, 0, 1) == queue_work_result::rerun_queued &&
                          classify_queue_work_request(true, true, false, 1, 1) == queue_work_result::already_pending &&
                          classify_queue_work_request(true, false, false, 1, 1) == queue_work_result::capacity_exhausted &&
                          classify_queue_work_request(false, false, false, 0, 1) == queue_work_result::unavailable &&
                          classify_queue_work_request(true, false, false, 0, 0) == queue_work_result::unavailable,
                      "ordered workqueue admission did not expose its closed pressure outcomes");
}

void TestResolverSerialization(TestContext& context) {
    using namespace wgnx::platform;
    using namespace resolver_serialization;

    HorizonAddrInfoHints hints{};
    constexpr std::array<std::uint8_t, 33> expected_hints{
        0xbe, 0xef, 0xca, 0xfe, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };
    const bool hints_ok = serialize_horizon_addrinfo_hints(hints, 0x1, 0, 2, 17) && hints.size() == expected_hints.size() &&
                          std::equal(hints.begin(), hints.end(), expected_hints.begin());

    // One AF_INET record with a resolver-serialized BSD sockaddr_in.
    // The header is big-endian, while the embedded sockaddr has libnx's
    // documented recursive conversion: port is little-endian and IPv4 address
    // bytes are reversed from their canonical presentation order.
    constexpr std::array<std::uint8_t, 41> ipv4_record{
        0xbe, 0xef, 0xca, 0xfe, 0, 0,    0,    0, 0,   0, 0,   2, 0, 0, 0, 2, 0, 0, 0, 17, 0,
        0,    0,    16,   16,   2, 0x6c, 0xca, 7, 113, 0, 203, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };
    endpoint parsed{};
    const bool ipv4_ok = parse_horizon_addrinfo_result(ipv4_record, parsed) && parsed.family == address_family::inet &&
                         parsed.port == 51820 && parsed.address[0] == 203 && parsed.address[1] == 0 && parsed.address[2] == 113 &&
                         parsed.address[3] == 7;

    // The Horizon resolver can leave BSD sin_len at zero. libnx accepts this
    // shape and reconstructs the native sockaddr length from ai_addrlen.
    auto zero_length_ipv4_record = ipv4_record;
    zero_length_ipv4_record[24] = 0;
    const bool zero_length_ipv4_ok = parse_horizon_addrinfo_result(zero_length_ipv4_record, parsed) &&
                                     parsed.family == address_family::inet && parsed.port == 51820 && parsed.address[0] == 203 &&
                                     parsed.address[1] == 0 && parsed.address[2] == 113 && parsed.address[3] == 7;

    // One AF_INET6 record with BSD sockaddr_in6 (len, family, port, flow,
    // address, scope). This exercises the family-specific minimum length.
    constexpr std::array<std::uint8_t, 53> ipv6_record{
        0xbe, 0xef, 0xca, 0xfe, 0, 0,    0,    0,    0,    0, 0, 28, 0, 0, 0, 2, 0, 0, 0, 17, 0, 0, 0, 28, 28, 28, 0x6c,
        0xca, 0,    0,    0,    0, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,  1, 0, 0, 0,  0,  0,
    };
    const bool ipv6_ok = parse_horizon_addrinfo_result(ipv6_record, parsed) && parsed.family == address_family::inet6 &&
                         parsed.port == 51820 && parsed.address[0] == 0x20 && parsed.address[1] == 0x01 && parsed.address[2] == 0x0d &&
                         parsed.address[3] == 0xb8 && parsed.address[15] == 1;

    std::array<std::uint8_t, ipv4_record.size() + ipv6_record.size()> multi_record{};
    std::copy(ipv4_record.begin(), ipv4_record.end(), multi_record.begin());
    std::copy(ipv6_record.begin(), ipv6_record.end(), multi_record.begin() + ipv4_record.size());
    const bool multiple_records_ok = parse_horizon_addrinfo_result(multi_record, parsed) && parsed.family == address_family::inet &&
                                     parsed.port == 51820 && parsed.address[0] == 203 && parsed.address[3] == 7;

    std::array<std::uint8_t, ipv4_record.size() + AddrInfoListTerminatorWireSize> terminated_record{};
    std::copy(ipv4_record.begin(), ipv4_record.end(), terminated_record.begin());
    const bool terminator_ok = parse_horizon_addrinfo_result(terminated_record, parsed) && parsed.family == address_family::inet &&
                               parsed.port == 51820 && parsed.address[0] == 203 && parsed.address[3] == 7;

    auto malformed_length = ipv4_record;
    malformed_length[23] = 17;
    auto missing_terminator = ipv4_record;
    missing_terminator.back() = 1;
    auto malformed_family = ipv4_record;
    malformed_family[25] = 28;
    std::array<std::uint8_t, ipv4_record.size() + 1> malformed_trailing_record{};
    std::copy(ipv4_record.begin(), ipv4_record.end(), malformed_trailing_record.begin());
    malformed_trailing_record.back() = 0xff;
    const bool malformed_rejected =
        !parse_horizon_addrinfo_result(malformed_length, parsed) && !parse_horizon_addrinfo_result(missing_terminator, parsed) &&
        !parse_horizon_addrinfo_result(malformed_family, parsed) && !parse_horizon_addrinfo_result(malformed_trailing_record, parsed) &&
        !parse_horizon_addrinfo_result(std::span<const std::uint8_t>{ipv4_record}.first(12), parsed);

    WGNX_TEST_REQUIRE(context,
                      hints_ok && ipv4_ok && zero_length_ipv4_ok && ipv6_ok && multiple_records_ok && terminator_ok && malformed_rejected,
                      "resolver serialization did not preserve the documented Horizon ABI or reject malformed records");
}

} // namespace wgnx::test
