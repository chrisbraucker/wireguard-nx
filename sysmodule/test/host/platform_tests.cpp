#include "platform_tests.hpp"

#include "test_framework.hpp"
#include "wgnx/platform/udp.hpp"
#include "wgnx/platform/work.hpp"

#include <array>
#include <cstdint>

namespace wgnx::test {

void TestUdpReceiveClassification(TestContext &context) {
    using namespace wgnx::platform;

    endpoint source{
        .family = address_family::inet,
        .port = 51820,
        .address = {10, 13, 13, 1},
    };
    const auto datagram = classify_udp_receive_result(
        32,
        udp_receive_native_condition::none,
        0,
        source);
    WGNX_TEST_REQUIRE(
        context,
        datagram.disposition == udp_receive_disposition::datagram &&
            datagram.bytes_received == 32 &&
            datagram.source.family == address_family::inet &&
            datagram.source.port == 51820 &&
            datagram.source.address[0] == 10 &&
            datagram.source.address[1] == 13 &&
            datagram.source.address[2] == 13 &&
            datagram.source.address[3] == 1 &&
            datagram.error == socket_error::none &&
            datagram.native_result == 32 &&
            datagram.native_error == 0,
        "successful receive did not preserve datagram facts");

    const auto empty_datagram = classify_udp_receive_result(
        0,
        udp_receive_native_condition::none,
        0,
        source);
    WGNX_TEST_REQUIRE(
        context,
        empty_datagram.disposition == udp_receive_disposition::datagram &&
            empty_datagram.bytes_received == 0 &&
            empty_datagram.source.port == 51820 &&
            empty_datagram.error == socket_error::none,
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
        const auto retry = classify_udp_receive_result(
            -1,
            RetryConditions[index],
            NativeErrors[index],
            source);
        WGNX_TEST_REQUIRE(
            context,
            retry.disposition == udp_receive_disposition::retry &&
                retry.retry_reason ==
                    udp_receive_retry_reason::native_transient &&
                retry.native_condition == RetryConditions[index] &&
                retry.bytes_received == 0 &&
                retry.source.family == address_family::unspecified &&
                retry.error == socket_error::none &&
                retry.native_result == -1 &&
                retry.native_error == NativeErrors[index] &&
                !udp_receive_retry_requires_pacing(retry),
            "retryable receive did not preserve its closed outcome");
    }

    const auto missing_errno = classify_udp_receive_result(
        -1,
        udp_receive_native_condition::none,
        0,
        source);
    WGNX_TEST_REQUIRE(
        context,
        missing_errno.disposition == udp_receive_disposition::retry &&
            missing_errno.retry_reason ==
                udp_receive_retry_reason::missing_native_error &&
            missing_errno.native_condition == udp_receive_native_condition::none &&
            missing_errno.bytes_received == 0 &&
            missing_errno.source.family == address_family::unspecified &&
            missing_errno.error == socket_error::none &&
            missing_errno.native_result == -1 &&
            missing_errno.native_error == 0 &&
            udp_receive_retry_requires_pacing(missing_errno),
        "negative receive without a native error did not become a paced retry");

    const auto failure = classify_udp_receive_result(
        -1,
        udp_receive_native_condition::other,
        54,
        source);
    WGNX_TEST_REQUIRE(
        context,
        failure.disposition == udp_receive_disposition::failure &&
            failure.retry_reason == udp_receive_retry_reason::none &&
            failure.native_condition == udp_receive_native_condition::other &&
            failure.bytes_received == 0 &&
            failure.source.family == address_family::unspecified &&
            failure.error == socket_error::receive_failed &&
            failure.native_result == -1 &&
            failure.native_error == 54,
        "terminal receive did not preserve failure diagnostics");
}

void TestWorkqueueAdmission(TestContext &context) {
    using wgnx::platform::classify_queue_work_request;
    using wgnx::platform::queue_work_result;

    WGNX_TEST_REQUIRE(
        context,
        classify_queue_work_request(true, false, false, 0, 1) ==
            queue_work_result::queued &&
        classify_queue_work_request(true, false, true, 0, 1) ==
            queue_work_result::rerun_queued &&
        classify_queue_work_request(true, true, false, 1, 1) ==
            queue_work_result::already_pending &&
        classify_queue_work_request(true, false, false, 1, 1) ==
            queue_work_result::capacity_exhausted &&
        classify_queue_work_request(false, false, false, 0, 1) ==
            queue_work_result::unavailable &&
        classify_queue_work_request(true, false, false, 0, 0) ==
            queue_work_result::unavailable,
        "ordered workqueue admission did not expose its closed pressure outcomes");
}

} // namespace wgnx::test
