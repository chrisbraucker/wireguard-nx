#include "legacy_self_tests.hpp"

#include "protocol_tests.hpp"
#include "test_framework.hpp"

#include <array>

int main() {
    using wgnx::test::TestCase;

    const std::array tests = {
        TestCase{"legacy.message-boundaries", [](wgnx::test::TestContext &context) {
            WGNX_TEST_CHECK(context, wgnx::wireguard::RunMessageSelfTest());
        }},
        TestCase{"legacy.crypto-smoke", [](wgnx::test::TestContext &context) {
            WGNX_TEST_CHECK(context, wgnx::wireguard::RunPrimitiveSelfTest());
        }},
        TestCase{"legacy.core-smoke", [](wgnx::test::TestContext &context) {
            WGNX_TEST_CHECK(context, wgnx::wireguard::RunCoreSelfTest());
        }},
        TestCase{"protocol.deterministic-handshake", wgnx::test::TestDeterministicHandshake},
        TestCase{"protocol.bidirectional-transport", wgnx::test::TestBidirectionalTransport},
        TestCase{"protocol.timer-intent", wgnx::test::TestTimerIntent},
    };

    return wgnx::test::RunTests(tests);
}
