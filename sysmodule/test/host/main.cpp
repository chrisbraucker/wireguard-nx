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
        TestCase{"protocol.typed-message-boundaries", wgnx::test::TestTypedMessageBoundaries},
        TestCase{"protocol.private-key-parsing", wgnx::test::TestPrivateKeyParsing},
        TestCase{"protocol.keypair-lifetime", wgnx::test::TestKeypairLifetime},
        TestCase{"protocol.bounded-queue-observability", wgnx::test::TestBoundedQueueObservability},
        TestCase{"runtime.packet-channel-ownership", wgnx::test::TestPacketChannelOwnership},
        TestCase{"runtime.frozen-contracts", wgnx::test::TestRuntimeContracts},
        TestCase{"runtime.peer-registry-ownership", wgnx::test::TestPeerRegistryOwnership},
        TestCase{"runtime.peer-lifecycle", wgnx::test::TestPeerRuntimeLifecycle},
        TestCase{"runtime.coordinator-dispatch", wgnx::test::TestRuntimeCoordinatorDispatch},
        TestCase{"runtime.peer-activation", wgnx::test::TestRuntimePeerActivation},
        TestCase{"runtime.outbound-lifecycle", wgnx::test::TestRuntimeOutboundLifecycle},
        TestCase{"protocol.replay-window-parity", wgnx::test::TestReplayWindowParity},
        TestCase{"runtime.timer-coordinator", wgnx::test::TestTimerCoordinator},
        TestCase{"runtime.peer-controller-send-policy", wgnx::test::TestPeerControllerSendPolicy},
        TestCase{"runtime.peer-controller-recovery-workflow", wgnx::test::TestPeerControllerRecoveryWorkflow},
        TestCase{"protocol.keypair-protocol-limits", wgnx::test::TestKeypairProtocolLimits},
        TestCase{"protocol.outbound-staging-lifecycle", wgnx::test::TestOutboundStagingLifecycle},
        TestCase{"protocol.handshake-retry-lifecycle", wgnx::test::TestHandshakeRetryLifecycle},
    };

    return wgnx::test::RunTests(tests);
}
