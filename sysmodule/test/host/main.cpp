#include "legacy_self_tests.hpp"

#include "platform_tests.hpp"
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
        TestCase{"platform.udp-receive-classification", wgnx::test::TestUdpReceiveClassification},
        TestCase{"platform.workqueue-admission", wgnx::test::TestWorkqueueAdmission},
        TestCase{"protocol.deterministic-handshake", wgnx::test::TestDeterministicHandshake},
        TestCase{"protocol.handshake-initiation-admission", wgnx::test::TestHandshakeInitiationAdmission},
        TestCase{"protocol.bidirectional-transport", wgnx::test::TestBidirectionalTransport},
        TestCase{"protocol.timer-intent", wgnx::test::TestTimerIntent},
        TestCase{"protocol.typed-message-boundaries", wgnx::test::TestTypedMessageBoundaries},
        TestCase{"protocol.private-key-parsing", wgnx::test::TestPrivateKeyParsing},
        TestCase{"protocol.keypair-lifetime", wgnx::test::TestKeypairLifetime},
        TestCase{"protocol.bounded-queue-observability", wgnx::test::TestBoundedQueueObservability},
        TestCase{"runtime.packet-channel-ownership", wgnx::test::TestPacketChannelOwnership},
        TestCase{"runtime.packet-data-plane", wgnx::test::TestPacketDataPlane},
        TestCase{"runtime.typed-rejections", wgnx::test::TestRuntimeTypedRejections},
        TestCase{"runtime.resource-budgets", wgnx::test::TestRuntimeResourceBudgets},
        TestCase{"runtime.auxiliary-workflows", wgnx::test::TestAuxiliaryRuntimeWorkflows},
        TestCase{"runtime.frozen-contracts", wgnx::test::TestRuntimeContracts},
        TestCase{"runtime.peer-registry-ownership", wgnx::test::TestPeerRegistryOwnership},
        TestCase{"runtime.peer-lifecycle", wgnx::test::TestPeerRuntimeLifecycle},
        TestCase{"runtime.coordinator-dispatch", wgnx::test::TestRuntimeCoordinatorDispatch},
        TestCase{"runtime.peer-activation", wgnx::test::TestRuntimePeerActivation},
        TestCase{"runtime.outbound-lifecycle", wgnx::test::TestRuntimeOutboundLifecycle},
        TestCase{"protocol.replay-window-parity", wgnx::test::TestReplayWindowParity},
        TestCase{"runtime.timer-coordinator", wgnx::test::TestTimerCoordinator},
        TestCase{"runtime.timer-schedule", wgnx::test::TestTimerSchedule},
        TestCase{"runtime.peer-controller-send-policy", wgnx::test::TestPeerControllerSendPolicy},
        TestCase{"runtime.peer-controller-recovery-workflow", wgnx::test::TestPeerControllerRecoveryWorkflow},
        TestCase{"protocol.keypair-protocol-limits", wgnx::test::TestKeypairProtocolLimits},
        TestCase{"protocol.outbound-staging-lifecycle", wgnx::test::TestOutboundStagingLifecycle},
        TestCase{"protocol.handshake-retry-lifecycle", wgnx::test::TestHandshakeRetryLifecycle},
        TestCase{"runtime.autostart-persistence-generation", wgnx::test::TestAutoStartPersistenceGeneration},
        TestCase{"runtime.udp-binding-ownership", wgnx::test::TestUdpBindingOwnership},
        TestCase{"runtime.composition-failure-injection", wgnx::test::TestRuntimeCompositionFailureInjection},
        TestCase{"runtime.scripted-platform-failure-coverage", wgnx::test::TestRuntimeScriptedPlatformFailureCoverage},
    };

    return wgnx::test::RunTests(tests);
}
