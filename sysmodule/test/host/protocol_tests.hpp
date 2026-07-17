#pragma once

namespace wgnx::test {

class TestContext;

void TestDeterministicHandshake(TestContext &context);
void TestHandshakeInitiationAdmission(TestContext &context);
void TestBidirectionalTransport(TestContext &context);
void TestTimerIntent(TestContext &context);
void TestTypedMessageBoundaries(TestContext &context);
void TestPrivateKeyParsing(TestContext &context);
void TestKeypairLifetime(TestContext &context);
void TestBoundedQueueObservability(TestContext &context);
void TestPacketChannelOwnership(TestContext &context);
void TestPacketDataPlane(TestContext &context);
void TestRuntimeContracts(TestContext &context);
void TestPeerRegistryOwnership(TestContext &context);
void TestPeerRuntimeLifecycle(TestContext &context);
void TestRuntimeCoordinatorDispatch(TestContext &context);
void TestRuntimePeerActivation(TestContext &context);
void TestRuntimeOutboundLifecycle(TestContext &context);
void TestReplayWindowParity(TestContext &context);
void TestTimerCoordinator(TestContext &context);
void TestTimerSchedule(TestContext &context);
void TestPeerControllerSendPolicy(TestContext &context);
void TestPeerControllerRecoveryWorkflow(TestContext &context);
void TestKeypairProtocolLimits(TestContext &context);
void TestOutboundStagingLifecycle(TestContext &context);
void TestHandshakeRetryLifecycle(TestContext &context);

} // namespace wgnx::test
