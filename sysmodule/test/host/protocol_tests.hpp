#pragma once

namespace wgnx::test {

class TestContext;

void TestDeterministicHandshake(TestContext &context);
void TestBidirectionalTransport(TestContext &context);
void TestTimerIntent(TestContext &context);
void TestTypedMessageBoundaries(TestContext &context);
void TestPrivateKeyParsing(TestContext &context);
void TestKeypairLifetime(TestContext &context);
void TestBoundedQueueObservability(TestContext &context);
void TestReplayWindowParity(TestContext &context);
void TestTimerCoordinator(TestContext &context);
void TestPeerControllerSendPolicy(TestContext &context);
void TestKeypairProtocolLimits(TestContext &context);
void TestOutboundStagingLifecycle(TestContext &context);
void TestHandshakeRetryLifecycle(TestContext &context);

} // namespace wgnx::test
