#pragma once

namespace wgnx::test {

class TestContext;

void TestDeterministicHandshake(TestContext &context);
void TestBidirectionalTransport(TestContext &context);
void TestTimerIntent(TestContext &context);
void TestTypedMessageBoundaries(TestContext &context);
void TestKeypairLifetime(TestContext &context);
void TestBoundedQueueObservability(TestContext &context);
void TestKeypairProtocolLimits(TestContext &context);
void TestOutboundStagingLifecycle(TestContext &context);

} // namespace wgnx::test
