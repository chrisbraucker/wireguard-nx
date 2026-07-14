#pragma once

namespace wgnx::test {

class TestContext;

void TestDeterministicHandshake(TestContext &context);
void TestBidirectionalTransport(TestContext &context);
void TestTimerIntent(TestContext &context);

} // namespace wgnx::test
