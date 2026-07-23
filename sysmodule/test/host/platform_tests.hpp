#pragma once

namespace wgnx::test {

class TestContext;

void TestUdpReceiveClassification(TestContext &context);
void TestNetworkPathClassification(TestContext &context);
void TestWorkqueueAdmission(TestContext &context);

} // namespace wgnx::test
