#pragma once

namespace wgnx::test {

class TestContext;

void TestUdpReceiveClassification(TestContext& context);
void TestNetworkPathClassification(TestContext& context);
void TestWorkqueueAdmission(TestContext& context);
void TestResolverSerialization(TestContext& context);

} // namespace wgnx::test
