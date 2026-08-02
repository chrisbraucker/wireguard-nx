#include "userspace_ip_adapter_owner_tests.hpp"

#include "runtime/userspace_ip_adapter_owner.hpp"
#include "test_framework.hpp"

#include <array>

namespace wgnx::test {

void TestUserspaceIpAdapterOwner(TestContext& context) {
    constexpr std::array<std::uint8_t, 4> Local = {10, 13, 13, 8};
    sysmodule::runtime::UserspaceIpAdapterOwner owner{};
    const std::uint32_t starts = sysmodule::ip::UserspaceIpAdapter::InitializationCountForTests();
    owner.QueueConfigure(Local, 1420);
    owner.QueueConfigure(Local, 576);
    WGNX_TEST_REQUIRE(
        context,
        owner.HasPendingWork() && sysmodule::ip::UserspaceIpAdapter::InitializationCountForTests() == starts,
        "adapter owner initialized lwIP outside its serialized work callback"
    );
    owner.Run();
    WGNX_TEST_REQUIRE(
        context,
        !owner.HasPendingWork() && owner.AdapterForTests().IsInitialized() && owner.AdapterForTests().Epoch() == 2 &&
            sysmodule::ip::UserspaceIpAdapter::InitializationCountForTests() == starts,
        "adapter owner did not coalesce configuration on its serialized work callback"
    );
    owner.QueueReset();
    owner.Run();
    WGNX_TEST_REQUIRE(
        context,
        !owner.AdapterForTests().IsInitialized() && sysmodule::ip::UserspaceIpAdapter::InitializationCountForTests() == starts,
        "adapter owner did not run reset without recreating lwIP"
    );
}

} // namespace wgnx::test
