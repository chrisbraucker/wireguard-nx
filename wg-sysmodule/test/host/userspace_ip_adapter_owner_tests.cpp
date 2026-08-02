#include "userspace_ip_adapter_owner_tests.hpp"

#include "runtime/userspace_ip_adapter_owner.hpp"
#include "test_framework.hpp"

#include <array>

namespace wgnx::test {

namespace {

void RunOwner(sysmodule::runtime::UserspaceIpAdapterOwner& owner) {
    while (const auto operation = owner.TakeNextLocked()) {
        owner.CompleteLocked(*operation, owner.Execute(*operation));
    }
}

} // namespace

void TestUserspaceIpAdapterOwner(TestContext& context) {
    constexpr std::array<std::uint8_t, 4> Local = {10, 13, 13, 8};
    sysmodule::runtime::UserspaceIpAdapterOwner owner{};
    const std::uint32_t starts = sysmodule::ip::UserspaceIpAdapter::InitializationCountForTests();
    owner.QueueConfigureLocked(Local, 1420);
    owner.QueueConfigureLocked(Local, 576);
    WGNX_TEST_REQUIRE(
        context,
        owner.HasPendingWork() && sysmodule::ip::UserspaceIpAdapter::InitializationCountForTests() == starts,
        "adapter owner initialized lwIP outside its serialized work callback"
    );
    RunOwner(owner);
    WGNX_TEST_REQUIRE(
        context,
        !owner.HasPendingWork() && owner.AdapterForTests().IsInitialized() && owner.AdapterForTests().Epoch() == 2 &&
            sysmodule::ip::UserspaceIpAdapter::InitializationCountForTests() == starts,
        "adapter owner did not coalesce configuration on its serialized work callback"
    );
    const sysmodule::ip::UserspaceIpFlow flow{
        .token = 1,
        .local = {.address = {10, 13, 13, 8}, .port = 49152, .reserved = 0},
        .remote = {.address = {10, 251, 0, 2}, .port = 29000, .reserved = 0},
    };
    sysmodule::runtime::UserspaceIpAdapterOwner::OperationTicket open_ticket{};
    sysmodule::runtime::UserspaceIpAdapterOwner::OperationTicket close_ticket{};
    const bool open_queued =
        owner.QueueOpenFlowLocked(flow, &open_ticket) == sysmodule::runtime::UserspaceIpAdapterOwner::QueueResult::Queued;
    const bool close_rejected =
        owner.QueueCloseFlowLocked(flow.token, &close_ticket) == sysmodule::runtime::UserspaceIpAdapterOwner::QueueResult::QueueFull;
    RunOwner(owner);
    const auto open_result = owner.TakeResultLocked(open_ticket);
    const bool close_queued =
        owner.QueueCloseFlowLocked(flow.token, &close_ticket) == sysmodule::runtime::UserspaceIpAdapterOwner::QueueResult::Queued;
    RunOwner(owner);
    const auto close_result = owner.TakeResultLocked(close_ticket);
    WGNX_TEST_REQUIRE(
        context,
        open_queued && close_rejected && open_result == sysmodule::ip::UserspaceIpResult::Success && close_queued &&
            close_result == sysmodule::ip::UserspaceIpResult::Success,
        "adapter owner did not serialize bounded PCB operations"
    );
    owner.QueueResetLocked();
    RunOwner(owner);
    WGNX_TEST_REQUIRE(
        context,
        !owner.AdapterForTests().IsInitialized() && sysmodule::ip::UserspaceIpAdapter::InitializationCountForTests() == starts,
        "adapter owner did not run reset without recreating lwIP"
    );
}

} // namespace wgnx::test
