#include "userspace_ip_adapter_owner_tests.hpp"

#include "runtime/userspace_ip_adapter_owner.hpp"
#include "test_framework.hpp"

#include <array>
#include <limits>

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
    owner.QueueRunTimeoutsLocked();
    owner.QueueRunTimeoutsLocked();
    const auto timeout_operation = owner.TakeNextLocked();
    const bool timeout_queued = timeout_operation.has_value() &&
                                timeout_operation->kind == sysmodule::runtime::UserspaceIpAdapterOwner::OperationKind::RunTimeouts &&
                                owner.NextTimeoutDelayMs() != std::numeric_limits<std::uint32_t>::max();
    if (timeout_operation) {
        owner.CompleteLocked(*timeout_operation, owner.Execute(*timeout_operation));
    }
    WGNX_TEST_REQUIRE(context, timeout_queued && !owner.HasPendingWork(), "adapter owner did not coalesce and serialize lwIP timeout work");
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
    std::array<std::uint8_t, wgnx::tunnel::MaximumUdpPayloadStorageBytes> payload{};
    sysmodule::runtime::UserspaceIpAdapterOwner::OperationTicket send_ticket{};
    const bool send_queued = owner.QueueSendDatagramLocked(flow.token, payload, &send_ticket) ==
                             sysmodule::runtime::UserspaceIpAdapterOwner::QueueResult::Queued;
    RunOwner(owner);
    const auto send_result = owner.PeekResultLocked(send_ticket);
    const auto packets = owner.OutboundPacketsLocked(send_ticket);
    const auto released_send_result = owner.TakeResultLocked(send_ticket);
    const bool close_queued =
        owner.QueueCloseFlowLocked(flow.token, &close_ticket) == sysmodule::runtime::UserspaceIpAdapterOwner::QueueResult::Queued;
    RunOwner(owner);
    const auto close_result = owner.TakeResultLocked(close_ticket);
    WGNX_TEST_REQUIRE(
        context,
        open_queued && close_rejected && open_result == sysmodule::ip::UserspaceIpResult::Success && send_queued &&
            send_result == sysmodule::ip::UserspaceIpResult::Success && packets.size() == 3 &&
            released_send_result == sysmodule::ip::UserspaceIpResult::Success && close_queued &&
            close_result == sysmodule::ip::UserspaceIpResult::Success,
        "adapter owner did not serialize bounded PCB operations or collect every fragmented UDP output"
    );
    constexpr std::array<std::uint8_t, 20> InputPacket = {
        0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x66, 0xD6, 0x0A, 0xFB, 0x00, 0x02, 0x0A, 0x0D, 0x0D, 0x08,
    };
    const auto queue_input = [&owner, &InputPacket](
                                 sysmodule::runtime::PeerIndex peer_index,
                                 sysmodule::runtime::ActivationGeneration activation_generation,
                                 sysmodule::runtime::UserspaceIpAdapterOwner::OperationTicket& out_ticket
                             ) {
        const sysmodule::runtime::PeerIdentity input_peer{
            .peer_index = peer_index,
            .activation_generation = activation_generation,
        };
        const bool input_queued = owner.QueueInputPacketLocked(input_peer, 3, owner.AdapterEpochLocked(), InputPacket, &out_ticket) ==
                                  sysmodule::runtime::UserspaceIpAdapterOwner::QueueResult::Queued;
        const auto input_operation = owner.TakeNextLocked();
        const bool input_tagged = input_operation.has_value() &&
                                  input_operation->kind == sysmodule::runtime::UserspaceIpAdapterOwner::OperationKind::InputPacket &&
                                  input_operation->peer == input_peer && input_operation->policy_generation == 3 &&
                                  input_operation->adapter_epoch == owner.AdapterEpochLocked();
        if (input_operation) {
            owner.CompleteLocked(*input_operation, sysmodule::ip::UserspaceIpResult::Stale);
        }
        const auto copied_input = owner.InputPacketLocked(out_ticket);
        const auto stale_input = owner.TakeResultLocked(out_ticket);
        return input_queued && input_tagged && copied_input.size() == InputPacket.size() &&
               std::equal(copied_input.begin(), copied_input.end(), InputPacket.begin()) &&
               stale_input == sysmodule::ip::UserspaceIpResult::Stale;
    };
    sysmodule::runtime::UserspaceIpAdapterOwner::OperationTicket input_ticket{};
    const bool input_queued = queue_input(sysmodule::runtime::PeerIndex{1}, sysmodule::runtime::ActivationGeneration{2}, input_ticket);
    sysmodule::runtime::UserspaceIpAdapterOwner::OperationTicket zero_input_ticket{};
    const bool zero_input_queued =
        queue_input(sysmodule::runtime::PeerIndex{0}, sysmodule::runtime::ActivationGeneration{1}, zero_input_ticket);
    WGNX_TEST_REQUIRE(
        context,
        input_queued && zero_input_queued,
        "adapter owner did not accept and retain one tagged copied IPv4 input operation for peers 0 and 1"
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
