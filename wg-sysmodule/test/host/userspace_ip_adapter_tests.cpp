#include "userspace_ip_adapter_tests.hpp"

#include "ip/lwip_platform.hpp"
#include "ip/userspace_ip_adapter.hpp"
#include "test_framework.hpp"

#include <algorithm>
#include <array>

namespace wgnx::test {

namespace {

constexpr std::size_t Ipv4HeaderBytes = 20;

std::uint16_t Checksum(std::span<const std::uint8_t> bytes) {
    std::uint32_t sum{};
    for (std::size_t index = 0; index < bytes.size(); index += 2) {
        sum += static_cast<std::uint16_t>(bytes[index] << 8U | (index + 1 < bytes.size() ? bytes[index + 1] : 0));
    }
    while ((sum >> 16U) != 0) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    return static_cast<std::uint16_t>(~sum);
}

std::array<wgnx::sysmodule::ip::UserspaceIpPacket, 3> Reverse(std::span<const wgnx::sysmodule::ip::UserspaceIpPacket> packets) {
    std::array<wgnx::sysmodule::ip::UserspaceIpPacket, 3> result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = packets[index];
        auto& packet = result[index];
        std::swap_ranges(packet.bytes.begin() + 12, packet.bytes.begin() + 16, packet.bytes.begin() + 16);
        const std::uint16_t offset = static_cast<std::uint16_t>(packet.bytes[6] << 8U | packet.bytes[7]);
        if ((offset & 0x1FFFU) == 0) {
            std::swap(packet.bytes[Ipv4HeaderBytes], packet.bytes[Ipv4HeaderBytes + 2]);
            std::swap(packet.bytes[Ipv4HeaderBytes + 1], packet.bytes[Ipv4HeaderBytes + 3]);
        }
        packet.bytes[10] = 0;
        packet.bytes[11] = 0;
        const std::uint16_t checksum = Checksum(std::span<const std::uint8_t>(packet.bytes).first(Ipv4HeaderBytes));
        packet.bytes[10] = static_cast<std::uint8_t>(checksum >> 8U);
        packet.bytes[11] = static_cast<std::uint8_t>(checksum);
    }
    return result;
}

} // namespace

void TestUserspaceIpAdapter(TestContext& context) {
    using namespace wgnx::sysmodule::ip;
    constexpr std::array<std::uint8_t, 4> Local = {10, 13, 13, 8};
    constexpr UserspaceIpFlow Flow{
        .token = 1,
        .local = {.address = {10, 13, 13, 8}, .port = 49152, .reserved = 0},
        .remote = {.address = {10, 251, 0, 2}, .port = 29000, .reserved = 0},
    };
    SetLwipHostTimeForTests(0);
    UserspaceIpAdapter adapter{};
    const std::uint32_t starts = UserspaceIpAdapter::InitializationCountForTests();
    WGNX_TEST_REQUIRE(
        context,
        adapter.Initialize(Local, 1420) && adapter.OpenFlow(Flow) == UserspaceIpResult::Success &&
            UserspaceIpAdapter::InitializationCountForTests() == starts + 1,
        "adapter did not initialize one lwIP instance and open a connected PCB"
    );
    constexpr std::array<std::uint8_t, 4> Small = {1, 2, 3, 4};
    WGNX_TEST_REQUIRE(
        context,
        adapter.Send(Flow.token, Small) == UserspaceIpResult::Success && adapter.OutboundPackets().size() == 1 &&
            adapter.OutboundPackets().front().bytes[9] == 17,
        "adapter did not emit a complete IPv4 UDP packet"
    );
    adapter.CloseFlow(Flow.token);
    WGNX_TEST_REQUIRE(context, adapter.OpenFlow(Flow) == UserspaceIpResult::Success, "adapter did not release a closed PCB for reuse");

    adapter.ClearOutboundPackets();
    std::array<std::uint8_t, wgnx::tunnel::MaximumUdpPayloadStorageBytes> payload{};
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<std::uint8_t>(index);
    }
    WGNX_TEST_REQUIRE(
        context,
        adapter.SetMtu(576) && adapter.Send(Flow.token, payload) == UserspaceIpResult::Success && adapter.OutboundPackets().size() == 3,
        "adapter did not fragment at the minimum supported MTU"
    );
    const auto reversed = Reverse(adapter.OutboundPackets());
    WGNX_TEST_REQUIRE(
        context,
        adapter.Input(std::span<const std::uint8_t>(reversed[1].bytes).first(reversed[1].size)) == UserspaceIpResult::Success &&
            adapter.HasPendingInboundFragment() &&
            adapter.Input(std::span<const std::uint8_t>(reversed[0].bytes).first(reversed[0].size)) == UserspaceIpResult::Success &&
            adapter.Input(std::span<const std::uint8_t>(reversed[2].bytes).first(reversed[2].size)) == UserspaceIpResult::Success &&
            adapter.InboundDatagrams().size() == 1 && adapter.InboundDatagrams().front().token == Flow.token &&
            adapter.InboundDatagrams().front().size == payload.size() &&
            std::equal(payload.begin(), payload.end(), adapter.InboundDatagrams().front().payload.begin()),
        "adapter did not reassemble out-of-order fragments into the matching PCB"
    );

    auto zero_checksum = reversed;
    zero_checksum[0].bytes[Ipv4HeaderBytes + 6] = 0;
    zero_checksum[0].bytes[Ipv4HeaderBytes + 7] = 0;
    adapter.ClearInboundDatagrams();
    WGNX_TEST_REQUIRE(
        context,
        adapter.Input(std::span<const std::uint8_t>(zero_checksum[1].bytes).first(zero_checksum[1].size)) == UserspaceIpResult::Success &&
            adapter.Input(std::span<const std::uint8_t>(zero_checksum[0].bytes).first(zero_checksum[0].size)) ==
                UserspaceIpResult::Success &&
            adapter.Input(std::span<const std::uint8_t>(zero_checksum[2].bytes).first(zero_checksum[2].size)) ==
                UserspaceIpResult::Success &&
            adapter.InboundDatagrams().size() == 1 && adapter.InboundDatagrams().front().size == payload.size(),
        "adapter did not accept a zero IPv4 UDP checksum after reassembly"
    );

    adapter.ClearInboundDatagrams();
    static_cast<void>(adapter.Input(std::span<const std::uint8_t>(reversed[0].bytes).first(reversed[0].size)));
    adapter.Reset();
    WGNX_TEST_REQUIRE(
        context,
        adapter.Initialize(Local, 576) && adapter.OpenFlow(Flow) == UserspaceIpResult::Success &&
            UserspaceIpAdapter::InitializationCountForTests() == starts + 1 &&
            adapter.Input(std::span<const std::uint8_t>(reversed[1].bytes).first(reversed[1].size)) == UserspaceIpResult::Success &&
            adapter.Input(std::span<const std::uint8_t>(reversed[2].bytes).first(reversed[2].size)) == UserspaceIpResult::Success &&
            adapter.InboundDatagrams().empty(),
        "adapter reset did not discard retained fragments without reinvoking lwip_init"
    );
    adapter.Reset();
    WGNX_TEST_REQUIRE(
        context,
        adapter.Initialize(Local, 576) && adapter.OpenFlow(Flow) == UserspaceIpResult::Success,
        "adapter did not reset the reassembly fixture before expiry coverage"
    );
    static_cast<void>(adapter.Input(std::span<const std::uint8_t>(reversed[0].bytes).first(reversed[0].size)));
    for (std::uint32_t now_ms = 1'000; now_ms <= 16'000; now_ms += 1'000) {
        SetLwipHostTimeForTests(now_ms);
        adapter.RunTimeouts();
    }
    static_cast<void>(adapter.Input(std::span<const std::uint8_t>(reversed[1].bytes).first(reversed[1].size)));
    static_cast<void>(adapter.Input(std::span<const std::uint8_t>(reversed[2].bytes).first(reversed[2].size)));
    WGNX_TEST_REQUIRE(context, adapter.InboundDatagrams().empty(), "adapter did not expire incomplete reassembly");
    for (std::uint32_t token = 2; token <= UserspaceIpAdapter::MaximumFlows; ++token) {
        UserspaceIpFlow flow = Flow;
        flow.token = token;
        flow.local.port = static_cast<std::uint16_t>(Flow.local.port + token);
        WGNX_TEST_REQUIRE(context, adapter.OpenFlow(flow) == UserspaceIpResult::Success, "adapter rejected available PCB capacity");
    }
    UserspaceIpFlow overflow = Flow;
    overflow.token = UserspaceIpAdapter::MaximumFlows + 1;
    overflow.local.port = static_cast<std::uint16_t>(Flow.local.port + overflow.token);
    WGNX_TEST_REQUIRE(context, adapter.OpenFlow(overflow) == UserspaceIpResult::FlowQuotaExhausted, "adapter did not bound PCB capacity");
    adapter.ClearOutboundPackets();
    WGNX_TEST_REQUIRE(context, adapter.SetMtu(1420), "adapter did not restore the unfragmented MTU");
    for (std::size_t index = 0; index < UserspaceIpAdapter::OutboundPacketCapacity; ++index) {
        WGNX_TEST_REQUIRE(
            context,
            adapter.Send(Flow.token, Small) == UserspaceIpResult::Success,
            "adapter rejected available collector capacity"
        );
    }
    WGNX_TEST_REQUIRE(context, adapter.Send(Flow.token, Small) == UserspaceIpResult::QueueFull, "adapter did not bound collector pressure");
    const auto& statistics = adapter.Statistics();
    WGNX_TEST_REQUIRE(
        context,
        statistics.flow_high_water == UserspaceIpAdapter::MaximumFlows && statistics.input_packets >= 8 &&
            statistics.fragment_inputs >= 3 && statistics.reassembly_successes >= 2 && statistics.callback_deliveries >= 2 &&
            statistics.timeout_runs >= 1 && statistics.resets >= 2 && statistics.outbound_collector_rejections >= 1 &&
            statistics.first_rejection == UserspaceIpRejection::PbufAllocation,
        "adapter did not retain bounded resource, reassembly, timeout, and rejection accounting"
    );
}

} // namespace wgnx::test
