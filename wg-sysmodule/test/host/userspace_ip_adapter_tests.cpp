#include "userspace_ip_adapter_tests.hpp"

#include "ip/lwip_platform.hpp"
#include "ip/userspace_ip_adapter.hpp"
#include "test_framework.hpp"
#include "wireguard/inner_packet.hpp"

#include <algorithm>
#include <array>

namespace wgnx::test {

namespace {

constexpr std::size_t Ipv4HeaderBytes = 20;
constexpr std::size_t TcpHeaderBytes = 20;

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

std::uint32_t ReadNetworkU32(std::span<const std::uint8_t> bytes, std::size_t offset) {
    return static_cast<std::uint32_t>(bytes[offset]) << 24U | static_cast<std::uint32_t>(bytes[offset + 1]) << 16U |
           static_cast<std::uint32_t>(bytes[offset + 2]) << 8U | static_cast<std::uint32_t>(bytes[offset + 3]);
}

void WriteNetworkU16(std::span<std::uint8_t> bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 1] = static_cast<std::uint8_t>(value);
}

void WriteNetworkU32(std::span<std::uint8_t> bytes, std::size_t offset, std::uint32_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 2] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 3] = static_cast<std::uint8_t>(value);
}

wgnx::sysmodule::ip::UserspaceIpPacket MakeTcpReply(
    const wgnx::sysmodule::ip::UserspaceIpPacket& request,
    std::uint32_t sequence,
    std::uint32_t acknowledgement,
    std::uint8_t flags,
    std::span<const std::uint8_t> payload = {}
) {
    wgnx::sysmodule::ip::UserspaceIpPacket reply{};
    reply.size = static_cast<std::uint16_t>(Ipv4HeaderBytes + TcpHeaderBytes + payload.size());
    reply.bytes[0] = 0x45;
    WriteNetworkU16(reply.bytes, 2, reply.size);
    reply.bytes[6] = 0x40;
    reply.bytes[8] = 64;
    reply.bytes[9] = 6;
    std::copy_n(request.bytes.begin() + 16, 4, reply.bytes.begin() + 12);
    std::copy_n(request.bytes.begin() + 12, 4, reply.bytes.begin() + 16);
    WriteNetworkU16(reply.bytes, Ipv4HeaderBytes, static_cast<std::uint16_t>(request.bytes[22] << 8U | request.bytes[23]));
    WriteNetworkU16(reply.bytes, Ipv4HeaderBytes + 2, static_cast<std::uint16_t>(request.bytes[20] << 8U | request.bytes[21]));
    WriteNetworkU32(reply.bytes, Ipv4HeaderBytes + 4, sequence);
    WriteNetworkU32(reply.bytes, Ipv4HeaderBytes + 8, acknowledgement);
    reply.bytes[Ipv4HeaderBytes + 12] = 0x50;
    reply.bytes[Ipv4HeaderBytes + 13] = flags;
    WriteNetworkU16(reply.bytes, Ipv4HeaderBytes + 14, 0xFFFF);
    std::copy(payload.begin(), payload.end(), reply.bytes.begin() + Ipv4HeaderBytes + TcpHeaderBytes);
    WriteNetworkU16(reply.bytes, 10, Checksum(std::span<const std::uint8_t>(reply.bytes).first(Ipv4HeaderBytes)));

    std::array<std::uint8_t, 12 + TcpHeaderBytes + wgnx::tunnel::MaximumTcpWriteStorageBytes> pseudo{};
    std::copy_n(reply.bytes.begin() + 12, 8, pseudo.begin());
    pseudo[9] = 6;
    WriteNetworkU16(pseudo, 10, static_cast<std::uint16_t>(TcpHeaderBytes + payload.size()));
    std::copy_n(reply.bytes.begin() + Ipv4HeaderBytes, TcpHeaderBytes + payload.size(), pseudo.begin() + 12);
    WriteNetworkU16(
        reply.bytes,
        Ipv4HeaderBytes + 16,
        Checksum(std::span<const std::uint8_t>(pseudo).first(12 + TcpHeaderBytes + payload.size()))
    );
    return reply;
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
    UserspaceIpFlow connecting_flow = Flow;
    connecting_flow.token = 2;
    connecting_flow.local.port = 49153;
    adapter.ClearOutboundPackets();
    const bool opened_connecting_flow = adapter.OpenTcpFlow(connecting_flow) == UserspaceIpResult::Success;
    adapter.ClearOutboundPackets();
    for (std::uint32_t now_ms = 250; now_ms <= 4'000; now_ms += 250) {
        SetLwipHostTimeForTests(now_ms);
        adapter.RunTimeouts();
    }
    const bool retransmitted_connecting_flow = !adapter.OutboundPackets().empty() && adapter.OutboundPackets().front().bytes[9] == 6;
    adapter.Reset();
    WGNX_TEST_REQUIRE(
        context,
        opened_connecting_flow && retransmitted_connecting_flow && adapter.Initialize(Local, 1420),
        "adapter did not progress TCP retransmission timers or retire a connecting PCB during reset"
    );
    adapter.ClearOutboundPackets();
    wgnx::wireguard::InnerIpv4TcpTuple tcp_tuple{};
    wgnx::sysmodule::ip::UserspaceIpPacket tcp_syn{};
    WGNX_TEST_REQUIRE(
        context,
        adapter.OpenTcpFlow(Flow) == UserspaceIpResult::Success && adapter.OutboundPackets().size() == 1 &&
            adapter.OutboundPackets().front().bytes[9] == 6 && adapter.WriteTcp(Flow.token, Small) == UserspaceIpResult::TransportError &&
            adapter.ShutdownTcpWrite(Flow.token) == UserspaceIpResult::TransportError &&
            wgnx::wireguard::ParseInnerIpv4TcpTuple(
                std::span<const std::uint8_t>(adapter.OutboundPackets().front().bytes).first(adapter.OutboundPackets().front().size),
                &tcp_tuple
            ) &&
            tcp_tuple.source_port == Flow.local.port && tcp_tuple.destination_port == Flow.remote.port,
        "adapter did not open one bounded TCP PCB or retain a parseable pinned output tuple"
    );
    tcp_syn = adapter.OutboundPackets().front();
    constexpr std::uint32_t RemoteInitialSequence = 0x10203040;
    const auto tcp_syn_ack = MakeTcpReply(tcp_syn, RemoteInitialSequence, ReadNetworkU32(tcp_syn.bytes, Ipv4HeaderBytes + 4) + 1, 0x12);
    adapter.ClearOutboundPackets();
    WGNX_TEST_REQUIRE(
        context,
        adapter.Input(std::span<const std::uint8_t>(tcp_syn_ack.bytes).first(tcp_syn_ack.size)) == UserspaceIpResult::Success &&
            adapter.TcpEvents().size() == 1 && adapter.TcpEvents().front().type == UserspaceIpTcpEventType::Connected &&
            adapter.TcpEvents().front().token == Flow.token,
        "adapter did not complete a deterministic lwIP TCP handshake"
    );
    adapter.ClearTcpEvents();
    adapter.ClearOutboundPackets();
    WGNX_TEST_REQUIRE(
        context,
        adapter.WriteTcp(Flow.token, Small) == UserspaceIpResult::Success && adapter.OutboundPackets().size() == 1 &&
            adapter.OutboundPackets().front().bytes[Ipv4HeaderBytes + 13] == 0x18 &&
            std::equal(Small.begin(), Small.end(), adapter.OutboundPackets().front().bytes.begin() + Ipv4HeaderBytes + TcpHeaderBytes),
        "adapter did not emit one ordered TCP stream segment after connect"
    );
    const auto tcp_write = adapter.OutboundPackets().front();
    constexpr std::array<std::uint8_t, 2> FirstReply = {5, 6};
    constexpr std::array<std::uint8_t, 2> SecondReply = {7, 8};
    const std::uint32_t local_next_sequence = ReadNetworkU32(tcp_write.bytes, Ipv4HeaderBytes + 4) + Small.size();
    const auto first_reply = MakeTcpReply(tcp_syn, RemoteInitialSequence + 1, local_next_sequence, 0x18, FirstReply);
    const auto second_reply = MakeTcpReply(tcp_syn, RemoteInitialSequence + 1 + FirstReply.size(), local_next_sequence, 0x18, SecondReply);
    adapter.ClearOutboundPackets();
    WGNX_TEST_REQUIRE(
        context,
        adapter.Input(std::span<const std::uint8_t>(first_reply.bytes).first(first_reply.size)) == UserspaceIpResult::Success &&
            adapter.Input(std::span<const std::uint8_t>(second_reply.bytes).first(second_reply.size)) == UserspaceIpResult::Success &&
            adapter.InboundStreams().size() == 2 && adapter.InboundStreams()[0].token == Flow.token &&
            adapter.InboundStreams()[0].size == FirstReply.size() && adapter.InboundStreams()[1].size == SecondReply.size() &&
            std::equal(FirstReply.begin(), FirstReply.end(), adapter.InboundStreams()[0].payload.begin()) &&
            std::equal(SecondReply.begin(), SecondReply.end(), adapter.InboundStreams()[1].payload.begin()) &&
            adapter.AcknowledgeTcpReceive(
                {{{.token = Flow.token, .bytes = static_cast<std::uint16_t>(FirstReply.size() + SecondReply.size())}}}
            ) == UserspaceIpResult::Success,
        "adapter did not retain, order, and acknowledge deterministic remote TCP stream delivery"
    );
    const auto tcp_fin =
        MakeTcpReply(tcp_syn, RemoteInitialSequence + 1 + FirstReply.size() + SecondReply.size(), local_next_sequence, 0x11);
    adapter.ClearTcpEvents();
    WGNX_TEST_REQUIRE(
        context,
        adapter.Input(std::span<const std::uint8_t>(tcp_fin.bytes).first(tcp_fin.size)) == UserspaceIpResult::Success &&
            adapter.TcpEvents().size() == 1 && adapter.TcpEvents().front().type == UserspaceIpTcpEventType::RemoteWriteClosed &&
            adapter.ShutdownTcpWrite(Flow.token) == UserspaceIpResult::Success &&
            adapter.ShutdownTcpWrite(Flow.token) == UserspaceIpResult::Success,
        "adapter did not preserve orderly remote EOF and idempotent local half-close"
    );
    adapter.Reset();
    WGNX_TEST_REQUIRE(
        context,
        adapter.Initialize(Local, 1420) && adapter.OpenFlow(Flow) == UserspaceIpResult::Success,
        "adapter did not retire an established TCP PCB during reset and make the tuple reusable"
    );

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
    for (std::uint32_t now_ms = 5'000; now_ms <= 20'000; now_ms += 1'000) {
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
    bool repeated_reset_succeeded = true;
    for (std::size_t index = 0; index < 32; ++index) {
        adapter.Reset();
        repeated_reset_succeeded =
            repeated_reset_succeeded && adapter.Initialize(Local, 1420) && adapter.OpenFlow(Flow) == UserspaceIpResult::Success;
    }
    WGNX_TEST_REQUIRE(
        context,
        repeated_reset_succeeded,
        "adapter reset reinitialized lwIP timeout state until the fixed timeout pool overflowed"
    );
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
