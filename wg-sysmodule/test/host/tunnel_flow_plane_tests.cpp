#include "tunnel_flow_plane_tests.hpp"

#include "protocol_test_support.hpp"
#include "runtime/tunnel_flow_plane.hpp"

#include <array>
#include <cstring>

namespace wgnx::test {

namespace {

constexpr std::size_t Ipv4HeaderSize = 20;
constexpr std::size_t UdpHeaderSize = 8;
constexpr std::uint8_t UdpProtocol = 17;

struct NotificationCounter {
    std::uint32_t count{0};
};

void Notify(void* context) {
    if (context != nullptr) {
        ++static_cast<NotificationCounter*>(context)->count;
    }
}

void StoreBigEndian16(std::uint8_t* out, std::uint16_t value) {
    out[0] = static_cast<std::uint8_t>(value >> 8U);
    out[1] = static_cast<std::uint8_t>(value & 0xFFU);
}

std::uint16_t LoadBigEndian16(const std::uint8_t* in) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(in[0]) << 8U) | static_cast<std::uint16_t>(in[1]));
}

std::uint32_t AddChecksum(std::uint32_t sum, const std::uint8_t* bytes, std::size_t size) {
    std::size_t offset = 0;
    while (offset + 1 < size) {
        sum += (static_cast<std::uint32_t>(bytes[offset]) << 8U) | bytes[offset + 1];
        offset += 2;
    }
    if (offset < size) {
        sum += static_cast<std::uint32_t>(bytes[offset]) << 8U;
    }
    return sum;
}

std::uint16_t FinishChecksum(std::uint32_t sum) {
    while ((sum >> 16U) != 0) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

std::uint16_t Checksum(const std::uint8_t* bytes, std::size_t size) {
    return FinishChecksum(AddChecksum(0, bytes, size));
}

std::uint16_t UdpChecksum(const std::uint8_t source[4], const std::uint8_t destination[4], const std::uint8_t* udp, std::size_t udp_size) {
    const std::array<std::uint8_t, 4> pseudo_tail = {
        0,
        UdpProtocol,
        static_cast<std::uint8_t>(udp_size >> 8U),
        static_cast<std::uint8_t>(udp_size & 0xFFU),
    };
    std::uint32_t sum = AddChecksum(0, source, 4);
    sum = AddChecksum(sum, destination, 4);
    sum = AddChecksum(sum, pseudo_tail.data(), pseudo_tail.size());
    return FinishChecksum(AddChecksum(sum, udp, udp_size));
}

std::size_t BuildReply(std::span<std::uint8_t> out, std::span<const std::uint8_t> request, std::span<const std::uint8_t> payload) {
    if (request.size() < Ipv4HeaderSize + UdpHeaderSize || out.size() < Ipv4HeaderSize + UdpHeaderSize + payload.size()) {
        return 0;
    }
    const std::size_t packet_size = Ipv4HeaderSize + UdpHeaderSize + payload.size();
    std::fill_n(out.begin(), packet_size, std::uint8_t{0});
    out[0] = 0x45;
    StoreBigEndian16(out.data() + 2, static_cast<std::uint16_t>(packet_size));
    StoreBigEndian16(out.data() + 6, 0x4000U);
    out[8] = 64;
    out[9] = UdpProtocol;
    std::memcpy(out.data() + 12, request.data() + 16, 4);
    std::memcpy(out.data() + 16, request.data() + 12, 4);
    StoreBigEndian16(out.data() + 10, Checksum(out.data(), Ipv4HeaderSize));
    std::uint8_t* udp = out.data() + Ipv4HeaderSize;
    StoreBigEndian16(udp, LoadBigEndian16(request.data() + Ipv4HeaderSize + 2));
    StoreBigEndian16(udp + 2, LoadBigEndian16(request.data() + Ipv4HeaderSize));
    StoreBigEndian16(udp + 4, static_cast<std::uint16_t>(UdpHeaderSize + payload.size()));
    std::memcpy(udp + UdpHeaderSize, payload.data(), payload.size());
    std::uint16_t checksum = UdpChecksum(out.data() + 12, out.data() + 16, udp, UdpHeaderSize + payload.size());
    if (checksum == 0) {
        checksum = 0xFFFFU;
    }
    StoreBigEndian16(udp + 6, checksum);
    return packet_size;
}

} // namespace

void TestTunnelFlowPlane(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::tunnel;

    constexpr TunnelTransportAvailability TransportUnavailable{};
    constexpr TunnelTransportAvailability StagingFull{
        .protocol_available = true,
        .staging_available = false,
    };
    constexpr TunnelTransportAvailability TransportReady{
        .protocol_available = true,
        .staging_available = true,
    };

    wgnx::PeerConfigEntry config{};
    FillConfig(&config, "flow-plane", "10.13.13.8/24", InitiatorPrivateKey, ResponderPublicKey);
    std::snprintf(config.allowed_ips.data(), config.allowed_ips.size(), "%s", "10.0.0.0/8, 10.251.0.0/16");
    const PeerIdentity first_peer{.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{7}};

    TunnelFlowPlane plane{};
    NotificationCounter notifications{};
    const TunnelClientId client = plane.CreateClient(Notify, &notifications);
    plane.RefreshPolicy({.configuration = &config, .peer = first_peer, .selected = true}, 100);

    std::array<RouteRecord, MaximumPolicyRoutes> routes{};
    const RoutingPolicySnapshot snapshot = plane.CopyRoutingPolicy(routes);
    WGNX_TEST_REQUIRE(context,
                      client.IsValid() && snapshot.route_count == 2 && routes[0].prefix_length == 16 && routes[1].prefix_length == 8 &&
                          routes[0].network_address[0] == 10 && routes[0].network_address[1] == 251 && notifications.count == 1,
                      "flow plane did not create a client context or normalize longest-prefix routes");

    const OpenConnectedUdpFlowRequest uncovered{
        .remote = {.address = {192, 0, 2, 1}, .port = 29000, .reserved = 0},
        .diagnostic_tag = 1,
    };
    const OpenConnectedUdpFlowRequest open{
        .remote = {.address = {10, 251, 0, 2}, .port = 29000, .reserved = 0},
        .diagnostic_tag = 0xA5A5,
    };
    const auto uncovered_result = plane.OpenConnectedUdpFlow(client, uncovered, 110);
    const auto opened = plane.OpenConnectedUdpFlow(client, open, 120);
    WGNX_TEST_REQUIRE(context,
                      uncovered_result.status == ProtocolStatus::RouteNotCovered && opened.status == ProtocolStatus::Success &&
                          opened.peer_activation_generation == first_peer.activation_generation.Value(),
                      "flow opening did not distinguish route coverage or bind the peer activation");

    constexpr std::array<std::uint8_t, 5> Payload = {'h', 'e', 'l', 'l', 'o'};
    const DatagramDescriptor descriptor{
        .flow = opened.flow,
        .payload_offset = 0,
        .payload_size = static_cast<std::uint32_t>(Payload.size()),
        .client_tag = 99,
    };
    const auto not_ready = plane.PrepareSend(client, descriptor, Payload, TransportUnavailable, 130);
    const auto sent = plane.PrepareSend(client, descriptor, Payload, TransportReady, 140);
    WGNX_TEST_REQUIRE(context,
                      not_ready.status == ProtocolStatus::TransportUnavailable && sent.status == ProtocolStatus::Success &&
                          sent.HasPacket() && sent.packet.size() == Ipv4HeaderSize + UdpHeaderSize + Payload.size() &&
                          sent.packet[9] == UdpProtocol &&
                          std::equal(Payload.begin(), Payload.end(), sent.packet.begin() + Ipv4HeaderSize + UdpHeaderSize),
                      "flow send did not enforce transport availability or construct the requested UDP payload");

    std::array<std::uint8_t, wgnx::MaxInnerIpv4PacketSize> reply{};
    const std::size_t reply_size = BuildReply(reply, sent.packet, Payload);
    plane.ReleasePreparedDatagram(sent);
    const auto foreign = plane.DeliverDecryptedIpv4Packet({.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{8}},
                                                          std::span<const std::uint8_t>(reply.data(), reply_size), 149);
    reply[Ipv4HeaderSize + 6] ^= 0xFFU;
    const auto malformed = plane.DeliverDecryptedIpv4Packet(first_peer, std::span<const std::uint8_t>(reply.data(), reply_size), 149);
    reply[Ipv4HeaderSize + 6] ^= 0xFFU;
    const auto delivered = plane.DeliverDecryptedIpv4Packet(first_peer, std::span<const std::uint8_t>(reply.data(), reply_size), 150);
    std::array<CompletionRecord, MaximumBatchEntries> completions{};
    std::array<std::uint8_t, MaximumUdpPayloadBytes> received_payload{};
    const auto received = plane.ReceiveCompletions(client, completions, received_payload);
    WGNX_TEST_REQUIRE(context,
                      reply_size != 0 && foreign.disposition == TunnelInboundDisposition::NotClaimed &&
                          malformed.disposition == TunnelInboundDisposition::DroppedMalformed &&
                          delivered.disposition == TunnelInboundDisposition::Delivered && received.status == ProtocolStatus::Success &&
                          received.count >= 1 && completions[0].type == CompletionType::PolicyChanged &&
                          completions[1].type == CompletionType::InboundDatagram && completions[1].flow.value == opened.flow.value &&
                          completions[1].payload_size == Payload.size() &&
                          std::equal(Payload.begin(), Payload.end(), received_payload.begin()),
                      "flow receive did not retain the policy edge and matching UDP reply in completion order");

    const auto second_send = plane.PrepareSend(client, descriptor, Payload, TransportReady, 160);
    const std::size_t second_reply_size = BuildReply(reply, second_send.packet, Payload);
    plane.ReleasePreparedDatagram(second_send);
    static_cast<void>(plane.DeliverDecryptedIpv4Packet(first_peer, std::span<const std::uint8_t>(reply.data(), second_reply_size), 170));
    std::array<std::uint8_t, 1> too_small{};
    const auto insufficient = plane.ReceiveCompletions(client, completions, too_small);
    const auto after_insufficient = plane.ReceiveCompletions(client, completions, received_payload);
    WGNX_TEST_REQUIRE(context,
                      insufficient.status == ProtocolStatus::OutputBufferTooSmall && after_insufficient.status == ProtocolStatus::Success &&
                          after_insufficient.count == 1 && completions[0].type == CompletionType::InboundDatagram,
                      "completion draining emitted a partial datagram or lost it after an undersized buffer");

    const auto staging_full = plane.PrepareSend(client, descriptor, Payload, StagingFull, 175);
    plane.NotifyOutboundCapacityAvailable(first_peer);
    plane.NotifyOutboundCapacityAvailable(first_peer);
    const auto writable = plane.ReceiveCompletions(client, completions, received_payload);
    const auto retried_send = plane.PrepareSend(client, descriptor, Payload, TransportReady, 176);
    plane.CompleteSend(retried_send, ProtocolStatus::Success);
    plane.ReleasePreparedDatagram(retried_send);
    WGNX_TEST_REQUIRE(context,
                      staging_full.status == ProtocolStatus::QueueFull && writable.status == ProtocolStatus::Success &&
                          writable.count == 1 && completions[0].type == CompletionType::Writable &&
                          completions[0].flow.value == opened.flow.value && retried_send.status == ProtocolStatus::Success &&
                          notifications.count == 3,
                      "staging pressure did not report one coalesced writable transition and a successful retry without packet loss");

    const auto close_status = plane.CloseFlow(client, opened.flow, 180);
    const auto delayed = plane.DeliverDecryptedIpv4Packet(first_peer, std::span<const std::uint8_t>(reply.data(), second_reply_size), 181);
    const auto replacement = plane.OpenConnectedUdpFlow(client, open, 182);
    WGNX_TEST_REQUIRE(context,
                      close_status == ProtocolStatus::Success && delayed.disposition == TunnelInboundDisposition::DroppedStale &&
                          replacement.status == ProtocolStatus::Success && replacement.flow.value != opened.flow.value,
                      "released reverse tuples were not quarantined before flow reuse");

    plane.RefreshPolicy({.configuration = &config,
                         .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{8}},
                         .selected = true},
                        190);
    const auto stale_state = plane.GetFlowState(client, replacement.flow);
    WGNX_TEST_REQUIRE(
        context, stale_state.status == ProtocolStatus::FlowClosed && stale_state.terminal_reason == FlowTerminalReason::PolicyInvalidated,
        "peer activation transition did not close the old flow with a terminal state");

    TunnelFlowPlane client_reuse_plane{};
    const TunnelClientId first_reuse_client = client_reuse_plane.CreateClient(nullptr, nullptr);
    const TunnelClientId second_reuse_client = client_reuse_plane.CreateClient(nullptr, nullptr);
    client_reuse_plane.RefreshPolicy({.configuration = &config, .peer = first_peer, .selected = true}, 200);
    static_cast<void>(client_reuse_plane.ReceiveCompletions(first_reuse_client, completions, received_payload));
    static_cast<void>(client_reuse_plane.ReceiveCompletions(second_reuse_client, completions, received_payload));
    const auto first_reuse_flow = client_reuse_plane.OpenConnectedUdpFlow(first_reuse_client, open, 201);
    const DatagramDescriptor first_reuse_descriptor{
        .flow = first_reuse_flow.flow,
        .payload_offset = 0,
        .payload_size = static_cast<std::uint32_t>(Payload.size()),
        .client_tag = 200,
    };
    const auto first_reuse_send = client_reuse_plane.PrepareSend(first_reuse_client, first_reuse_descriptor, Payload, TransportReady, 202);
    const std::uint16_t first_reuse_port = LoadBigEndian16(first_reuse_send.packet.data() + Ipv4HeaderSize);
    client_reuse_plane.ReleasePreparedDatagram(first_reuse_send);
    const auto first_reuse_close = client_reuse_plane.CloseFlow(first_reuse_client, first_reuse_flow.flow, 203);
    const auto second_reuse_flow = client_reuse_plane.OpenConnectedUdpFlow(second_reuse_client, open, 204);
    const DatagramDescriptor second_reuse_descriptor{
        .flow = second_reuse_flow.flow,
        .payload_offset = 0,
        .payload_size = static_cast<std::uint32_t>(Payload.size()),
        .client_tag = 201,
    };
    const auto second_reuse_send =
        client_reuse_plane.PrepareSend(second_reuse_client, second_reuse_descriptor, Payload, TransportReady, 205);
    const std::uint16_t second_reuse_port = LoadBigEndian16(second_reuse_send.packet.data() + Ipv4HeaderSize);
    const std::size_t second_reuse_reply_size = BuildReply(reply, second_reuse_send.packet, Payload);
    client_reuse_plane.ReleasePreparedDatagram(second_reuse_send);
    const auto second_reuse_delivery = client_reuse_plane.DeliverDecryptedIpv4Packet(
        first_peer, std::span<const std::uint8_t>(reply.data(), second_reuse_reply_size), 206);
    const auto second_reuse_received = client_reuse_plane.ReceiveCompletions(second_reuse_client, completions, received_payload);
    WGNX_TEST_REQUIRE(context,
                      first_reuse_flow.status == ProtocolStatus::Success && first_reuse_send.status == ProtocolStatus::Success &&
                          first_reuse_close == ProtocolStatus::Success && second_reuse_flow.status == ProtocolStatus::Success &&
                          second_reuse_send.status == ProtocolStatus::Success && first_reuse_port != second_reuse_port &&
                          second_reuse_delivery.disposition == TunnelInboundDisposition::Delivered &&
                          second_reuse_received.status == ProtocolStatus::Success && second_reuse_received.count == 1 &&
                          completions[0].type == CompletionType::InboundDatagram &&
                          completions[0].flow.value == second_reuse_flow.flow.value &&
                          std::equal(Payload.begin(), Payload.end(), received_payload.begin()),
                      "a fresh client flow did not receive its reply after a prior client closed the same remote tuple");

    std::array<TunnelClientId, MaximumClientContexts - 1> extra_clients{};
    bool all_extra_created = true;
    for (TunnelClientId& extra : extra_clients) {
        extra = plane.CreateClient(nullptr, nullptr);
        all_extra_created = all_extra_created && extra.IsValid();
    }
    WGNX_TEST_REQUIRE(context, all_extra_created && !plane.CreateClient(nullptr, nullptr).IsValid(),
                      "logical client contexts exceeded the fixed global limit");

    const TunnelClientId released_client = extra_clients.front();
    plane.DestroyClient(released_client, 195);
    const TunnelClientId recycled_client = plane.CreateClient(nullptr, nullptr);
    WGNX_TEST_REQUIRE(context,
                      recycled_client.IsValid() && recycled_client.slot == released_client.slot &&
                          recycled_client.generation != released_client.generation,
                      "destroyed tunnel client contexts were not returned with a stale-safe generation");

    TunnelFlowPlane shutdown_plane{};
    NotificationCounter first_shutdown_notification{};
    NotificationCounter second_shutdown_notification{};
    const TunnelClientId first_shutdown_client = shutdown_plane.CreateClient(Notify, &first_shutdown_notification);
    const TunnelClientId second_shutdown_client = shutdown_plane.CreateClient(Notify, &second_shutdown_notification);
    const std::uint32_t shutdown_signaled = shutdown_plane.SignalAllClientCompletionEvents();
    const auto first_shutdown_drain = shutdown_plane.ReceiveCompletions(first_shutdown_client, completions, received_payload);
    const auto second_shutdown_drain = shutdown_plane.ReceiveCompletions(second_shutdown_client, completions, received_payload);
    WGNX_TEST_REQUIRE(context,
                      first_shutdown_client.IsValid() && second_shutdown_client.IsValid() && shutdown_signaled == 2 &&
                          first_shutdown_notification.count == 1 && second_shutdown_notification.count == 1 &&
                          first_shutdown_drain.status == ProtocolStatus::QueueEmpty &&
                          second_shutdown_drain.status == ProtocolStatus::QueueEmpty,
                      "sysmodule shutdown did not wake every tunnel client without fabricating completion records");

    TunnelFlowPlane bounded_plane{};
    const TunnelClientId bounded_client = bounded_plane.CreateClient(nullptr, nullptr);
    bounded_plane.RefreshPolicy({.configuration = &config, .peer = first_peer, .selected = true}, 200);
    static_cast<void>(bounded_plane.ReceiveCompletions(bounded_client, completions, received_payload));
    const OpenConnectedUdpFlowRequest invalid_port{
        .remote = {.address = {10, 251, 0, 2}, .port = 0, .reserved = 0},
        .diagnostic_tag = 0,
    };
    const auto invalid_port_result = bounded_plane.OpenConnectedUdpFlow(bounded_client, invalid_port, 201);

    std::array<FlowHandle, MaximumFlowsPerClient> bounded_flows{};
    bool all_bounded_flows_opened = true;
    for (std::size_t index = 0; index < bounded_flows.size(); ++index) {
        auto request = open;
        request.diagnostic_tag = index;
        const auto opened_flow = bounded_plane.OpenConnectedUdpFlow(bounded_client, request, 202 + index);
        bounded_flows[index] = opened_flow.flow;
        all_bounded_flows_opened = all_bounded_flows_opened && opened_flow.status == ProtocolStatus::Success;
    }
    std::uint32_t delivered_count = 0;
    std::uint32_t dropped_count = 0;
    for (std::uint32_t sequence = 0; sequence < 8; ++sequence) {
        const DatagramDescriptor bounded_descriptor{
            .flow = bounded_flows[sequence % bounded_flows.size()],
            .payload_offset = 0,
            .payload_size = static_cast<std::uint32_t>(Payload.size()),
            .client_tag = sequence,
        };
        const auto outbound = bounded_plane.PrepareSend(bounded_client, bounded_descriptor, Payload, TransportReady, 210 + sequence);
        const std::size_t bounded_reply_size = BuildReply(reply, outbound.packet, Payload);
        bounded_plane.ReleasePreparedDatagram(outbound);
        const auto inbound = bounded_plane.DeliverDecryptedIpv4Packet(
            first_peer, std::span<const std::uint8_t>(reply.data(), bounded_reply_size), 220 + sequence);
        delivered_count += inbound.disposition == TunnelInboundDisposition::Delivered ? 1U : 0U;
        dropped_count += inbound.disposition == TunnelInboundDisposition::DroppedQueueFull ? 1U : 0U;
    }
    bounded_plane.RefreshPolicy({.configuration = &config,
                                 .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{9}},
                                 .selected = true},
                                230);
    const auto bounded_drain = bounded_plane.ReceiveCompletions(bounded_client, completions, received_payload);
    bool terminal_seen = false;
    for (std::uint32_t index = 0; index < bounded_drain.count; ++index) {
        terminal_seen = terminal_seen || completions[index].type == CompletionType::FlowStateChanged;
    }
    WGNX_TEST_REQUIRE(
        context,
        invalid_port_result.status == ProtocolStatus::MalformedInput && all_bounded_flows_opened && delivered_count == 7 &&
            dropped_count == 1 && bounded_drain.status == ProtocolStatus::Success && terminal_seen,
        "flow plane did not enforce invalid ports, bounded inbound completion pressure, or terminal notification reservation");

    TunnelFlowPlane quarantine_plane{};
    std::array<TunnelClientId, MaximumClientContexts> quarantine_clients{};
    for (TunnelClientId& quarantine_client : quarantine_clients) {
        quarantine_client = quarantine_plane.CreateClient(nullptr, nullptr);
    }
    quarantine_plane.RefreshPolicy({.configuration = &config, .peer = first_peer, .selected = true}, 300);
    bool all_tuples_opened = true;
    std::array<FlowHandle, MaximumFlows> quarantine_flows{};
    for (std::size_t index = 0; index < quarantine_flows.size(); ++index) {
        const auto opened_flow =
            quarantine_plane.OpenConnectedUdpFlow(quarantine_clients[index / MaximumFlowsPerClient], open, 301 + index);
        quarantine_flows[index] = opened_flow.flow;
        all_tuples_opened = all_tuples_opened && opened_flow.status == ProtocolStatus::Success;
    }
    for (std::size_t index = 0; index < quarantine_flows.size(); ++index) {
        static_cast<void>(
            quarantine_plane.CloseFlow(quarantine_clients[index / MaximumFlowsPerClient], quarantine_flows[index], 400 + index));
    }
    const auto exhausted = quarantine_plane.OpenConnectedUdpFlow(quarantine_clients[0], open, 500);
    const auto after_expiry =
        quarantine_plane.OpenConnectedUdpFlow(quarantine_clients[0], open, 500 + TunnelFlowPlane::ReverseTupleQuarantineNs + 1);
    WGNX_TEST_REQUIRE(context,
                      all_tuples_opened && exhausted.status == ProtocolStatus::ReverseTupleExhausted &&
                          after_expiry.status == ProtocolStatus::Success,
                      "tuple tombstones did not reserve close capacity or reject reuse until their fixed quarantine expired");
}

} // namespace wgnx::test
