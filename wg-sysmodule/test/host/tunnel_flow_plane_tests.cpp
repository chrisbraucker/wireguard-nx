#include "tunnel_flow_plane_tests.hpp"

#include "protocol_test_support.hpp"
#include "runtime/tunnel_flow_plane.hpp"

#include <array>

namespace wgnx::test {

namespace {

struct NotificationCounter {
    std::uint32_t count{0};
};

void Notify(void* context) {
    if (context != nullptr) {
        ++static_cast<NotificationCounter*>(context)->count;
    }
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

    config.mtu = 0;
    TunnelFlowPlane mtu_plane{};
    const TunnelClientId mtu_client = mtu_plane.CreateClient(nullptr, nullptr);
    mtu_plane.RefreshPolicy({.configuration = &config, .peer = first_peer, .selected = true}, 90);
    const auto default_mtu_capabilities = mtu_plane.GetCapabilities();
    const OpenConnectedUdpFlowRequest mtu_open{
        .remote = {.address = {10, 251, 0, 2}, .port = 29000, .reserved = 0},
        .diagnostic_tag = 0x4D5455,
    };
    const auto mtu_flow = mtu_plane.OpenConnectedUdpFlow(mtu_client, mtu_open, 91);
    std::array<std::uint8_t, 1392> default_mtu_payload{};
    std::array<std::uint8_t, MaximumUdpPayloadStorageBytes> fragmented_payload{};
    std::array<std::uint8_t, MaximumUdpPayloadStorageBytes + 1> oversized_payload{};
    const DatagramDescriptor default_mtu_descriptor{
        .flow = mtu_flow.flow,
        .payload_offset = 0,
        .payload_size = static_cast<std::uint32_t>(default_mtu_payload.size()),
        .client_tag = 0xD001,
    };
    const DatagramDescriptor fragmented_descriptor{
        .flow = mtu_flow.flow,
        .payload_offset = 0,
        .payload_size = static_cast<std::uint32_t>(fragmented_payload.size()),
        .client_tag = 0xD002,
    };
    const DatagramDescriptor oversized_descriptor{
        .flow = mtu_flow.flow,
        .payload_offset = 0,
        .payload_size = static_cast<std::uint32_t>(oversized_payload.size()),
        .client_tag = 0xD005,
    };
    const auto default_mtu_send = mtu_plane.PrepareSend(mtu_client, default_mtu_descriptor, default_mtu_payload, TransportReady, 92);
    const auto fragmented_default_mtu_send =
        mtu_plane.PrepareSend(mtu_client, fragmented_descriptor, fragmented_payload, TransportReady, 93);

    config.mtu = 1280;
    mtu_plane.RefreshPolicy({.configuration = &config, .peer = first_peer, .selected = true}, 94);
    const auto configured_mtu_capabilities = mtu_plane.GetCapabilities();
    std::array<std::uint8_t, 1252> configured_mtu_payload{};
    const DatagramDescriptor configured_mtu_descriptor{
        .flow = mtu_flow.flow,
        .payload_offset = 0,
        .payload_size = static_cast<std::uint32_t>(configured_mtu_payload.size()),
        .client_tag = 0xD003,
    };
    const auto configured_mtu_send =
        mtu_plane.PrepareSend(mtu_client, configured_mtu_descriptor, configured_mtu_payload, TransportReady, 95);
    const auto fragmented_configured_mtu_send =
        mtu_plane.PrepareSend(mtu_client, fragmented_descriptor, fragmented_payload, TransportReady, 96);
    const auto oversized_send = mtu_plane.PrepareSend(mtu_client, oversized_descriptor, oversized_payload, TransportReady, 97);
    WGNX_TEST_REQUIRE(
        context,
        mtu_flow.status == ProtocolStatus::Success && default_mtu_capabilities.effective_inner_mtu == 1420 &&
            default_mtu_capabilities.maximum_udp_payload_bytes == MaximumUdpPayloadStorageBytes &&
            default_mtu_send.status == ProtocolStatus::Success && default_mtu_send.IsPrepared() &&
            fragmented_default_mtu_send.status == ProtocolStatus::Success && fragmented_default_mtu_send.IsPrepared() &&
            configured_mtu_capabilities.effective_inner_mtu == 1280 &&
            configured_mtu_capabilities.maximum_udp_payload_bytes == MaximumUdpPayloadStorageBytes &&
            configured_mtu_send.status == ProtocolStatus::Success && configured_mtu_send.IsPrepared() &&
            fragmented_configured_mtu_send.status == ProtocolStatus::Success && fragmented_configured_mtu_send.IsPrepared() &&
            oversized_send.status == ProtocolStatus::DatagramTooLarge,
        "flow plane did not retain the fixed datagram bound independently of the effective inner MTU"
    );
    config.mtu = 1420;

    TunnelFlowPlane plane{};
    NotificationCounter notifications{};
    const TunnelClientId client = plane.CreateClient(Notify, &notifications);
    plane.RefreshPolicy({.configuration = &config, .peer = first_peer, .selected = true}, 100);

    std::array<RouteRecord, MaximumPolicyRoutes> routes{};
    const RoutingPolicySnapshot snapshot = plane.CopyRoutingPolicy(routes);
    WGNX_TEST_REQUIRE(
        context,
        client.IsValid() && snapshot.route_count == 2 && routes[0].prefix_length == 16 && routes[1].prefix_length == 8 &&
            routes[0].network_address[0] == 10 && routes[0].network_address[1] == 251 && notifications.count == 1,
        "flow plane did not create a client context or normalize longest-prefix routes"
    );

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
    const auto unavailable_result = plane.OpenConnectedUdpFlow(client, open, 125, TransportUnavailable);
    const auto opened_state = plane.GetFlowState(client, opened.flow);
    TunnelFlowPlane reservation_plane{};
    const TunnelClientId reservation_client = reservation_plane.CreateClient(nullptr, nullptr);
    reservation_plane.RefreshPolicy({.configuration = &config, .peer = first_peer, .selected = true}, 121);
    const auto reservation = reservation_plane.ReserveConnectedUdpFlow(reservation_client, open, 122, TransportReady);
    std::uint64_t adapter_token = 0;
    const bool hidden_before_commit =
        reservation.IsReserved() && !reservation_plane.GetFlowAdapterToken(reservation_client, reservation.result.flow, &adapter_token);
    const bool committed = reservation_plane.CommitFlowReservation(reservation) &&
                           reservation_plane.GetFlowAdapterToken(reservation_client, reservation.result.flow, &adapter_token) &&
                           adapter_token == reservation.result.flow.value;
    const auto stale_reservation = reservation_plane.ReserveConnectedUdpFlow(reservation_client, open, 123, TransportReady);
    reservation_plane.RefreshPolicy(
        {.configuration = &config,
         .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{8}},
         .selected = true},
        124
    );
    const bool stale_rejected = stale_reservation.IsReserved() && !reservation_plane.CommitFlowReservation(stale_reservation);
    reservation_plane.CancelFlowReservation(stale_reservation);
    config.mtu = 1280;
    plane.RefreshPolicy({.configuration = &config, .peer = first_peer, .selected = true}, 126);
    const RoutingPolicySnapshot policy_after_refresh = plane.CopyRoutingPolicy(routes);
    config.mtu = 1420;
    plane.RefreshPolicy({.configuration = &config, .peer = first_peer, .selected = true}, 127);
    const RoutingPolicySnapshot policy_after_second_refresh = plane.CopyRoutingPolicy(routes);
    WGNX_TEST_REQUIRE(
        context,
        uncovered_result.status == ProtocolStatus::RouteNotCovered && opened.status == ProtocolStatus::Success && hidden_before_commit &&
            committed && stale_rejected && unavailable_result.status == ProtocolStatus::TransportUnavailable &&
            opened.peer_activation_generation == first_peer.activation_generation.Value() &&
            opened_state.advertised_local.address[0] == 10 && opened_state.advertised_local.address[1] == 13 &&
            opened_state.advertised_local.address[2] == 13 && opened_state.advertised_local.address[3] == 8 &&
            opened_state.advertised_local.port != 0 && snapshot.policy_generation != policy_after_refresh.policy_generation &&
            policy_after_refresh.policy_generation != policy_after_second_refresh.policy_generation,
        "flow opening did not distinguish route coverage, availability, or peer activation, or policy generations did not advance"
    );

    config.leak_protection = true;
    TunnelFlowPlane protected_plane{};
    NotificationCounter protected_notifications{};
    const TunnelClientId protected_client = protected_plane.CreateClient(Notify, &protected_notifications);
    protected_plane.RefreshPolicy({.configuration = &config, .peer = first_peer, .selected = true}, 126);
    const auto blocked_result = protected_plane.OpenConnectedUdpFlow(protected_client, open, 127, TransportUnavailable);
    WGNX_TEST_REQUIRE(
        context,
        blocked_result.status == ProtocolStatus::TunnelBlockedByPolicy,
        "leak protection did not block a covered route with unavailable tunnel transport"
    );
    config.leak_protection = false;

    constexpr std::array<std::uint8_t, 5> Payload = {'h', 'e', 'l', 'l', 'o'};
    const DatagramDescriptor descriptor{
        .flow = opened.flow,
        .payload_offset = 0,
        .payload_size = static_cast<std::uint32_t>(Payload.size()),
        .client_tag = 99,
    };
    const auto not_ready = plane.PrepareSend(client, descriptor, Payload, TransportUnavailable, 130);
    const auto sent = plane.PrepareSend(client, descriptor, Payload, TransportReady, 140);
    WGNX_TEST_REQUIRE(
        context,
        not_ready.status == ProtocolStatus::TransportUnavailable && sent.status == ProtocolStatus::Success && sent.IsPrepared() &&
            sent.adapter_token == opened.flow.value,
        "flow send did not enforce transport availability or retain the stable adapter flow token"
    );

    const auto foreign = plane.DeliverInboundUdpDatagram(
        {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{8}},
        plane.PolicyGeneration(),
        opened.flow.value,
        open.remote,
        Payload,
        149
    );
    const auto delivered =
        plane.DeliverInboundUdpDatagram(first_peer, plane.PolicyGeneration(), opened.flow.value, open.remote, Payload, 150);
    std::array<CompletionRecord, MaximumBatchEntries> completions{};
    std::array<std::uint8_t, MaximumUdpPayloadStorageBytes> received_payload{};
    const auto received = plane.ReceiveCompletions(client, completions, received_payload);
    WGNX_TEST_REQUIRE(
        context,
        foreign.disposition == TunnelInboundDisposition::DroppedStale && delivered.disposition == TunnelInboundDisposition::Delivered &&
            received.status == ProtocolStatus::Success && received.count >= 1 && completions[0].type == CompletionType::PolicyChanged &&
            completions[1].type == CompletionType::InboundDatagram && completions[1].flow.value == opened.flow.value &&
            completions[1].payload_size == Payload.size() && std::equal(Payload.begin(), Payload.end(), received_payload.begin()),
        "flow receive did not retain the policy edge and generation-checked UDP callback in completion order"
    );

    const auto second_send = plane.PrepareSend(client, descriptor, Payload, TransportReady, 160);
    const auto second_delivery =
        plane.DeliverInboundUdpDatagram(first_peer, plane.PolicyGeneration(), opened.flow.value, open.remote, Payload, 170);
    std::array<std::uint8_t, 1> too_small{};
    const auto insufficient = plane.ReceiveCompletions(client, completions, too_small);
    const auto after_insufficient = plane.ReceiveCompletions(client, completions, received_payload);
    WGNX_TEST_REQUIRE(
        context,
        second_send.IsPrepared() && second_delivery.disposition == TunnelInboundDisposition::Delivered &&
            insufficient.status == ProtocolStatus::OutputBufferTooSmall && after_insufficient.status == ProtocolStatus::Success &&
            after_insufficient.count == 1 && completions[0].type == CompletionType::InboundDatagram,
        "completion draining emitted a partial datagram or lost it after an undersized buffer"
    );

    const std::uint32_t notifications_before_writable = notifications.count;
    const auto staging_full = plane.PrepareSend(client, descriptor, Payload, StagingFull, 175);
    plane.NotifyOutboundCapacityAvailable(first_peer);
    plane.NotifyOutboundCapacityAvailable(first_peer);
    const auto writable = plane.ReceiveCompletions(client, completions, received_payload);
    const auto retried_send = plane.PrepareSend(client, descriptor, Payload, TransportReady, 176);
    plane.CompleteSend(retried_send, ProtocolStatus::Success);
    WGNX_TEST_REQUIRE(
        context,
        staging_full.status == ProtocolStatus::QueueFull && writable.status == ProtocolStatus::Success && writable.count == 1 &&
            completions[0].type == CompletionType::Writable && completions[0].flow.value == opened.flow.value &&
            retried_send.status == ProtocolStatus::Success && notifications.count == notifications_before_writable + 1,
        "staging pressure did not report one coalesced writable transition and a successful retry without packet loss"
    );

    const auto close_status = plane.CloseFlow(client, opened.flow, 180);
    const auto delayed =
        plane.DeliverInboundUdpDatagram(first_peer, plane.PolicyGeneration(), opened.flow.value, open.remote, Payload, 181);
    const auto replacement = plane.OpenConnectedUdpFlow(client, open, 182);
    WGNX_TEST_REQUIRE(
        context,
        close_status == ProtocolStatus::Success && delayed.disposition == TunnelInboundDisposition::DroppedStale &&
            replacement.status == ProtocolStatus::Success && replacement.flow.value != opened.flow.value,
        "released reverse tuples were not quarantined before flow reuse"
    );

    plane.RefreshPolicy(
        {.configuration = &config,
         .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{8}},
         .selected = true},
        190
    );
    const auto stale_state = plane.GetFlowState(client, replacement.flow);
    WGNX_TEST_REQUIRE(
        context,
        stale_state.status == ProtocolStatus::FlowClosed && stale_state.terminal_reason == FlowTerminalReason::PolicyInvalidated,
        "peer activation transition did not close the old flow with a terminal state"
    );

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
    const std::uint16_t first_reuse_port = client_reuse_plane.GetFlowState(first_reuse_client, first_reuse_flow.flow).advertised_local.port;
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
    const std::uint16_t second_reuse_port =
        client_reuse_plane.GetFlowState(second_reuse_client, second_reuse_flow.flow).advertised_local.port;
    const auto second_reuse_delivery = client_reuse_plane.DeliverInboundUdpDatagram(
        first_peer,
        client_reuse_plane.PolicyGeneration(),
        second_reuse_flow.flow.value,
        open.remote,
        Payload,
        206
    );
    const auto second_reuse_received = client_reuse_plane.ReceiveCompletions(second_reuse_client, completions, received_payload);
    WGNX_TEST_REQUIRE(
        context,
        first_reuse_flow.status == ProtocolStatus::Success && first_reuse_send.status == ProtocolStatus::Success &&
            first_reuse_close == ProtocolStatus::Success && second_reuse_flow.status == ProtocolStatus::Success &&
            second_reuse_send.status == ProtocolStatus::Success && first_reuse_port != second_reuse_port &&
            second_reuse_delivery.disposition == TunnelInboundDisposition::Delivered &&
            second_reuse_received.status == ProtocolStatus::Success && second_reuse_received.count == 1 &&
            completions[0].type == CompletionType::InboundDatagram && completions[0].flow.value == second_reuse_flow.flow.value &&
            std::equal(Payload.begin(), Payload.end(), received_payload.begin()),
        "a fresh client flow did not receive its reply after a prior client closed the same remote tuple"
    );

    std::array<TunnelClientId, MaximumClientContexts - 1> extra_clients{};
    bool all_extra_created = true;
    for (TunnelClientId& extra : extra_clients) {
        extra = plane.CreateClient(nullptr, nullptr);
        all_extra_created = all_extra_created && extra.IsValid();
    }
    WGNX_TEST_REQUIRE(
        context,
        all_extra_created && !plane.CreateClient(nullptr, nullptr).IsValid(),
        "logical client contexts exceeded the fixed global limit"
    );

    const TunnelClientId released_client = extra_clients.front();
    plane.DestroyClient(released_client, 195);
    const TunnelClientId recycled_client = plane.CreateClient(nullptr, nullptr);
    WGNX_TEST_REQUIRE(
        context,
        recycled_client.IsValid() && recycled_client.slot == released_client.slot &&
            recycled_client.generation != released_client.generation,
        "destroyed tunnel client contexts were not returned with a stale-safe generation"
    );

    TunnelFlowPlane shutdown_plane{};
    NotificationCounter first_shutdown_notification{};
    NotificationCounter second_shutdown_notification{};
    const TunnelClientId first_shutdown_client = shutdown_plane.CreateClient(Notify, &first_shutdown_notification);
    const TunnelClientId second_shutdown_client = shutdown_plane.CreateClient(Notify, &second_shutdown_notification);
    const std::uint32_t shutdown_signaled = shutdown_plane.SignalAllClientCompletionEvents();
    const auto first_shutdown_drain = shutdown_plane.ReceiveCompletions(first_shutdown_client, completions, received_payload);
    const auto second_shutdown_drain = shutdown_plane.ReceiveCompletions(second_shutdown_client, completions, received_payload);
    WGNX_TEST_REQUIRE(
        context,
        first_shutdown_client.IsValid() && second_shutdown_client.IsValid() && shutdown_signaled == 2 &&
            first_shutdown_notification.count == 1 && second_shutdown_notification.count == 1 &&
            first_shutdown_drain.status == ProtocolStatus::QueueEmpty && second_shutdown_drain.status == ProtocolStatus::QueueEmpty,
        "sysmodule shutdown did not wake every tunnel client without fabricating completion records"
    );

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
        auto flow_request = open;
        flow_request.diagnostic_tag = index;
        const auto opened_flow =
            bounded_plane.OpenConnectedUdpFlow(bounded_client, flow_request, 202 + static_cast<wgnx::platform::ktime_t>(index));
        bounded_flows[index] = opened_flow.flow;
        all_bounded_flows_opened = all_bounded_flows_opened && opened_flow.status == ProtocolStatus::Success;
    }
    std::uint32_t delivered_count = 0;
    std::uint32_t dropped_count = 0;
    bool all_bounded_prepared = true;
    for (std::uint32_t sequence = 0; sequence < 8; ++sequence) {
        const DatagramDescriptor bounded_descriptor{
            .flow = bounded_flows[sequence % bounded_flows.size()],
            .payload_offset = 0,
            .payload_size = static_cast<std::uint32_t>(Payload.size()),
            .client_tag = sequence,
        };
        const auto outbound = bounded_plane.PrepareSend(bounded_client, bounded_descriptor, Payload, TransportReady, 210 + sequence);
        all_bounded_prepared = all_bounded_prepared && outbound.IsPrepared();
        const auto inbound = bounded_plane.DeliverInboundUdpDatagram(
            first_peer,
            bounded_plane.PolicyGeneration(),
            bounded_descriptor.flow.value,
            open.remote,
            Payload,
            220 + sequence
        );
        delivered_count += inbound.disposition == TunnelInboundDisposition::Delivered ? 1U : 0U;
        dropped_count += inbound.disposition == TunnelInboundDisposition::DroppedQueueFull ? 1U : 0U;
    }
    bounded_plane.RefreshPolicy(
        {.configuration = &config,
         .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{9}},
         .selected = true},
        230
    );
    const auto bounded_drain = bounded_plane.ReceiveCompletions(bounded_client, completions, received_payload);
    bool terminal_seen = false;
    for (std::uint32_t index = 0; index < bounded_drain.count; ++index) {
        terminal_seen = terminal_seen || completions[index].type == CompletionType::FlowStateChanged;
    }
    WGNX_TEST_REQUIRE(
        context,
        invalid_port_result.status == ProtocolStatus::MalformedInput && all_bounded_flows_opened && all_bounded_prepared &&
            delivered_count == 7 && dropped_count == 1 && bounded_drain.status == ProtocolStatus::Success && terminal_seen,
        "flow plane did not enforce invalid ports, bounded inbound completion pressure, or terminal notification reservation"
    );

    TunnelFlowPlane quarantine_plane{};
    std::array<TunnelClientId, MaximumClientContexts> quarantine_clients{};
    for (TunnelClientId& quarantine_client : quarantine_clients) {
        quarantine_client = quarantine_plane.CreateClient(nullptr, nullptr);
    }
    quarantine_plane.RefreshPolicy({.configuration = &config, .peer = first_peer, .selected = true}, 300);
    bool all_tuples_opened = true;
    std::array<FlowHandle, MaximumFlows> quarantine_flows{};
    for (std::size_t index = 0; index < quarantine_flows.size(); ++index) {
        const auto opened_flow = quarantine_plane.OpenConnectedUdpFlow(
            quarantine_clients[index / MaximumFlowsPerClient],
            open,
            301 + static_cast<wgnx::platform::ktime_t>(index)
        );
        quarantine_flows[index] = opened_flow.flow;
        all_tuples_opened = all_tuples_opened && opened_flow.status == ProtocolStatus::Success;
    }
    for (std::size_t index = 0; index < quarantine_flows.size(); ++index) {
        static_cast<void>(quarantine_plane.CloseFlow(
            quarantine_clients[index / MaximumFlowsPerClient],
            quarantine_flows[index],
            400 + static_cast<wgnx::platform::ktime_t>(index)
        ));
    }
    const auto exhausted = quarantine_plane.OpenConnectedUdpFlow(quarantine_clients[0], open, 500);
    const auto after_expiry =
        quarantine_plane.OpenConnectedUdpFlow(quarantine_clients[0], open, 500 + TunnelFlowPlane::ReverseTupleQuarantineNs + 1);
    WGNX_TEST_REQUIRE(
        context,
        all_tuples_opened && exhausted.status == ProtocolStatus::ReverseTupleExhausted && after_expiry.status == ProtocolStatus::Success,
        "tuple tombstones did not reserve close capacity or reject reuse until their fixed quarantine expired"
    );
}

} // namespace wgnx::test
