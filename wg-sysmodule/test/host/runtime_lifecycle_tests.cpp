#include "protocol_tests.hpp"
#include "protocol_test_support.hpp"

namespace wgnx::test {

void TestRuntimeResourceBudgets(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;

    static_assert(sizeof(PeerRuntime) <= wgnx::resource_budget::MaximumPeerRuntimeBytes);
    static_assert(sizeof(PeerRegistry) <= wgnx::resource_budget::MaximumPeerRegistryBytes);
    static_assert(sizeof(EffectBatch) <= wgnx::resource_budget::MaximumEffectBatchBytes);
    static_assert(sizeof(PacketChannel) <= wgnx::resource_budget::MaximumLegacyPacketChannelBytes);

    PendingSlotAccounting accounting{};
    accounting.RecordAdmission(false);
    accounting.RecordAdmission(true);
    const auto pressured = accounting.Statistics();
    accounting.RecordTake();
    accounting.RecordAdmission(false);
    accounting.RecordCancellation();
    const auto final = accounting.Statistics();

    WGNX_TEST_REQUIRE(context,
                      wgnx::resource_budget::PeerSlots == wgnx::MaxPeers && wgnx::resource_budget::ActivePeerSlots == 1 &&
                          wgnx::resource_budget::IpcServerPorts == 2 && wgnx::resource_budget::IpcSessions == 8 &&
                          wgnx::resource_budget::PeerOutboundStagingSlots == wgnx::wireguard::PeerStagedPacketCapacity &&
                          wgnx::resource_budget::LegacyPacketChannelReceiveSlots == PacketChannel::ReceiveCapacity &&
                          wgnx::resource_budget::EffectBatchSlots == EffectBatch::Capacity &&
                          wgnx::resource_budget::MainThreadStackBytes == 16 * 1024 && pressured.depth == 1 &&
                          pressured.high_watermark == 1 && pressured.admitted == 2 && pressured.replaced == 1 && pressured.coalesced == 0 &&
                          pressured.taken == 0 && final.depth == 0 && final.admitted == 3 && final.taken == 1 && final.cancelled == 1,
                      "central runtime capacities or pending-slot pressure accounting diverged");
}

void TestRuntimeTypedRejections(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::wireguard;

    runtime::Reset(InitialRuntimeState);
    std::array<wgnx::PeerConfigEntry, 1> configured{};
    FillConfig(&configured[0], "typed-rejections", "10.66.66.2/32", InitiatorPrivateKey, ResponderPublicKey);
    PeerRegistry registry{};
    RuntimeCoordinator coordinator{registry};
    PacketChannel channel{};
    PacketDataPlane data_plane{coordinator, channel};
    EffectBatch effects{};
    constexpr ProcessId Consumer{400};
    constexpr std::array<std::uint8_t, 20> ValidPacket = {
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0xE2, 0x52, 0x0A, 0x42, 0x42, 0x02, 0x0A, 0x42, 0x42, 0x01,
    };
    constexpr std::array<std::uint8_t, 3> MalformedPacket = {0x45, 0x00, 0x00};
    const TimerFacts timer_facts{
        .now = TimerDeadlineFromJiffies(500),
    };

    WGNX_TEST_REQUIRE(context, ConfigureTestPeers(coordinator, configured, 0), "typed rejection registry setup failed");
    const auto malformed_submission = data_plane.SubmitIpv4Packet(MalformedPacket, Consumer, timer_facts, 100, effects);
    const auto unavailable_submission = data_plane.SubmitIpv4Packet(ValidPacket, Consumer, timer_facts, 200, effects);
    WGNX_TEST_REQUIRE(context,
                      malformed_submission.status == PacketSubmissionStatus::MalformedPacket &&
                          unavailable_submission.status == PacketSubmissionStatus::TunnelUnavailable,
                      "submission rejection did not distinguish malformed input from tunnel state");

    const auto activation = coordinator.Dispatch(ActivationRequestedEvent{
        .peer_index = PeerIndex{0},
        .occurred_at = 300,
    });
    const auto* start = activation.Size() == 1 ? std::get_if<StartNetworkPathRequestEffect>(activation.begin()) : nullptr;
    const auto permitted = start != nullptr ? AllowTestLocalPath(coordinator, *start, 350) : EffectBatch{};
    const auto* resolve = permitted.Size() == 1 ? std::get_if<ResolveEndpointEffect>(permitted.begin()) : nullptr;
    const auto pre_protocol_submission = data_plane.SubmitIpv4Packet(ValidPacket, Consumer, timer_facts, 400, effects);
    WGNX_TEST_REQUIRE(context, resolve != nullptr && pre_protocol_submission.status == PacketSubmissionStatus::InternalError,
                      "submission rejection did not preserve the pre-protocol invalid state");

    const auto activated = CompleteTestPeerActivation(coordinator, *resolve, 92, 500);
    const PeerIdentity identity{
        .peer_index = PeerIndex{0},
        .activation_generation = ActivationGeneration{1},
    };
    WGNX_TEST_REQUIRE(
        context, !activated.Empty() && data_plane.DeliverDecryptedPacket(identity, ValidPacket).status == PacketDeliveryStatus::NoConsumer,
        "delivery rejection did not preserve the no-consumer state");

    static_cast<void>(channel.Claim(Consumer));
    std::array<std::uint8_t, MaxInnerIpPacketSize> output{};
    const auto malformed_delivery = data_plane.DeliverDecryptedPacket(identity, MalformedPacket);
    const auto stale_delivery = data_plane.DeliverDecryptedPacket(
        PeerIdentity{
            .peer_index = PeerIndex{0},
            .activation_generation = ActivationGeneration{2},
        },
        ValidPacket);
    const auto empty_receive = data_plane.ReceivePacket(output, Consumer);
    WGNX_TEST_REQUIRE(context,
                      malformed_delivery.status == PacketDeliveryStatus::MalformedPacket &&
                          stale_delivery.status == PacketDeliveryStatus::StalePeer &&
                          empty_receive.status == PacketReceiveStatus::QueueEmpty,
                      "delivery and receive rejection outcomes were conflated");

    bool filled = true;
    for (std::size_t index = 0; index < PeerStagedPacketCapacity; ++index) {
        const auto submission =
            data_plane.SubmitIpv4Packet(ValidPacket, Consumer, timer_facts, 600 + static_cast<wgnx::platform::ktime_t>(index), effects);
        filled = filled && submission.status == PacketSubmissionStatus::Queued;
    }
    const auto full_submission = data_plane.SubmitIpv4Packet(ValidPacket, Consumer, timer_facts, 700, effects);
    WGNX_TEST_REQUIRE(context, filled && full_submission.status == PacketSubmissionStatus::QueueFull,
                      "submission rejection did not expose bounded staging capacity");
}

void TestAuxiliaryRuntimeWorkflows(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;

    DebugProbeRunner probes{};
    const PeerIdentity peer{.peer_index = PeerIndex{2}, .activation_generation = ActivationGeneration{7}};
    const auto unsupported_probe = probes.Queue(peer, "10.13.13.8/24", wgnx::DebugTriggerAction::None, 900'000'000);
    const auto invalid_source_probe = probes.Queue(peer, {}, wgnx::DebugTriggerAction::PingTunnelPeer, 950'000'000);
    const auto valid_probe = probes.Queue(peer, "10.13.13.8/24", wgnx::DebugTriggerAction::PingTunnelPeer, 1'000'000'000);
    const auto busy_probe = probes.Queue(peer, "10.13.13.8/24", wgnx::DebugTriggerAction::PingTunnelPeer, 1'100'000'000);
    WGNX_TEST_REQUIRE(context,
                      unsupported_probe == DebugProbeQueueResult::UnsupportedAction &&
                          invalid_source_probe == DebugProbeQueueResult::InvalidSource && valid_probe == DebugProbeQueueResult::Queued &&
                          busy_probe == DebugProbeQueueResult::Busy && probes.IsPending() &&
                          probes.Status() == wgnx::DebugProbeStatus::Queued,
                      "debug probe runner rejected a valid command");

    DebugProbeRequest request{};
    std::array<std::uint8_t, wgnx::wireguard::DebugProbePacketSize> packet{};
    WGNX_TEST_REQUIRE(context,
                      probes.TakePending(request) && probes.BuildPacket(request, packet, 0x12345678) == packet.size() &&
                          probes.MarkSent(request, 2'000'000'000) && probes.Status() == wgnx::DebugProbeStatus::Sent &&
                          probes.HandleTimeout(3'000'000'000) && probes.Status() == wgnx::DebugProbeStatus::TimedOut,
                      "debug probe command lifecycle diverged");

    wgnx::PeerInfo projected{};
    probes.Project(peer.peer_index.Value(), 5'000'000'000, projected);
    WGNX_TEST_REQUIRE(context,
                      projected.debug_probe_action == static_cast<std::uint32_t>(wgnx::DebugTriggerAction::PingTunnelPeer) &&
                          projected.debug_probe_status == static_cast<std::uint32_t>(wgnx::DebugProbeStatus::TimedOut) &&
                          projected.last_debug_probe_seconds == 2,
                      "debug probe status projection diverged");

    UdpRebindQueue rebinds{};
    const UdpRebindRequest rebind{.peer_index = PeerIndex{1}, .activation_generation = ActivationGeneration{9}};
    const auto first_rebind = rebinds.Queue(rebind);
    const auto replacement_rebind = rebinds.Queue(rebind);
    const auto rebind_statistics = rebinds.Statistics();
    const bool pending_before_take = rebinds.IsPending(rebind);
    const auto taken = rebinds.Take();
    const auto consumed_rebind_statistics = rebinds.Statistics();
    WGNX_TEST_REQUIRE(context,
                      first_rebind == UdpRebindQueueResult::Scheduled && replacement_rebind == UdpRebindQueueResult::Replaced &&
                          rebind_statistics.admitted == 2 && rebind_statistics.replaced == 1 && rebind_statistics.depth == 1 &&
                          rebind_statistics.high_watermark == 1 && pending_before_take && taken.has_value() &&
                          consumed_rebind_statistics.depth == 0 && consumed_rebind_statistics.taken == 1 &&
                          taken->peer_index == rebind.peer_index && taken->activation_generation == rebind.activation_generation &&
                          !rebinds.Take().has_value(),
                      "UDP rebind request ownership or coalescing diverged");
}

void TestRuntimeContracts(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;

    WGNX_TEST_REQUIRE(context,
                      IsValidPeerSelection(-1, 0) && !IsValidPeerSelection(0, 0) && !IsValidPeerSelection(-2, 8) &&
                          IsValidPeerSelection(0, 8) && IsValidPeerSelection(7, 8) && !IsValidPeerSelection(8, 8),
                      "peer selection no longer accepts exactly disabled or a configured index");

    WGNX_TEST_REQUIRE(context,
                      BuildDaemonFlags(false, false) == wgnx::DaemonFlag_Ready &&
                          BuildDaemonFlags(true, false) == (wgnx::DaemonFlag_Ready | wgnx::DaemonFlag_TunnelActive) &&
                          BuildDaemonFlags(false, true) == (wgnx::DaemonFlag_Ready | wgnx::DaemonFlag_HasErrors) &&
                          BuildDaemonFlags(true, true) ==
                              (wgnx::DaemonFlag_Ready | wgnx::DaemonFlag_TunnelActive | wgnx::DaemonFlag_HasErrors),
                      "daemon status flags diverged from active-peer or error state");

    WGNX_TEST_REQUIRE(context,
                      BuildPeerFlags(true, true, true, wgnx::PeerRuntimeState::Error, true) ==
                              (wgnx::PeerFlag_Active | wgnx::PeerFlag_AutoStart | wgnx::PeerFlag_Established | wgnx::PeerFlag_HasError |
                               wgnx::PeerFlag_HasResolvedEndpoint) &&
                          BuildPeerFlags(false, false, false, wgnx::PeerRuntimeState::Active, false) == 0,
                      "peer status flags no longer project lifecycle state independently");

    WGNX_TEST_REQUIRE(context,
                      IsCurrentGeneration(ActivationGeneration{1}, ActivationGeneration{1}) &&
                          IsCurrentGeneration(ActivationGeneration{0xffffffffU}, ActivationGeneration{0xffffffffU}) &&
                          !IsCurrentGeneration(ActivationGeneration{}, ActivationGeneration{}) &&
                          !IsCurrentGeneration(ActivationGeneration{1}, ActivationGeneration{2}),
                      "generation matching accepted an unallocated or stale generation");

    static_assert(!std::equality_comparable_with<PeerIndex, ActivationGeneration>);
    static_assert(!std::equality_comparable_with<SocketGeneration, DatagramGeneration>);
    static_assert(!std::equality_comparable_with<PacketGeneration, PacketId>);
    static_assert(!std::equality_comparable_with<PacketId, ProcessId>);

    WGNX_TEST_REQUIRE(context,
                      MaxEffectsForEvent<ActivationRequestedEvent>() == 5 && MaxEffectsForEvent<DeactivationRequestedEvent>() == 7 &&
                          MaxEffectsForEvent<NetworkPathRequestStartedEvent>() == 5 &&
                          MaxEffectsForEvent<NetworkPathAvailabilityChangedEvent>() == 7 &&
                          MaxEffectsForEvent<TransportFailureEvent>() == 6 && MaxEffectsForEvent<EndpointResolvedEvent>() == 5 &&
                          MaxEffectsForEvent<UdpBindOpenedEvent>() == 7 && MaxEffectsForEvent<UdpRebindRequestedEvent>() == 1 &&
                          MaxEffectsForEvent<EncryptedDatagramReceivedEvent>() == 6 &&
                          MaxEffectsForEvent<PendingDatagramSentEvent>() == 5 && MaxEffectsForEvent<InnerPacketStagedEvent>() == 5 &&
                          MaxEffectsForEvent<ProcessOutboundQueueEvent>() == 5 && MaxEffectsForEvent<ProtocolTimerExpiredEvent>() == 6,
                      "peer event effect budgets no longer cover every closed event path");
}

void TestNifmPathGating(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;

    runtime::Reset(InitialRuntimeState);
    std::array<wgnx::PeerConfigEntry, 1> configured{};
    FillConfig(&configured[0], "nifm-path", "10.66.66.2/32", InitiatorPrivateKey, ResponderPublicKey);
    PeerRegistry registry{};
    RuntimeCoordinator coordinator{registry};
    WGNX_TEST_REQUIRE(context, ConfigureTestPeers(coordinator, configured, 0), "NIFM path test registry setup failed");

    const auto activation = coordinator.Dispatch(ActivationRequestedEvent{
        .peer_index = PeerIndex{0},
        .occurred_at = 1'000,
    });
    const auto* start = activation.Size() == 1 ? std::get_if<StartNetworkPathRequestEffect>(activation.begin()) : nullptr;
    WGNX_TEST_REQUIRE(context,
                      start != nullptr && !start->path_generation.IsZero() &&
                          coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::ResolvingEndpoint,
                      "activation did not create one generation-tagged NIFM request");

    const auto pending = coordinator.Dispatch(NetworkPathAvailabilityChangedEvent{
        .peer = start->peer,
        .path_generation = start->path_generation,
        .observation =
            {
                .availability = wgnx::platform::classify_network_path_state(wgnx::platform::network_path_raw_state::pending),
                .raw_state = wgnx::platform::network_path_raw_state::pending,
                .request_generation = start->path_generation.Value(),
            },
        .occurred_at = 1'001,
    });
    WGNX_TEST_REQUIRE(context, pending.Empty(), "pending NIFM path opened transport work before local availability");

    const auto permitted = AllowTestLocalPath(coordinator, *start, 1'003);
    const auto* resolve = permitted.Size() == 1 ? std::get_if<ResolveEndpointEffect>(permitted.begin()) : nullptr;
    const auto handshake = resolve != nullptr ? CompleteTestPeerActivation(coordinator, *resolve, 77, 1'004) : EffectBatch{};
    WGNX_TEST_REQUIRE(context, resolve != nullptr && !handshake.Empty() && coordinator.BindingSnapshot(0).IsOpen(),
                      "available local path did not permit one normal activation");

    const auto binding_before_indeterminate = coordinator.BindingSnapshot(0);
    const auto indeterminate = coordinator.Dispatch(NetworkPathAvailabilityChangedEvent{
        .peer = start->peer,
        .path_generation = start->path_generation,
        .observation =
            {
                .availability = wgnx::platform::network_path_availability::unknown,
                .raw_state = wgnx::platform::network_path_raw_state::unknown4,
                .request_generation = start->path_generation.Value(),
            },
        .occurred_at = 1'005,
    });
    const auto confirmation_rebind = AllowTestLocalPath(coordinator, *start, 1'006);
    const auto* confirmed_rebind = confirmation_rebind.Size() == 1 ? std::get_if<OpenUdpBindEffect>(confirmation_rebind.begin()) : nullptr;
    const auto duplicate_available = AllowTestLocalPath(coordinator, *start, 1'007);
    WGNX_TEST_REQUIRE(
        context,
        indeterminate.Empty() &&
            coordinator.BindingSnapshot(0).Matches(binding_before_indeterminate.generation, binding_before_indeterminate.socket) &&
            confirmed_rebind != nullptr && confirmed_rebind->purpose == UdpBindPurpose::Rebind &&
            confirmed_rebind->replaces_socket == binding_before_indeterminate.socket && duplicate_available.Empty(),
        "indeterminate-to-available NIFM recovery did not request exactly one controlled rebind");

    const auto confirmed_rebind_completion = confirmed_rebind != nullptr
                                                 ? coordinator.Dispatch(UdpBindOpenedEvent{
                                                       .peer = confirmed_rebind->peer,
                                                       .path_generation = confirmed_rebind->path_generation,
                                                       .endpoint = confirmed_rebind->endpoint,
                                                       .endpoint_text = confirmed_rebind->endpoint_text,
                                                       .socket = 78,
                                                       .error = wgnx::platform::socket_error::none,
                                                       .socket_generation = confirmed_rebind->socket_generation,
                                                       .purpose = confirmed_rebind->purpose,
                                                       .timer_facts =
                                                           {
                                                               .now = wgnx::wireguard::TimerDeadlineFromJiffies(500),
                                                           },
                                                       .occurred_at = 1'008,
                                                   })
                                                 : EffectBatch{};
    WGNX_TEST_REQUIRE(
        context, !confirmed_rebind_completion.Empty() && coordinator.BindingSnapshot(0).Matches(confirmed_rebind->socket_generation, 78),
        "confirmed indeterminate-path rebind did not adopt its replacement binding");

    const auto suspended = coordinator.Dispatch(NetworkPathAvailabilityChangedEvent{
        .peer = start->peer,
        .path_generation = start->path_generation,
        .observation =
            {
                .availability = wgnx::platform::classify_network_path_state(wgnx::platform::network_path_raw_state::on_hold),
                .raw_state = wgnx::platform::network_path_raw_state::on_hold,
                .request_generation = start->path_generation.Value(),
            },
        .occurred_at = 1'010,
    });
    const auto binding_after_loss = coordinator.BindingSnapshot(0);
    const auto blocked_rebind = coordinator.Dispatch(UdpRebindRequestedEvent{
        .peer = start->peer,
        .occurred_at = 1'010,
    });
    const auto resumed = AllowTestLocalPath(coordinator, *start, 1'011);
    const auto* rebind = resumed.Size() == 1 ? std::get_if<OpenUdpBindEffect>(resumed.begin()) : nullptr;
    WGNX_TEST_REQUIRE(context,
                      !suspended.Empty() && binding_after_loss.suspended && !binding_after_loss.IsOpen() && blocked_rebind.Empty() &&
                          rebind != nullptr && rebind->purpose == UdpBindPurpose::Rebind &&
                          rebind->replaces_socket == wgnx::platform::InvalidSocket,
                      "OnHold local-path loss did not suspend once and resume through rebind");

    const auto pending_rebind_completion = rebind != nullptr ? coordinator.Dispatch(UdpBindOpenedEvent{
                                                                   .peer = rebind->peer,
                                                                   .path_generation = rebind->path_generation,
                                                                   .endpoint = rebind->endpoint,
                                                                   .endpoint_text = rebind->endpoint_text,
                                                                   .socket = 79,
                                                                   .error = wgnx::platform::socket_error::none,
                                                                   .socket_generation = rebind->socket_generation,
                                                                   .purpose = rebind->purpose,
                                                                   .timer_facts =
                                                                       {
                                                                           .now = wgnx::wireguard::TimerDeadlineFromJiffies(600),
                                                                       },
                                                                   .occurred_at = 1'012,
                                                               })
                                                             : EffectBatch{};
    const auto pending_after_available = coordinator.Dispatch(NetworkPathAvailabilityChangedEvent{
        .peer = start->peer,
        .path_generation = start->path_generation,
        .observation =
            {
                .availability = wgnx::platform::classify_network_path_state(wgnx::platform::network_path_raw_state::pending),
                .raw_state = wgnx::platform::network_path_raw_state::pending,
                .request_generation = start->path_generation.Value(),
            },
        .occurred_at = 1'013,
    });
    const auto binding_after_pending = coordinator.BindingSnapshot(0);
    const auto pending_blocked_rebind = coordinator.Dispatch(UdpRebindRequestedEvent{
        .peer = start->peer,
        .occurred_at = 1'013,
    });
    const auto pending_resumed = AllowTestLocalPath(coordinator, *start, 1'014);
    const auto* pending_rebind = pending_resumed.Size() == 1 ? std::get_if<OpenUdpBindEffect>(pending_resumed.begin()) : nullptr;
    const auto close_count = std::ranges::count_if(pending_after_available,
                                                   [](const auto& effect) { return std::holds_alternative<CloseUdpSocketEffect>(effect); });
    WGNX_TEST_REQUIRE(context,
                      !pending_rebind_completion.Empty() && binding_after_pending.suspended && !binding_after_pending.IsOpen() &&
                          close_count == 1 && pending_blocked_rebind.Empty() && pending_rebind != nullptr &&
                          pending_rebind->purpose == UdpBindPurpose::Rebind,
                      "Pending local-path loss did not close once and gate rebinding until Available");

    const auto stale = coordinator.Dispatch(NetworkPathAvailabilityChangedEvent{
        .peer = start->peer,
        .path_generation = PathRequestGeneration{start->path_generation.Value() + 1},
        .observation =
            {
                .availability = wgnx::platform::network_path_availability::unavailable,
                .raw_state = wgnx::platform::network_path_raw_state::on_hold,
            },
        .occurred_at = 1'015,
    });
    WGNX_TEST_REQUIRE(context, stale.Empty(), "stale NIFM request observation affected the active peer");
}

void TestPeerRegistryOwnership(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;

    std::array<wgnx::PeerConfigEntry, 2> configured{};
    std::snprintf(configured[0].name.data(), configured[0].name.size(), "first");
    FillConfig(&configured[1], "second", "10.66.66.2/32", InitiatorPrivateKey, ResponderPublicKey);

    PeerRegistry registry{};
    RuntimeCoordinator coordinator{registry};
    WGNX_TEST_REQUIRE(context,
                      coordinator.Empty() && coordinator.ActivePeerIndex() == -1 && coordinator.AutoStartPeerIndex() == -1 &&
                          coordinator.IsValidSelection(-1) && !coordinator.IsValidSelection(0),
                      "empty peer registry exposed a configured or selected peer");
    WGNX_TEST_REQUIRE(context,
                      ConfigureTestPeers(coordinator, configured, 1, 0) && coordinator.PeerCount() == configured.size() &&
                          coordinator.IsValidSelection(0) && coordinator.IsValidSelection(1) && !coordinator.IsValidSelection(2) &&
                          std::strcmp(coordinator.Configuration(0)->name.data(), "first") == 0 &&
                          std::strcmp(coordinator.Configuration(1)->name.data(), "second") == 0,
                      "peer registry did not preserve fixed-slot configuration identity");

    WGNX_TEST_REQUIRE(context,
                      coordinator.SetActivePeerIndex(1) && coordinator.SetAutoStartPeerIndex(0) && !coordinator.SetActivePeerIndex(2) &&
                          !coordinator.SetAutoStartPeerIndex(-2),
                      "peer registry accepted an out-of-range selection");
    const auto first_activation = coordinator.Dispatch(ActivationRequestedEvent{
        .peer_index = PeerIndex{0},
        .occurred_at = 6,
    });
    const auto second_activation = ActivateTestPeer(coordinator, 1, 41, 8);
    const auto first_protocol = coordinator.ProtocolSnapshot(0);
    const auto second_protocol = coordinator.ProtocolSnapshot(1);

    WGNX_TEST_REQUIRE(context,
                      first_activation.Empty() && second_activation.Size() == 1 && coordinator.ActivePeerIndex() == 1 &&
                          coordinator.AutoStartPeerIndex() == 0 && coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Error &&
                          coordinator.Lifecycle(0)->activation_generation == ActivationGeneration{} && !first_protocol.instantiated &&
                          coordinator.Lifecycle(1)->state == wgnx::PeerRuntimeState::Handshaking &&
                          coordinator.Lifecycle(1)->activation_generation == ActivationGeneration{1} && second_protocol.instantiated,
                      "peer runtime slots did not isolate index-correlated mutable state");

    static_cast<void>(coordinator.ClearConfiguration(20));
    WGNX_TEST_REQUIRE(context,
                      coordinator.Empty() && coordinator.ActivePeerIndex() == -1 && coordinator.AutoStartPeerIndex() == -1 &&
                          coordinator.IsValidSelection(-1) && !coordinator.IsValidSelection(0),
                      "clearing peer configuration retained selection state");
}

void TestPeerRuntimeLifecycle(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::wireguard;

    std::array<wgnx::PeerConfigEntry, 1> configured{};
    FillConfig(&configured[0], "lifecycle", "10.66.66.2/32", InitiatorPrivateKey, ResponderPublicKey);
    configured[0].persistent_keepalive = 25;
    PeerRegistry registry{};
    RuntimeCoordinator coordinator{registry};
    WGNX_TEST_REQUIRE(context,
                      ConfigureTestPeers(coordinator, configured, 0, -1, 1'000) &&
                          coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Inactive &&
                          coordinator.Lifecycle(0)->activation_generation == ActivationGeneration{} &&
                          coordinator.Lifecycle(0)->persistent_keepalive_interval == 25,
                      "inactive lifecycle diverged");

    const auto activation = coordinator.Dispatch(ActivationRequestedEvent{
        .peer_index = PeerIndex{0},
        .occurred_at = 3'000,
    });
    WGNX_TEST_REQUIRE(context,
                      activation.Size() == 1 && coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::ResolvingEndpoint &&
                          coordinator.IsActiveIdentity({.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{1}}) &&
                          !coordinator.IsActiveIdentity({.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{2}}),
                      "activation start or generation ownership diverged");

    const auto* start = std::get_if<StartNetworkPathRequestEffect>(activation.begin());
    const auto permitted = start != nullptr ? AllowTestLocalPath(coordinator, *start, 3'500) : EffectBatch{};
    const auto* resolve = permitted.Size() == 1 ? std::get_if<ResolveEndpointEffect>(permitted.begin()) : nullptr;
    const auto opened = resolve != nullptr ? CompleteTestPeerActivation(coordinator, *resolve, 42, 4'000) : EffectBatch{};
    const auto binding = coordinator.BindingSnapshot(0);
    WGNX_TEST_REQUIRE(context,
                      opened.Size() == 1 && coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Handshaking && binding.IsOpen(),
                      "activation did not enter peer-owned handshaking state");

    const auto failure = coordinator.Dispatch(TransportFailureEvent{
        .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{2}},
        .socket = binding.socket,
        .socket_generation = binding.generation,
        .error = wgnx::platform::socket_error::open_failed,
        .occurred_at = 11'000,
    });
    WGNX_TEST_REQUIRE(context, failure.Empty(), "stale failure mutated lifecycle state");
    const auto fatal = coordinator.Dispatch(TransportFailureEvent{
        .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{1}},
        .socket = binding.socket,
        .socket_generation = binding.generation,
        .error = wgnx::platform::socket_error::open_failed,
        .occurred_at = 11'000,
    });
    const auto error_info = coordinator.BuildPeerInfo(0, 11'000);
    WGNX_TEST_REQUIRE(context,
                      !fatal.Empty() && error_info.runtime_state == static_cast<std::uint8_t>(wgnx::PeerRuntimeState::Error) &&
                          error_info.error_stage == static_cast<std::uint8_t>(wgnx::PeerErrorStage::Transport) &&
                          error_info.last_error_code == static_cast<std::uint32_t>(wgnx::PeerErrorCode::TransportOpenFailed) &&
                          (error_info.flags & wgnx::PeerFlag_HasError) != 0 && (error_info.flags & wgnx::PeerFlag_Established) == 0,
                      "error status snapshot diverged from lifecycle state");

    static_cast<void>(coordinator.Dispatch(DeactivationRequestedEvent{
        .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{1}},
        .occurred_at = 12'000,
    }));
    WGNX_TEST_REQUIRE(context,
                      coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Inactive &&
                          coordinator.Lifecycle(0)->activation_generation == ActivationGeneration{} &&
                          coordinator.Lifecycle(0)->rx_bytes == 0 && coordinator.Lifecycle(0)->tx_bytes == 0,
                      "deactivation retained activation or metrics");
}

void TestRuntimeCoordinatorDispatch(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;

    std::array<wgnx::PeerConfigEntry, 1> configured{};
    FillConfig(&configured[0], "coordinator", "10.66.66.2/32", InitiatorPrivateKey, ResponderPublicKey);
    PeerRegistry registry{};
    RuntimeCoordinator coordinator{registry};
    WGNX_TEST_REQUIRE(context, ConfigureTestPeers(coordinator, configured, 0) && !ActivateTestPeer(coordinator, 0, 43).Empty(),
                      "coordinator test could not establish handshaking state");

    const auto out_of_range = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = {.peer_index = PeerIndex{1}, .activation_generation = ActivationGeneration{1}},
        .occurred_at = 3'000,
    });
    const auto stale = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{2}},
        .occurred_at = 3'000,
    });
    WGNX_TEST_REQUIRE(context,
                      out_of_range.Empty() && stale.Empty() && coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Handshaking &&
                          coordinator.Lifecycle(0)->activation_generation == ActivationGeneration{1},
                      "coordinator accepted an out-of-range or stale event");

    const auto effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{1}},
        .occurred_at = 4'000,
    });
    WGNX_TEST_REQUIRE(context, effects.Empty() && coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Handshaking,
                      "coordinator accepted session completion without protocol state");

    const auto binding = coordinator.BindingSnapshot(0);
    const auto stale_failure = coordinator.Dispatch(TransportFailureEvent{
        .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{2}},
        .socket = binding.socket,
        .socket_generation = binding.generation,
        .error = wgnx::platform::socket_error::receive_failed,
        .occurred_at = 4'500,
    });
    const auto failure = coordinator.Dispatch(TransportFailureEvent{
        .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{1}},
        .socket = binding.socket,
        .socket_generation = binding.generation,
        .error = wgnx::platform::socket_error::receive_failed,
        .occurred_at = 5'000,
    });
    const auto binding_after_failure = coordinator.BindingSnapshot(0);
    WGNX_TEST_REQUIRE(context,
                      stale_failure.Empty() && failure.Empty() && binding_after_failure.Matches(binding.generation, binding.socket) &&
                          coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Handshaking,
                      "receive failure event did not preserve the current binding");

    static_cast<void>(coordinator.Dispatch(DeactivationRequestedEvent{
        .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{1}},
        .occurred_at = 6'000,
    }));
    WGNX_TEST_REQUIRE(context,
                      coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Inactive &&
                          coordinator.Lifecycle(0)->activation_generation == ActivationGeneration{},
                      "deactivation event did not retire peer-owned lifecycle state");

    EffectBatch bounded{};
    const RuntimeEffect effect = QueueInnerPacketSubmissionEffect{
        .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{1}},
    };
    bool filled = true;
    for (std::size_t index = 0; index < EffectBatch::Capacity; ++index) {
        filled = filled && bounded.TryAdd(effect) == EffectBatch::InsertionResult::Inserted;
    }
    WGNX_TEST_REQUIRE(context,
                      filled && bounded.Size() == EffectBatch::Capacity &&
                          bounded.TryAdd(effect) == EffectBatch::InsertionResult::CapacityExhausted,
                      "runtime effect batch did not enforce fixed capacity");

    EffectBatch first{};
    EffectBatch second{};
    WGNX_TEST_REQUIRE(context,
                      first.TryAdd(QueueReceiveEffect{
                          .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{1}},
                      }) == EffectBatch::InsertionResult::Inserted &&
                          second.TryAdd(SendPendingDatagramEffect{
                              .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{1}},
                              .datagram_generation = DatagramGeneration{7},
                          }) == EffectBatch::InsertionResult::Inserted &&
                          first.TryAppend(second) == EffectBatch::InsertionResult::Inserted && first.Size() == 2 &&
                          std::holds_alternative<QueueReceiveEffect>(*first.begin()) &&
                          std::holds_alternative<SendPendingDatagramEffect>(*(first.begin() + 1)) &&
                          bounded.TryAppend(second) == EffectBatch::InsertionResult::CapacityExhausted &&
                          bounded.Size() == EffectBatch::Capacity,
                      "runtime effect batch append lost ordering or violated bounded capacity");
    bounded.Clear();
    WGNX_TEST_REQUIRE(context, bounded.Empty() && bounded.TryAdd(effect) == EffectBatch::InsertionResult::Inserted && bounded.Size() == 1,
                      "runtime effect batch could not be reused by the ordered receive worker");
}

void TestRuntimePeerActivation(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::wireguard;

    runtime::Reset(InitialRuntimeState);
    std::array<wgnx::PeerConfigEntry, 1> configured{};
    FillConfig(&configured[0], "activation", "10.66.66.2/32", InitiatorPrivateKey, ResponderPublicKey);

    PeerRegistry registry{};
    RuntimeCoordinator coordinator{registry};
    WGNX_TEST_REQUIRE(context, ConfigureTestPeers(coordinator, configured, 0), "activation test registry initialization failed");
    const auto activation = coordinator.Dispatch(ActivationRequestedEvent{
        .peer_index = PeerIndex{0},
        .occurred_at = 1'000,
    });
    const auto* start = activation.Size() == 1 ? std::get_if<StartNetworkPathRequestEffect>(activation.begin()) : nullptr;
    const auto permitted = start != nullptr ? AllowTestLocalPath(coordinator, *start, 1'100) : EffectBatch{};
    const auto* resolve = permitted.Size() == 1 ? std::get_if<ResolveEndpointEffect>(permitted.begin()) : nullptr;
    const PeerIdentity expected_activation{.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{1}};
    WGNX_TEST_REQUIRE(
        context,
        resolve != nullptr && resolve->peer == expected_activation && std::strcmp(resolve->endpoint.data(), "peer.test:51820") == 0 &&
            coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::ResolvingEndpoint && !coordinator.ProtocolSnapshot(0).instantiated,
        "activation did not enter resolution with a generation-tagged request");

    EndpointResolver resolver{};
    ResolveEndpointEffect replacement = *resolve;
    replacement.peer.activation_generation = ActivationGeneration{2};
    const auto first_resolve = resolver.Queue(*resolve);
    const auto replacement_resolve = resolver.Queue(replacement);
    const auto resolve_statistics = resolver.Statistics();
    const auto latest_resolve = resolver.Take();
    WGNX_TEST_REQUIRE(context,
                      first_resolve == EndpointQueueResult::Scheduled && replacement_resolve == EndpointQueueResult::Replaced &&
                          resolve_statistics.admitted == 2 && resolve_statistics.replaced == 1 && resolve_statistics.coalesced == 1 &&
                          resolve_statistics.depth == 1 && resolve_statistics.high_watermark == 1 && latest_resolve.has_value() &&
                          latest_resolve->peer == replacement.peer && !resolver.Take().has_value(),
                      "endpoint resolver did not coalesce pending work under one scheduled worker");

    const auto coalesced_resolve = resolver.Queue(*resolve);
    const auto coalesced_resolve_statistics = resolver.Statistics();
    const auto coalesced_take = resolver.Take();
    WGNX_TEST_REQUIRE(context,
                      coalesced_resolve == EndpointQueueResult::Coalesced && coalesced_resolve_statistics.admitted == 3 &&
                          coalesced_resolve_statistics.replaced == 1 && coalesced_resolve_statistics.coalesced == 2 &&
                          coalesced_take.has_value() && coalesced_take->peer == resolve->peer,
                      "endpoint resolver conflated worker coalescing with pending replacement");

    resolver.MarkWorkerIdle();
    WGNX_TEST_REQUIRE(context, resolver.Queue(*resolve) == EndpointQueueResult::Scheduled,
                      "idle endpoint resolver did not request worker scheduling");

    wgnx::platform::endpoint_resolution_result resolved{
        .success = true,
        .resolved =
            {
                .family = wgnx::platform::address_family::inet,
                .port = 51820,
                .address = {192, 0, 2, 1},
            },
    };
    std::snprintf(resolved.text.data(), resolved.text.size(), "192.0.2.1:51820");
    const auto stale_resolution = coordinator.Dispatch(EndpointResolvedEvent{
        .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{2}},
        .result = resolved,
        .occurred_at = 2'000,
    });
    WGNX_TEST_REQUIRE(context, stale_resolution.Empty() && !coordinator.ProtocolSnapshot(0).instantiated,
                      "stale endpoint completion mutated protocol state");

    const auto resolution = coordinator.Dispatch(EndpointResolvedEvent{
        .peer = {.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{1}},
        .path_generation = resolve->path_generation,
        .result = resolved,
        .occurred_at = 2'000,
    });
    const auto* open = resolution.Size() == 1 ? std::get_if<OpenUdpBindEffect>(resolution.begin()) : nullptr;
    WGNX_TEST_REQUIRE(context,
                      open != nullptr && !open->socket_generation.IsZero() && !coordinator.ProtocolSnapshot(0).instantiated &&
                          coordinator.BindingSnapshot(0).has_endpoint,
                      "resolution did not request a UDP bind before protocol instantiation");

    constexpr std::uint32_t HandshakeRetryEntropy = RekeyTimeoutJitterMaxMs + 7;
    const auto opened = coordinator.Dispatch(UdpBindOpenedEvent{
        .peer = open->peer,
        .path_generation = open->path_generation,
        .endpoint = open->endpoint,
        .endpoint_text = open->endpoint_text,
        .socket = 42,
        .error = wgnx::platform::socket_error::none,
        .socket_generation = open->socket_generation,
        .timer_facts =
            {
                .now = TimerDeadlineFromJiffies(500),
                .random_u32 = HandshakeRetryEntropy,
            },
        .occurred_at = 3'000,
    });
    const auto* send = opened.Size() > 0 ? std::get_if<SendPendingDatagramEffect>(opened.begin()) : nullptr;
    WGNX_TEST_REQUIRE(context,
                      opened.Size() == 1 && send != nullptr && coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Handshaking &&
                          coordinator.ProtocolSnapshot(0).instantiated &&
                          coordinator.BindingSnapshot(0).Matches(open->socket_generation, 42),
                      "opened bind did not derive the first handshake timer in peer policy");

    PendingDatagramSnapshot snapshot{};
    WGNX_TEST_REQUIRE(context,
                      coordinator.SnapshotPendingDatagram(expected_activation, send->datagram_generation, snapshot) &&
                          snapshot.size == HandshakeInitiationSize,
                      "initial handshake effect did not reference a peer-owned datagram");
    const auto sent = coordinator.Dispatch(PendingDatagramSentEvent{
        .peer = send->peer,
        .datagram_generation = send->datagram_generation,
        .bytes_sent = snapshot.size,
        .error = wgnx::platform::socket_error::none,
        .timer_facts =
            {
                .now = TimerDeadlineFromJiffies(500),
                .random_u32 = HandshakeRetryEntropy,
            },
        .occurred_at = 4'000,
    });
    const auto* handshake_timer = sent.Size() > 2 ? std::get_if<ArmProtocolTimerEffect>(sent.begin() + 2) : nullptr;
    WGNX_TEST_REQUIRE(context,
                      sent.Size() == 4 && handshake_timer != nullptr && std::get_if<QueueReceiveEffect>(sent.begin() + 3) != nullptr &&
                          handshake_timer->hook == TimerHook::RetransmitHandshake &&
                          handshake_timer->deadline == TimerDeadlineFromJiffies(500) + GetHandshakeRetryDelay(HandshakeRetryEntropy) &&
                          coordinator.IsCurrentTimerEffect(*handshake_timer) &&
                          coordinator.Lifecycle(0)->tx_bytes == HandshakeInitiationSize &&
                          !coordinator.SnapshotPendingDatagram(expected_activation, send->datagram_generation, snapshot),
                      "handshake send completion did not retire pending transport state");

    PeerRegistry failed_registry{};
    std::array<wgnx::PeerConfigEntry, 1> invalid{};
    RuntimeCoordinator failed_coordinator{failed_registry};
    WGNX_TEST_REQUIRE(context, ConfigureTestPeers(failed_coordinator, invalid, 0), "failure-path registry initialization failed");
    const auto invalid_effects = failed_coordinator.Dispatch(ActivationRequestedEvent{
        .peer_index = PeerIndex{0},
        .occurred_at = 5'000,
    });
    WGNX_TEST_REQUIRE(context,
                      invalid_effects.Empty() && failed_coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Error &&
                          failed_coordinator.Lifecycle(0)->error_stage == wgnx::PeerErrorStage::Config,
                      "invalid activation did not fail before platform work");
}

void TestRuntimeOutboundLifecycle(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::wireguard;

    runtime::Reset(InitialRuntimeState);
    std::array<wgnx::PeerConfigEntry, 1> configured{};
    FillConfig(&configured[0], "runtime-outbound", "10.66.66.2/32", InitiatorPrivateKey, ResponderPublicKey);
    PeerRegistry registry{};
    RuntimeCoordinator coordinator{registry};
    WGNX_TEST_REQUIRE(context, ConfigureTestPeers(coordinator, configured, 0), "outbound runtime registry initialization failed");
    auto effects = ActivateTestPeer(coordinator, 0, 91);
    constexpr std::array<std::uint8_t, 20> FirstPacket = {
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0A, 0x42, 0x42, 0x02, 0x0A, 0x42, 0x42, 0x01,
    };
    const PeerIdentity identity{.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{1}};
    const TimerFacts timer_facts{
        .now = TimerDeadlineFromJiffies(500),
    };
    const auto* initial_send = effects.Size() > 0 ? std::get_if<SendPendingDatagramEffect>(effects.begin()) : nullptr;
    PendingDatagramSnapshot snapshot{};
    const SendPendingDatagramEffect* send = nullptr;
    WGNX_TEST_REQUIRE(context,
                      effects.Size() == 1 && initial_send != nullptr &&
                          coordinator.SnapshotPendingDatagram(identity, initial_send->datagram_generation, snapshot) &&
                          snapshot.size == HandshakeInitiationSize,
                      "activation did not stage the initial handshake submission");
    effects = coordinator.Dispatch(PendingDatagramSentEvent{
        .peer = identity,
        .datagram_generation = initial_send->datagram_generation,
        .bytes_sent = snapshot.size,
        .error = wgnx::platform::socket_error::none,
        .timer_facts = timer_facts,
        .occurred_at = 2'000,
    });
    const auto* initial_arm = effects.Size() > 2 ? std::get_if<ArmProtocolTimerEffect>(effects.begin() + 2) : nullptr;
    WGNX_TEST_REQUIRE(context,
                      effects.Size() == 4 && initial_arm != nullptr && initial_arm->token.IsValid() &&
                          std::get_if<QueueReceiveEffect>(effects.begin() + 3) != nullptr,
                      "initial handshake send did not arm retransmission after submission");

    const auto staged = coordinator.Dispatch(InnerPacketStagedEvent{
        .peer = identity,
        .packet = FirstPacket,
        .packet_id = PacketId{61},
        .timer_facts = timer_facts,
        .occurred_at = 3'000,
    });
    PeerPacketStateSnapshot packet_state{};
    static_cast<void>(coordinator.SnapshotPacketState(packet_state));
    WGNX_TEST_REQUIRE(context, staged.Empty() && packet_state.staged_packet_count == 1,
                      "staged packet did not start the production handshake path");

    auto stale_timer_token = initial_arm->token;
    ++stale_timer_token.generation;
    auto timer_token = initial_arm->token;
    const auto stale_timer_effects = coordinator.Dispatch(ProtocolTimerExpiredEvent{
        .peer = identity,
        .hook = TimerHook::RetransmitHandshake,
        .token = stale_timer_token,
        .timer_facts = timer_facts,
        .occurred_at = 3'500,
    });
    WGNX_TEST_REQUIRE(context, stale_timer_effects.Empty() && coordinator.IsCurrentTimerEffect(*initial_arm),
                      "stale queued timer delivery mutated the peer runtime");

    constexpr std::uint32_t MaxSendAttempts = MaxTimerHandshakes + 2;
    for (std::uint32_t attempt = 2; attempt <= MaxSendAttempts; ++attempt) {
        effects = coordinator.Dispatch(ProtocolTimerExpiredEvent{
            .peer = identity,
            .hook = TimerHook::RetransmitHandshake,
            .token = timer_token,
            .timer_facts = timer_facts,
            .occurred_at = 5'000 + attempt,
        });
        send = effects.Size() > 1 ? std::get_if<SendPendingDatagramEffect>(effects.begin() + 1) : nullptr;
        WGNX_TEST_REQUIRE(context,
                          effects.Size() == 2 && std::get_if<CancelProtocolTimerEffect>(effects.begin()) != nullptr && send != nullptr,
                          "runtime retry expiration did not request a fresh initiation");
        WGNX_TEST_REQUIRE(context,
                          coordinator.SnapshotPendingDatagram(identity, send->datagram_generation, snapshot) &&
                              snapshot.size == HandshakeInitiationSize,
                          "runtime retry did not expose a fresh pending initiation");
        effects = coordinator.Dispatch(PendingDatagramSentEvent{
            .peer = identity,
            .datagram_generation = send->datagram_generation,
            .bytes_sent = snapshot.size,
            .error = wgnx::platform::socket_error::none,
            .timer_facts = timer_facts,
            .occurred_at = 4'000 + attempt,
        });
        const auto* retry_arm = effects.Size() > 2 ? std::get_if<ArmProtocolTimerEffect>(effects.begin() + 2) : nullptr;
        WGNX_TEST_REQUIRE(context, effects.Size() == 3 && retry_arm != nullptr && retry_arm->token.IsValid(),
                          "successful handshake retry did not renew retransmission timing");
        timer_token = retry_arm->token;
    }

    effects = coordinator.Dispatch(ProtocolTimerExpiredEvent{
        .peer = identity,
        .hook = TimerHook::RetransmitHandshake,
        .token = timer_token,
        .timer_facts = timer_facts,
        .occurred_at = 7'000,
    });
    static_cast<void>(coordinator.SnapshotPacketState(packet_state));
    WGNX_TEST_REQUIRE(context,
                      effects.Size() == 2 && std::get_if<CancelProtocolTimerEffect>(effects.begin()) != nullptr &&
                          std::get_if<ArmProtocolTimerEffect>(effects.begin() + 1) != nullptr && packet_state.staged_packet_count == 0,
                      "runtime retry exhaustion did not drop and account for staged traffic");

    constexpr std::array<std::uint8_t, 20> RecoveryPacket = {
        0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0A, 0x42, 0x42, 0x02, 0x0A, 0x42, 0x42, 0x01,
    };
    effects = coordinator.Dispatch(InnerPacketStagedEvent{
        .peer = identity,
        .packet = RecoveryPacket,
        .packet_id = PacketId{62},
        .timer_facts = timer_facts,
        .occurred_at = 8'000,
    });
    send = effects.Size() > 0 ? std::get_if<SendPendingDatagramEffect>(effects.begin()) : nullptr;
    WGNX_TEST_REQUIRE(context, send != nullptr && coordinator.SnapshotPendingDatagram(identity, send->datagram_generation, snapshot),
                      "later traffic did not begin a fresh runtime handshake");

    ProtocolPair responder{};
    WGNX_TEST_REQUIRE(context, responder.Initialize(), "recovery responder initialization failed");
    WGNX_TEST_REQUIRE(context,
                      responder.initiator_to_responder.Send(std::span<const std::uint8_t>(snapshot.bytes).first(snapshot.size)) &&
                          responder.ReceiveInitiationAndSendResponse(),
                      "runtime initiation did not produce a responder handshake");
    std::span<const std::uint8_t> response{};
    WGNX_TEST_REQUIRE(context, responder.responder_to_initiator.Receive(response), "runtime peer did not receive the recovery response");
    effects = coordinator.Dispatch(PendingDatagramSentEvent{
        .peer = identity,
        .datagram_generation = send->datagram_generation,
        .bytes_sent = snapshot.size,
        .error = wgnx::platform::socket_error::none,
        .occurred_at = 9'000,
    });
    runtime::SetMonotonicTime(SessionBirthTime);
    WGNX_TEST_REQUIRE(context, effects.Size() == 3 && noise_handshake_begin_session(&responder.responder_device, responder.responder),
                      "responder session derivation failed");
    effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = identity,
        .packet = response,
        .source =
            {
                .family = wgnx::platform::address_family::inet,
                .port = 51820,
                .address = {192, 0, 2, 1},
            },
        .source_text = {"192.0.2.1:51820"},
        .timer_facts =
            {
                .now = TimerDeadlineFromJiffies(600),
            },
        .occurred_at = SessionBirthTime,
    });
    const bool response_emitted_send =
        std::ranges::any_of(effects, [](const RuntimeEffect& effect) { return std::holds_alternative<SendPendingDatagramEffect>(effect); });
    WGNX_TEST_REQUIRE(context, effects.Size() == 5 && coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Active,
                      "session establishment did not arm timers and release outbound work");
    WGNX_TEST_REQUIRE(context,
                      std::get_if<ArmProtocolTimerEffect>(effects.begin()) != nullptr &&
                          std::get_if<CancelProtocolTimerEffect>(effects.begin() + 1) != nullptr &&
                          std::get_if<ArmProtocolTimerEffect>(effects.begin() + 2) != nullptr &&
                          std::get_if<CancelProtocolTimerEffect>(effects.begin() + 3) != nullptr &&
                          std::get_if<QueueInnerPacketSubmissionEffect>(effects.begin() + 4) != nullptr && !response_emitted_send,
                      "session derivation did not release staged data before queuing a confirmation keepalive");

    effects = coordinator.Dispatch(ProcessOutboundQueueEvent{
        .peer = identity,
        .timer_facts = timer_facts,
        .occurred_at = SessionBirthTime + 1,
    });
    send = effects.Size() == 1 ? std::get_if<SendPendingDatagramEffect>(effects.begin()) : nullptr;
    WGNX_TEST_REQUIRE(context,
                      send != nullptr && coordinator.SnapshotPendingDatagram(identity, send->datagram_generation, snapshot) &&
                          snapshot.kind == PendingDatagramKind::TransportData && snapshot.size > TransportDataHeaderSize,
                      "staged plaintext was not converted to encrypted transport data immediately after session derivation");
    std::array<std::uint8_t, GetPaddedTransportPayloadSize(wgnx::wireguard::MaxInnerIpv4PacketSize)> responder_plaintext{};
    IncomingTransportDataResult responder_confirmation{};
    WGNX_TEST_REQUIRE(context,
                      noise_consume_incoming_transport_data_packet(std::span<const std::uint8_t>(snapshot.bytes).first(snapshot.size),
                                                                   responder.responder_device, *responder.responder, responder_plaintext,
                                                                   responder_confirmation) == TransportDataError::None &&
                          responder_confirmation.promoted_next_keypair && responder.responder->current_keypair.IsValid(),
                      "responder did not confirm the initial runtime session from staged data");
    effects = coordinator.Dispatch(PendingDatagramSentEvent{
        .peer = identity,
        .datagram_generation = send->datagram_generation,
        .bytes_sent = snapshot.size,
        .error = wgnx::platform::socket_error::none,
        .occurred_at = SessionBirthTime + 2,
    });
    WGNX_TEST_REQUIRE(context,
                      effects.Size() == 4 && std::get_if<ArmProtocolTimerEffect>(effects.begin()) != nullptr &&
                          std::get_if<CancelProtocolTimerEffect>(effects.begin() + 1) != nullptr &&
                          std::get_if<ArmProtocolTimerEffect>(effects.begin() + 2) != nullptr &&
                          std::get_if<QueueInnerPacketSubmissionEffect>(effects.begin() + 3) != nullptr &&
                          std::get<ArmProtocolTimerEffect>(effects.begin()[0]).hook == TimerHook::PersistentKeepalive &&
                          std::get<CancelProtocolTimerEffect>(effects.begin()[1]).hook == TimerHook::SendKeepalive &&
                          std::get<ArmProtocolTimerEffect>(effects.begin()[2]).hook == TimerHook::NewHandshake,
                      "transport completion did not retire staged data before continuing the queue");
    static_cast<void>(coordinator.SnapshotPacketState(packet_state));
    WGNX_TEST_REQUIRE(context, packet_state.staged_packet_count == 0, "successful transport completion did not retire staged plaintext");

    const std::uint32_t previous_runtime_index = coordinator.ProtocolSnapshot(0).current_keypair_index;
    runtime::SetMonotonicTime(SessionBirthTime + wgnx::platform::NSEC_PER_SEC);
    runtime::SetRealtime({
        .tv_sec = InitialRuntimeState.realtime.tv_sec + 1,
        .tv_nsec = InitialRuntimeState.realtime.tv_nsec,
    });
    message_handshake_initiation peer_initiation{};
    std::array<std::uint8_t, HandshakeInitiationSize> peer_initiation_packet{};
    WGNX_TEST_REQUIRE(context,
                      wg_device_create_handshake_initiation(&responder.responder_device, &peer_initiation) &&
                          SerializeHandshakeInitiation(peer_initiation_packet, peer_initiation) == ParseError::None,
                      "remote peer did not create a rotation initiation");

    const wgnx::platform::endpoint roamed_endpoint{
        .family = wgnx::platform::address_family::inet,
        .port = 51999,
        .address = {198, 51, 100, 44},
    };
    effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = identity,
        .packet = peer_initiation_packet,
        .source = roamed_endpoint,
        .source_text = {"198.51.100.44:51999"},
        .timer_facts =
            {
                .now = TimerDeadlineFromJiffies(900),
            },
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC,
    });
    send = effects.Size() == 4 ? std::get_if<SendPendingDatagramEffect>(effects.begin() + 3) : nullptr;
    const auto responder_pending_protocol = coordinator.ProtocolSnapshot(0);
    const auto roamed_binding = coordinator.BindingSnapshot(0);
    WGNX_TEST_REQUIRE(context,
                      send != nullptr && responder_pending_protocol.current_keypair_index == previous_runtime_index &&
                          responder_pending_protocol.next_keypair_valid && roamed_binding.endpoint.port == roamed_endpoint.port &&
                          roamed_binding.endpoint.address == roamed_endpoint.address,
                      "authenticated initiation did not preserve the current session and roam the endpoint");

    WGNX_TEST_REQUIRE(context,
                      coordinator.SnapshotPendingDatagram(identity, send->datagram_generation, snapshot) &&
                          snapshot.kind == PendingDatagramKind::HandshakeResponse && snapshot.size == HandshakeResponseSize &&
                          snapshot.binding.endpoint.port == roamed_endpoint.port &&
                          snapshot.binding.endpoint.address == roamed_endpoint.address,
                      "runtime did not stage the responder handshake response for the authenticated endpoint");
    const auto response_packet = std::span<const std::uint8_t>(snapshot.bytes).first(snapshot.size);
    WGNX_TEST_REQUIRE(context,
                      noise_handshake_consume_incoming_packet(response_packet, &responder.responder_device, responder.responder) ==
                              HandshakePacketOutcome::ResponseConsumed &&
                          noise_handshake_begin_session(&responder.responder_device, responder.responder),
                      "remote peer did not derive the responder-created session");
    effects = coordinator.Dispatch(PendingDatagramSentEvent{
        .peer = identity,
        .datagram_generation = send->datagram_generation,
        .bytes_sent = snapshot.size,
        .error = wgnx::platform::socket_error::none,
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 1,
    });
    WGNX_TEST_REQUIRE(context, effects.Size() == 2, "handshake response completion did not record authenticated traversal");

    constexpr std::array<std::uint8_t, 20> InboundPacket = {
        0x45, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x40, 0x11, 0xE2, 0x50, 0x0A, 0x42, 0x42, 0x01, 0x0A, 0x42, 0x42, 0x02,
    };
    std::array<std::uint8_t, MaxEncryptedDatagramSize> inbound_datagram{};
    const auto inbound_create = noise_create_transport_data_packet(inbound_datagram, responder.responder->current_keypair, InboundPacket);
    WGNX_TEST_REQUIRE(context, inbound_create.error == TransportDataError::None,
                      "remote peer did not create responder-session transport data");
    const auto inbound_packet = std::span<const std::uint8_t>(inbound_datagram).first(inbound_create.packet_size);
    effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = identity,
        .packet = inbound_packet,
        .source = roamed_endpoint,
        .source_text = {"198.51.100.44:51999"},
        .timer_facts =
            {
                .now = TimerDeadlineFromJiffies(1'100),
            },
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 2,
    });
    const PublishDecryptedPacketEffect* publish = nullptr;
    for (const auto& effect : effects) {
        if (const auto* candidate = std::get_if<PublishDecryptedPacketEffect>(&effect)) {
            publish = candidate;
        }
    }
    DecryptedPacketView decrypted{};
    WGNX_TEST_REQUIRE(context,
                      publish != nullptr && coordinator.ViewDecryptedPacket(identity, publish->packet_generation, decrypted) &&
                          std::ranges::equal(decrypted.packet, InboundPacket),
                      "first responder-session transport packet did not promote and publish atomically");

    const auto promoted_protocol = coordinator.ProtocolSnapshot(0);
    WGNX_TEST_REQUIRE(context,
                      promoted_protocol.current_keypair_index != previous_runtime_index &&
                          promoted_protocol.previous_keypair_index == previous_runtime_index && !promoted_protocol.next_keypair_valid,
                      "first responder-session transport packet did not promote key slots atomically");

    const auto received_bytes = coordinator.Lifecycle(0)->rx_bytes;
    effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = identity,
        .packet = inbound_packet,
        .source = roamed_endpoint,
        .source_text = {"198.51.100.44:51999"},
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 3,
    });
    WGNX_TEST_REQUIRE(context, effects.Empty() && coordinator.Lifecycle(0)->rx_bytes == received_bytes,
                      "replayed transport data changed peer state or authenticated counters");

    auto stale_datagram = inbound_datagram;
    stale_datagram[4] ^= 0x80U;
    effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = identity,
        .packet = std::span<const std::uint8_t>(stale_datagram).first(inbound_create.packet_size),
        .source = roamed_endpoint,
        .source_text = {"198.51.100.44:51999"},
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 4,
    });
    WGNX_TEST_REQUIRE(context, effects.Empty() && coordinator.Lifecycle(0)->rx_bytes == received_bytes,
                      "stale receiver index changed peer state or authenticated counters");

    const wgnx::platform::endpoint unauthenticated_endpoint{
        .family = wgnx::platform::address_family::inet,
        .port = 60000,
        .address = {203, 0, 113, 7},
    };
    constexpr std::array<std::uint8_t, 3> Malformed = {1, 2, 3};
    effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = identity,
        .packet = Malformed,
        .source = unauthenticated_endpoint,
        .source_text = {"203.0.113.7:60000"},
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 5,
    });
    const auto endpoint_after_malformed = coordinator.BindingSnapshot(0);
    WGNX_TEST_REQUIRE(context,
                      effects.Empty() && endpoint_after_malformed.endpoint.port == roamed_endpoint.port &&
                          endpoint_after_malformed.endpoint.address == roamed_endpoint.address,
                      "unauthenticated malformed datagram changed the roaming endpoint");

    effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = identity,
        .packet = peer_initiation_packet,
        .source = unauthenticated_endpoint,
        .source_text = {"203.0.113.7:60000"},
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 6,
    });
    const auto endpoint_after_replay = coordinator.BindingSnapshot(0);
    WGNX_TEST_REQUIRE(context,
                      effects.Empty() && coordinator.Lifecycle(0)->rx_bytes == received_bytes &&
                          endpoint_after_replay.endpoint.port == roamed_endpoint.port &&
                          endpoint_after_replay.endpoint.address == roamed_endpoint.address,
                      "replayed handshake initiation changed session or endpoint state");

    effects = coordinator.Dispatch(UdpRebindRequestedEvent{
        .peer = identity,
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 7,
    });
    const auto* first_rebind = effects.Size() == 1 ? std::get_if<OpenUdpBindEffect>(effects.begin()) : nullptr;
    WGNX_TEST_REQUIRE(context, first_rebind != nullptr, "first rebind was not requested");
    const auto first_rebind_request = *first_rebind;
    const auto binding_before_rebind = coordinator.BindingSnapshot(0);
    WGNX_TEST_REQUIRE(context, first_rebind_request.purpose == UdpBindPurpose::Rebind && binding_before_rebind.socket == 91,
                      "rebind request mutated the live socket before platform completion");

    effects = coordinator.Dispatch(UdpBindOpenedEvent{
        .peer = identity,
        .path_generation = first_rebind_request.path_generation,
        .endpoint = first_rebind_request.endpoint,
        .endpoint_text = first_rebind_request.endpoint_text,
        .error = wgnx::platform::socket_error::open_failed,
        .socket_generation = first_rebind_request.socket_generation,
        .purpose = UdpBindPurpose::Rebind,
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 8,
    });
    WGNX_TEST_REQUIRE(context,
                      effects.Empty() && coordinator.BindingSnapshot(0).socket == 91 &&
                          coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Active,
                      "failed rebind did not preserve the live peer transport");

    effects = coordinator.Dispatch(UdpRebindRequestedEvent{
        .peer = identity,
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 9,
    });
    const auto* second_rebind = effects.Size() == 1 ? std::get_if<OpenUdpBindEffect>(effects.begin()) : nullptr;
    WGNX_TEST_REQUIRE(context, second_rebind != nullptr, "second rebind was not requested");
    const auto second_rebind_request = *second_rebind;
    effects = coordinator.Dispatch(UdpBindOpenedEvent{
        .peer = identity,
        .path_generation = first_rebind_request.path_generation,
        .endpoint = first_rebind_request.endpoint,
        .endpoint_text = first_rebind_request.endpoint_text,
        .socket = 93,
        .error = wgnx::platform::socket_error::none,
        .socket_generation = first_rebind_request.socket_generation,
        .purpose = UdpBindPurpose::Rebind,
        .timer_facts = timer_facts,
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 10,
    });
    WGNX_TEST_REQUIRE(context,
                      effects.Size() == 1 && std::get_if<CloseUdpSocketEffect>(effects.begin()) != nullptr &&
                          coordinator.BindingSnapshot(0).socket == 91,
                      "stale rebind completion replaced the current peer socket");
    effects = coordinator.Dispatch(UdpBindOpenedEvent{
        .peer = identity,
        .path_generation = second_rebind_request.path_generation,
        .endpoint = second_rebind_request.endpoint,
        .endpoint_text = second_rebind_request.endpoint_text,
        .socket = 92,
        .error = wgnx::platform::socket_error::none,
        .socket_generation = second_rebind_request.socket_generation,
        .purpose = UdpBindPurpose::Rebind,
        .timer_facts = timer_facts,
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 11,
    });
    const SendPendingDatagramEffect* rebind_send = nullptr;
    const CloseUdpSocketEffect* rebind_close = nullptr;
    for (const auto& effect : effects) {
        if (const auto* candidate = std::get_if<SendPendingDatagramEffect>(&effect)) {
            rebind_send = candidate;
        }
        if (const auto* candidate = std::get_if<CloseUdpSocketEffect>(&effect)) {
            rebind_close = candidate;
        }
    }
    WGNX_TEST_REQUIRE(context,
                      rebind_send != nullptr && rebind_close != nullptr &&
                          coordinator.BindingSnapshot(0).Matches(second_rebind_request.socket_generation, 92),
                      "successful rebind did not atomically replace and recover peer transport");

    WGNX_TEST_REQUIRE(context, coordinator.SnapshotPendingDatagram(identity, rebind_send->datagram_generation, snapshot),
                      "rebind recovery did not expose its pending keepalive");
    effects = coordinator.Dispatch(PendingDatagramSentEvent{
        .peer = identity,
        .datagram_generation = rebind_send->datagram_generation,
        .error = wgnx::platform::socket_error::send_failed,
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 12,
    });
    const auto binding_after_send_failure = coordinator.BindingSnapshot(0);
    WGNX_TEST_REQUIRE(context,
                      effects.Empty() && binding_after_send_failure.Matches(second_rebind_request.socket_generation, 92) &&
                          coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Active,
                      "send failure replaced the active binding");

    const TransportFailureEvent receive_failure{
        .peer = identity,
        .operation = TransportIoOperation::Receive,
        .socket = 92,
        .socket_generation = second_rebind_request.socket_generation,
        .error = wgnx::platform::socket_error::receive_failed,
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 13,
    };
    const auto first_receive_failure = coordinator.Dispatch(receive_failure);
    const auto second_receive_failure = coordinator.Dispatch(receive_failure);
    WGNX_TEST_REQUIRE(context,
                      first_receive_failure.Empty() && second_receive_failure.Empty() &&
                          coordinator.BindingSnapshot(0).Matches(second_rebind_request.socket_generation, 92),
                      "repeated receive failures replaced the active binding");

    const auto path_suspended = coordinator.Dispatch(NetworkPathAvailabilityChangedEvent{
        .peer = identity,
        .path_generation = PathRequestGeneration{1},
        .observation =
            {
                .availability = wgnx::platform::network_path_availability::unavailable,
                .raw_state = wgnx::platform::network_path_raw_state::on_hold,
                .request_generation = 1,
            },
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 14,
    });
    const auto suspended_binding = coordinator.BindingSnapshot(0);
    effects = coordinator.Dispatch(InnerPacketStagedEvent{
        .peer = identity,
        .packet = FirstPacket,
        .packet_id = PacketId{63},
        .timer_facts = timer_facts,
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 15,
    });
    static_cast<void>(coordinator.SnapshotPacketState(packet_state));
    WGNX_TEST_REQUIRE(context,
                      !path_suspended.Empty() && suspended_binding.suspended && !suspended_binding.IsOpen() && effects.Empty() &&
                          packet_state.staged_packet_count == 1,
                      "local-path suspension encrypted staged traffic without a sendable binding");

    effects = coordinator.Dispatch(NetworkPathAvailabilityChangedEvent{
        .peer = identity,
        .path_generation = PathRequestGeneration{1},
        .observation =
            {
                .availability = wgnx::platform::network_path_availability::available,
                .raw_state = wgnx::platform::network_path_raw_state::available,
                .request_generation = 1,
            },
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 16,
    });
    const auto* path_rebind = effects.Size() == 1 ? std::get_if<OpenUdpBindEffect>(effects.begin()) : nullptr;
    const bool has_path_rebind = path_rebind != nullptr;
    const OpenUdpBindEffect path_rebind_request = has_path_rebind ? *path_rebind : OpenUdpBindEffect{};
    effects = has_path_rebind ? coordinator.Dispatch(UdpBindOpenedEvent{
                                    .peer = path_rebind_request.peer,
                                    .path_generation = path_rebind_request.path_generation,
                                    .endpoint = path_rebind_request.endpoint,
                                    .endpoint_text = path_rebind_request.endpoint_text,
                                    .socket = 94,
                                    .error = wgnx::platform::socket_error::none,
                                    .socket_generation = path_rebind_request.socket_generation,
                                    .purpose = path_rebind_request.purpose,
                                    .timer_facts = timer_facts,
                                    .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 17,
                                })
                              : EffectBatch{};
    send = nullptr;
    for (const auto& effect : effects) {
        if (const auto* candidate = std::get_if<SendPendingDatagramEffect>(&effect)) {
            send = candidate;
        }
    }
    const SendPendingDatagramEffect recovered_send = send != nullptr ? *send : SendPendingDatagramEffect{};
    WGNX_TEST_REQUIRE(context,
                      has_path_rebind && send != nullptr &&
                          coordinator.SnapshotPendingDatagram(identity, recovered_send.datagram_generation, snapshot) &&
                          snapshot.kind == PendingDatagramKind::TransportData &&
                          coordinator.BindingSnapshot(0).Matches(path_rebind_request.socket_generation, 94),
                      "available local path did not drain staged traffic through its replacement binding");
    effects = coordinator.Dispatch(PendingDatagramSentEvent{
        .peer = identity,
        .datagram_generation = recovered_send.datagram_generation,
        .bytes_sent = snapshot.size,
        .error = wgnx::platform::socket_error::none,
        .timer_facts = timer_facts,
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 18,
    });
    static_cast<void>(coordinator.SnapshotPacketState(packet_state));
    WGNX_TEST_REQUIRE(
        context, !coordinator.HasPendingDatagram(identity, recovered_send.datagram_generation) && packet_state.staged_packet_count == 0,
        "replacement-binding transport completion did not retire preserved staged traffic");

    effects = coordinator.Dispatch(InnerPacketStagedEvent{
        .peer = identity,
        .packet = RecoveryPacket,
        .packet_id = PacketId{64},
        .timer_facts = timer_facts,
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 19,
    });
    const auto* raced_send = effects.Size() == 1 ? std::get_if<SendPendingDatagramEffect>(effects.begin()) : nullptr;
    const bool has_raced_send = raced_send != nullptr;
    const SendPendingDatagramEffect raced_send_effect = has_raced_send ? *raced_send : SendPendingDatagramEffect{};
    effects = coordinator.Dispatch(NetworkPathAvailabilityChangedEvent{
        .peer = identity,
        .path_generation = PathRequestGeneration{1},
        .observation =
            {
                .availability = wgnx::platform::network_path_availability::unavailable,
                .raw_state = wgnx::platform::network_path_raw_state::on_hold,
                .request_generation = 1,
            },
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 20,
    });
    PendingDatagramSnapshot raced_snapshot{};
    const bool raced_snapshot_available =
        raced_send != nullptr && coordinator.SnapshotPendingDatagram(identity, raced_send_effect.datagram_generation, raced_snapshot);
    static_cast<void>(coordinator.SnapshotPacketState(packet_state));
    WGNX_TEST_REQUIRE(context,
                      has_raced_send && coordinator.HasPendingDatagram(identity, raced_send_effect.datagram_generation) &&
                          !raced_snapshot_available && packet_state.staged_packet_count == 1,
                      "path suspension did not preserve a pending transmit for deterministic completion");
    static_cast<void>(coordinator.Dispatch(PendingDatagramSentEvent{
        .peer = identity,
        .datagram_generation = raced_send_effect.datagram_generation,
        .error = wgnx::platform::socket_error::send_failed,
        .timer_facts = timer_facts,
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 21,
    }));
    static_cast<void>(coordinator.SnapshotPacketState(packet_state));
    WGNX_TEST_REQUIRE(context,
                      !coordinator.HasPendingDatagram(identity, raced_send_effect.datagram_generation) &&
                          packet_state.staged_packet_count == 0 && packet_state.can_stage_packet &&
                          coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Active,
                      "suspended transmit failure did not free staged admission capacity for a later writer");
}

void TestRuntimeInitiatorSessionKeepalive(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::wireguard;

    runtime::Reset(InitialRuntimeState);
    std::array<wgnx::PeerConfigEntry, 1> configured{};
    FillConfig(&configured[0], "runtime-empty-stage", "10.66.66.2/32", InitiatorPrivateKey, ResponderPublicKey);
    PeerRegistry registry{};
    RuntimeCoordinator coordinator{registry};
    WGNX_TEST_REQUIRE(context, ConfigureTestPeers(coordinator, configured, 0), "empty-stage registry initialization failed");

    auto effects = ActivateTestPeer(coordinator, 0, 92);
    const PeerIdentity identity{.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{1}};
    const auto* initial_send = effects.Size() == 1 ? std::get_if<SendPendingDatagramEffect>(effects.begin()) : nullptr;
    PendingDatagramSnapshot snapshot{};
    WGNX_TEST_REQUIRE(context,
                      initial_send != nullptr &&
                          coordinator.SnapshotPendingDatagram(identity, initial_send->datagram_generation, snapshot) &&
                          snapshot.kind == PendingDatagramKind::HandshakeInitiation,
                      "empty-stage activation did not produce an initiation");

    ProtocolPair responder{};
    WGNX_TEST_REQUIRE(context,
                      responder.Initialize() &&
                          responder.initiator_to_responder.Send(std::span<const std::uint8_t>(snapshot.bytes).first(snapshot.size)) &&
                          responder.ReceiveInitiationAndSendResponse(),
                      "empty-stage responder did not produce a handshake response");
    std::span<const std::uint8_t> response{};
    WGNX_TEST_REQUIRE(context, responder.responder_to_initiator.Receive(response), "empty-stage response was unavailable");

    effects = coordinator.Dispatch(PendingDatagramSentEvent{
        .peer = identity,
        .datagram_generation = initial_send->datagram_generation,
        .bytes_sent = snapshot.size,
        .error = wgnx::platform::socket_error::none,
        .timer_facts = {.now = TimerDeadlineFromJiffies(500)},
        .occurred_at = 2'000,
    });
    runtime::SetMonotonicTime(SessionBirthTime);
    WGNX_TEST_REQUIRE(context, noise_handshake_begin_session(&responder.responder_device, responder.responder),
                      "empty-stage responder session derivation failed");

    effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = identity,
        .packet = response,
        .source =
            {
                .family = wgnx::platform::address_family::inet,
                .port = 51820,
                .address = {192, 0, 2, 1},
            },
        .source_text = {"192.0.2.1:51820"},
        .timer_facts = {.now = TimerDeadlineFromJiffies(600)},
        .occurred_at = SessionBirthTime,
    });
    const auto* keepalive_send = effects.Size() == 5 ? std::get_if<SendPendingDatagramEffect>(effects.begin() + 4) : nullptr;
    WGNX_TEST_REQUIRE(context,
                      effects.Size() == 5 && std::get_if<ArmProtocolTimerEffect>(effects.begin()) != nullptr &&
                          std::get_if<CancelProtocolTimerEffect>(effects.begin() + 1) != nullptr &&
                          std::get_if<ArmProtocolTimerEffect>(effects.begin() + 2) != nullptr &&
                          std::get_if<CancelProtocolTimerEffect>(effects.begin() + 3) != nullptr && keepalive_send != nullptr &&
                          coordinator.SnapshotPendingDatagram(identity, keepalive_send->datagram_generation, snapshot) &&
                          snapshot.kind == PendingDatagramKind::Keepalive && snapshot.size == TransportDataHeaderSize + NoiseTagSize,
                      "empty staged queue did not produce exactly one initiator confirmation keepalive");
}

void TestAutoStartPersistenceGeneration(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;

    AutoStartPersistenceState persistence{};
    const auto first = persistence.Begin(0, "first");
    const auto replacement = persistence.Begin(1, "replacement");
    const auto clear = persistence.Begin(-1, nullptr);

    WGNX_TEST_REQUIRE(context,
                      first.generation != replacement.generation && replacement.generation != clear.generation &&
                          !persistence.IsCurrent(first) && !persistence.IsCurrent(replacement) && persistence.IsCurrent(clear) &&
                          clear.peer_index == -1 && clear.peer_name.front() == '\0',
                      "autostart persistence generations did not reject stale requests");
}

void TestUdpBindingOwnership(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;

    static_assert(!HasLegacyUdpPlatformIo<UdpBinding>);

    UdpBinding binding{};
    const wgnx::platform::endpoint endpoint{
        .family = wgnx::platform::address_family::inet,
        .port = 51820,
        .address = {192, 0, 2, 1},
    };
    binding.SetEndpoint(endpoint, "192.0.2.1:51820");
    binding.AdoptOpenSocket(endpoint, "192.0.2.1:51820", SocketGeneration{3}, 44);
    const auto open = binding.StateSnapshot();
    const auto released = binding.ReleaseSocket();
    binding.AdoptOpenSocket(endpoint, "192.0.2.1:51820", SocketGeneration{4}, 45);
    const auto suspended = binding.ReleaseAndSuspend();
    UdpBinding::SendSnapshot send{};

    WGNX_TEST_REQUIRE(context,
                      open.IsOpen() && open.Matches(SocketGeneration{3}, 44) && released == 44 && binding.IsSuspended() &&
                          suspended == 45 && !binding.SnapshotForSend(send),
                      "UDP binding did not expose an explicit, I/O-free socket transfer");
}

} // namespace wgnx::test
