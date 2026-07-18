#include "protocol_tests.hpp"
#include "protocol_test_support.hpp"

namespace wgnx::test {

void TestRuntimeCompositionFailureInjection(TestContext &context) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::wireguard;

    runtime::Reset(InitialRuntimeState);
    std::array<wgnx::PeerConfigEntry, 1> configured{};
    FillConfig(
        &configured[0],
        "composition",
        "10.66.66.2/32",
        InitiatorPrivateKey,
        ResponderPublicKey);

    PeerRegistry registry{};
    RuntimeCoordinator coordinator{registry};
    WGNX_TEST_REQUIRE(
        context,
        ConfigureTestPeers(coordinator, configured, 0),
        "composition failure-injection setup failed");

    const auto activation = coordinator.Dispatch(ActivationRequestedEvent{
        .peer_index = PeerIndex{0},
        .occurred_at = 1'000,
    });
    const auto *resolve = activation.Size() == 1
        ? std::get_if<ResolveEndpointEffect>(activation.begin())
        : nullptr;
    WGNX_TEST_REQUIRE(
        context,
        resolve != nullptr,
        "composition failure-injection did not produce an endpoint request");
    if (resolve == nullptr) {
        return;
    }

    // This is the host representation of queued resolver work which becomes
    // stale during shutdown before the worker receives CPU time.
    EndpointResolver resolver{};
    static_cast<void>(resolver.Queue(*resolve));
    resolver.Cancel(resolve->peer);
    const auto shutdown = coordinator.Dispatch(DeactivationRequestedEvent{
        .peer = resolve->peer,
        .occurred_at = 1'100,
    });
    const wgnx::platform::endpoint_resolution_result resolved{
        .success = true,
        .resolved = {
            .family = wgnx::platform::address_family::inet,
            .port = 51820,
            .address = {192, 0, 2, 1},
        },
    };
    const auto stale_resolution = coordinator.Dispatch(EndpointResolvedEvent{
        .peer = resolve->peer,
        .result = resolved,
        .occurred_at = 1'200,
    });
    const auto resolver_statistics = resolver.Statistics();
    WGNX_TEST_REQUIRE(
        context,
        resolver_statistics.cancelled == 1 && resolver_statistics.depth == 0 &&
            !resolver.Take().has_value() && stale_resolution.Empty() &&
            coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Inactive,
        "cancelled resolver work or its stale completion escaped shutdown");
    static_cast<void>(shutdown);

    const auto failed_activation = coordinator.Dispatch(ActivationRequestedEvent{
        .peer_index = PeerIndex{0},
        .occurred_at = 1'300,
    });
    const auto *failed_resolve = failed_activation.Size() == 1
        ? std::get_if<ResolveEndpointEffect>(failed_activation.begin())
        : nullptr;
    wgnx::platform::endpoint_resolution_result resolution_failure{
        .success = false,
        .error_stage = wgnx::PeerErrorStage::ResolveEndpoint,
        .error_code = wgnx::PeerErrorCode::EndpointResolutionFailed,
    };
    const auto resolution_failure_effects = failed_resolve != nullptr
        ? coordinator.Dispatch(EndpointResolvedEvent{
              .peer = failed_resolve->peer,
              .result = resolution_failure,
              .occurred_at = 1'400,
          })
        : EffectBatch{};
    WGNX_TEST_REQUIRE(
        context,
        failed_resolve != nullptr && resolution_failure_effects.Size() == 4 &&
            coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Error &&
            coordinator.Lifecycle(0)->error_stage ==
                wgnx::PeerErrorStage::ResolveEndpoint &&
            coordinator.Lifecycle(0)->last_error_code == static_cast<std::uint32_t>(
                wgnx::PeerErrorCode::EndpointResolutionFailed),
        "endpoint-resolution failure did not remain a peer-owned terminal event");

    const auto retry_activation = coordinator.Dispatch(ActivationRequestedEvent{
        .peer_index = PeerIndex{0},
        .occurred_at = 1'500,
    });
    const auto *retry_resolve = retry_activation.Size() == 1
        ? std::get_if<ResolveEndpointEffect>(retry_activation.begin())
        : nullptr;
    const auto open_request = retry_resolve != nullptr
        ? coordinator.Dispatch(EndpointResolvedEvent{
              .peer = retry_resolve->peer,
              .result = resolved,
              .occurred_at = 1'600,
          })
        : EffectBatch{};
    const auto *open = open_request.Size() == 1
        ? std::get_if<OpenUdpBindEffect>(open_request.begin())
        : nullptr;
    const auto open_failure_effects = open != nullptr
        ? coordinator.Dispatch(UdpBindOpenedEvent{
              .peer = open->peer,
              .endpoint = open->endpoint,
              .endpoint_text = open->endpoint_text,
              .socket = wgnx::platform::InvalidSocket,
              .error = wgnx::platform::socket_error::open_failed,
              .socket_generation = open->socket_generation,
              .purpose = open->purpose,
              .timer_facts = {.now = TimerDeadlineFromJiffies(10)},
              .occurred_at = 1'700,
          })
        : EffectBatch{};
    WGNX_TEST_REQUIRE(
        context,
        retry_resolve != nullptr && open != nullptr && open_failure_effects.Size() == 4 &&
            coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Error &&
            coordinator.Lifecycle(0)->error_stage == wgnx::PeerErrorStage::Transport &&
            coordinator.Lifecycle(0)->last_error_code == static_cast<std::uint32_t>(
                wgnx::PeerErrorCode::TransportOpenFailed),
        "UDP-open failure did not preserve the resolved endpoint and enter transport error");

    const auto live_effects = ActivateTestPeer(coordinator, 0, 91, 1'800);
    const PeerIdentity live_peer{
        .peer_index = PeerIndex{0},
        .activation_generation = coordinator.Lifecycle(0)->activation_generation,
    };
    const auto *timer = live_effects.Empty()
        ? nullptr
        : std::get_if<ArmProtocolTimerEffect>(live_effects.begin());
    UdpRebindQueue rebinds{};
    static_cast<void>(rebinds.Queue({
        .peer_index = live_peer.peer_index,
        .activation_generation = live_peer.activation_generation,
    }));
    const auto deactivate_effects = coordinator.Dispatch(DeactivationRequestedEvent{
        .peer = live_peer,
        .occurred_at = 1'900,
    });
    const auto pending_rebind = rebinds.Take();
    const auto stale_rebind = pending_rebind.has_value()
        ? coordinator.Dispatch(UdpRebindRequestedEvent{
              .peer = {
                  .peer_index = pending_rebind->peer_index,
                  .activation_generation = pending_rebind->activation_generation,
              },
              .occurred_at = 2'000,
          })
        : EffectBatch{};
    TimerSchedule schedule{};
    const bool timer_armed = timer != nullptr && schedule.Arm(timer->token, timer->deadline);
    schedule.CancelAll();
    WGNX_TEST_REQUIRE(
        context,
        timer_armed && !deactivate_effects.Empty() && pending_rebind.has_value() &&
            stale_rebind.Empty() && !schedule.CaptureExpiration(timer->hook) &&
            !schedule.TakeDelivery(timer->hook).IsValid() &&
            coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Inactive,
        "pending rebind or timer work remained actionable after deactivation");

    // Exercise the production effect-drain primitive with more generated
    // batches than fit in one effect batch. The callback's active depth stays
    // one, demonstrating that completion batches are not recursively invoked.
    EffectBatch initial{};
    initial.Add(QueueReceiveEffect{.peer = live_peer});
    std::size_t processed = 0;
    std::size_t active_depth = 0;
    std::size_t maximum_depth = 0;
    constexpr std::size_t EffectChainLength = EffectBatch::Capacity * 3 + 1;
    DrainEffectBatches(initial, [&](const RuntimeEffect &, EffectBatch &generated) {
        ++active_depth;
        maximum_depth = std::max(maximum_depth, active_depth);
        ++processed;
        if (processed < EffectChainLength) {
            generated.Add(QueueReceiveEffect{.peer = live_peer});
        }
        --active_depth;
    });
    WGNX_TEST_REQUIRE(
        context,
        processed == EffectChainLength && maximum_depth == 1,
        "effect completion batches were not drained iteratively");
}

} // namespace wgnx::test
