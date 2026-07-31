#include "protocol_tests.hpp"
#include "protocol_test_support.hpp"
#include "scripted_platform.hpp"

#include <algorithm>

namespace wgnx::test {

namespace {

using namespace wgnx::sysmodule::runtime;

wgnx::platform::endpoint_resolution_result ResolutionFailure() {
    return {
        .success = false,
        .error_stage = wgnx::PeerErrorStage::ResolveEndpoint,
        .error_code = wgnx::PeerErrorCode::EndpointResolutionFailed,
    };
}

PeerIdentity BeginActivation(RuntimeCoordinator& coordinator, ScriptedPlatform& platform, wgnx::platform::ktime_t now) {
    platform.Execute(coordinator.Dispatch(
        ActivationRequestedEvent{
            .peer_index = PeerIndex{0},
            .occurred_at = now,
        }
    ));
    return {
        .peer_index = PeerIndex{0},
        .activation_generation = coordinator.Lifecycle(0)->activation_generation,
    };
}

void Deactivate(RuntimeCoordinator& coordinator, ScriptedPlatform& platform, const PeerIdentity& peer, wgnx::platform::ktime_t now) {
    platform.Execute(coordinator.Dispatch(
        DeactivationRequestedEvent{
            .peer = peer,
            .occurred_at = now,
        }
    ));
}

} // namespace

void TestRuntimeCompositionFailureInjection(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;

    // This keeps the production drain primitive independently covered. The
    // platform-failure test below drives concrete completion boundaries.
    const PeerIdentity peer{
        .peer_index = PeerIndex{0},
        .activation_generation = ActivationGeneration{1},
    };
    EffectBatch initial{};
    initial.Add(QueueReceiveEffect{.peer = peer});
    std::size_t processed = 0;
    std::size_t active_depth = 0;
    std::size_t maximum_depth = 0;
    constexpr std::size_t EffectChainLength = EffectBatch::Capacity * 3 + 1;
    DrainEffectBatches(initial, [&](const RuntimeEffect&, EffectBatch& generated) {
        ++active_depth;
        maximum_depth = std::max(maximum_depth, active_depth);
        ++processed;
        if (processed < EffectChainLength) {
            generated.Add(QueueReceiveEffect{.peer = peer});
        }
        --active_depth;
    });
    WGNX_TEST_REQUIRE(
        context,
        processed == EffectChainLength && maximum_depth == 1,
        "effect completion batches were not drained iteratively"
    );
}

void TestRuntimeScriptedPlatformFailureCoverage(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;

    runtime::Reset(InitialRuntimeState);
    std::array<wgnx::PeerConfigEntry, 1> configured{};
    FillConfig(&configured[0], "scripted-platform", "10.66.66.2/32", InitiatorPrivateKey, ResponderPublicKey);

    PeerRegistry registry{};
    RuntimeCoordinator coordinator{registry};
    WGNX_TEST_REQUIRE(context, ConfigureTestPeers(coordinator, configured, 0), "scripted platform setup failed");
    ScriptedPlatform platform{coordinator};

    // A cancelled resolver request does not escape shutdown. A separately
    // delivered request after shutdown is still harmless at the coordinator.
    const PeerIdentity cancelled = BeginActivation(coordinator, platform, 1'000);
    const bool cancellation_observed =
        platform.HasPendingResolution() && platform.CancelResolution(cancelled) && !platform.HasPendingResolution();
    Deactivate(coordinator, platform, cancelled, 1'010);

    const PeerIdentity stale_resolve = BeginActivation(coordinator, platform, 1'020);
    Deactivate(coordinator, platform, stale_resolve, 1'030);
    const bool stale_resolution_delivered = platform.CompleteNextResolution();
    WGNX_TEST_REQUIRE(
        context,
        cancellation_observed && stale_resolution_delivered && !platform.HasPendingUdpOpen() &&
            coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Inactive,
        "resolver cancellation or stale completion escaped peer teardown"
    );

    platform.QueueUdpOpenResult({.socket = 90});
    const PeerIdentity stale_open = BeginActivation(coordinator, platform, 1'035);
    const bool stale_open_resolution = platform.CompleteNextResolution();
    Deactivate(coordinator, platform, stale_open, 1'037);
    const bool stale_open_delivered = platform.CompleteNextUdpOpen();
    WGNX_TEST_REQUIRE(
        context,
        stale_open_resolution && stale_open_delivered &&
            std::ranges::find(platform.ClosedSockets(), 90) != platform.ClosedSockets().end() &&
            coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Inactive,
        "stale UDP-open completion did not retire its newly created socket"
    );

    platform.QueueResolutionResult(ResolutionFailure());
    const PeerIdentity resolution_failure = BeginActivation(coordinator, platform, 1'040);
    const bool resolution_failed = platform.CompleteNextResolution();
    WGNX_TEST_REQUIRE(
        context,
        resolution_failed && coordinator.Lifecycle(0)->activation_generation == resolution_failure.activation_generation &&
            coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Error &&
            coordinator.Lifecycle(0)->error_stage == wgnx::PeerErrorStage::ResolveEndpoint &&
            coordinator.Lifecycle(0)->last_error_code == static_cast<std::uint32_t>(wgnx::PeerErrorCode::EndpointResolutionFailed),
        "scripted endpoint failure did not become a peer-owned activation error"
    );

    platform.QueueUdpOpenResult({
        .socket = wgnx::platform::InvalidSocket,
        .error = wgnx::platform::socket_error::open_failed,
    });
    const PeerIdentity open_failure = BeginActivation(coordinator, platform, 1'050);
    const bool resolution_opened = platform.CompleteNextResolution();
    const bool open_failed = platform.CompleteNextUdpOpen();
    WGNX_TEST_REQUIRE(
        context,
        resolution_opened && open_failed && coordinator.Lifecycle(0)->activation_generation == open_failure.activation_generation &&
            coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Error &&
            coordinator.Lifecycle(0)->error_stage == wgnx::PeerErrorStage::Transport &&
            coordinator.Lifecycle(0)->last_error_code == static_cast<std::uint32_t>(wgnx::PeerErrorCode::TransportOpenFailed),
        "scripted UDP-open failure did not become a transport activation error"
    );

    platform.QueueUdpOpenResult({.socket = 91});
    platform.QueueUdpSendResult({.error = wgnx::platform::socket_error::send_failed});
    const PeerIdentity send_failure = BeginActivation(coordinator, platform, 1'060);
    const bool send_resolution = platform.CompleteNextResolution();
    const bool send_open = platform.CompleteNextUdpOpen();
    const bool send_completed = platform.CompleteNextUdpSend();
    const auto send_binding = coordinator.BindingSnapshot(0);
    WGNX_TEST_REQUIRE(
        context,
        send_resolution && send_open && send_completed && send_binding.IsOpen() &&
            coordinator.Lifecycle(0)->activation_generation == send_failure.activation_generation &&
            coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Handshaking && !platform.HasPendingUdpOpen() &&
            platform.IsTimerArmed(wgnx::wireguard::TimerHook::RetransmitHandshake),
        "scripted UDP-send failure did not preserve the binding and arm handshake retry"
    );

    Deactivate(coordinator, platform, send_failure, 1'065);
    WGNX_TEST_REQUIRE(
        context,
        coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Inactive,
        "send-failure teardown did not retire the active peer"
    );

    platform.QueueUdpOpenResult({.socket = 92});
    platform.QueueUdpSendResult({});
    platform.QueueUdpReceiveResult({
        .kind = ScriptedPlatform::UdpReceiveResult::Kind::Failure,
        .error = wgnx::platform::socket_error::receive_failed,
    });
    const PeerIdentity receive_failure = BeginActivation(coordinator, platform, 1'070);
    const bool receive_resolution = platform.CompleteNextResolution();
    const bool receive_open = platform.CompleteNextUdpOpen();
    const bool initial_send_completed = platform.CompleteNextUdpSend();
    const bool receive_completed = platform.CompleteNextUdpReceive();
    const auto receive_binding = coordinator.BindingSnapshot(0);
    WGNX_TEST_REQUIRE(
        context,
        receive_resolution && receive_open && initial_send_completed && receive_completed && receive_binding.IsOpen() &&
            !platform.HasPendingUdpOpen() && coordinator.Lifecycle(0)->activation_generation == receive_failure.activation_generation &&
            coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Handshaking,
        "scripted UDP-receive failure did not preserve peer state and binding"
    );

    Deactivate(coordinator, platform, receive_failure, 1'075);
    platform.QueueUdpOpenResult({.socket = 93});
    platform.QueueUdpSendResult({});
    const PeerIdentity timer_peer = BeginActivation(coordinator, platform, 1'080);
    const bool timer_resolution = platform.CompleteNextResolution();
    const bool timer_open = platform.CompleteNextUdpOpen();
    const bool timer_send = platform.CompleteNextUdpSend();
    const bool timer_captured = platform.CaptureTimerExpiration(wgnx::wireguard::TimerHook::RetransmitHandshake);
    Deactivate(coordinator, platform, timer_peer, 1'090);
    const bool stale_timer_delivered = platform.DeliverCapturedTimer(wgnx::wireguard::TimerHook::RetransmitHandshake);
    WGNX_TEST_REQUIRE(
        context,
        timer_resolution && timer_open && timer_send && timer_captured && stale_timer_delivered &&
            !platform.IsTimerArmed(wgnx::wireguard::TimerHook::RetransmitHandshake) &&
            coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Inactive,
        "captured timer delivery remained actionable after peer teardown"
    );

    AutoStartPersistenceState persistence{};
    const auto failed_store = persistence.Begin(0, "scripted-platform");
    platform.QueuePersistenceResult(false);
    const bool persistence_failed = !platform.PersistAutoStart(persistence, failed_store) && coordinator.AutoStartPeerIndex() == -1;
    const auto committed_store = persistence.Begin(0, "scripted-platform");
    platform.QueuePersistenceResult(true);
    const bool persistence_committed = platform.PersistAutoStart(persistence, committed_store) &&
                                       coordinator.SetAutoStartPeerIndex(committed_store.peer_index) &&
                                       coordinator.AutoStartPeerIndex() == committed_store.peer_index;
    const auto stale_store = persistence.Begin(-1, nullptr);
    const bool stale_persistence_rejected = !platform.PersistAutoStart(persistence, committed_store) && persistence.IsCurrent(stale_store);
    WGNX_TEST_REQUIRE(
        context,
        persistence_failed && persistence_committed && stale_persistence_rejected && platform.GetStatistics().persistence_attempts == 2,
        "scripted autostart persistence did not preserve failure and stale-request boundaries"
    );
}

void TestRuntimeRepeatedLifecycleBounds(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;

    runtime::Reset(InitialRuntimeState);
    std::array<wgnx::PeerConfigEntry, 1> configured{};
    FillConfig(&configured[0], "repeated-lifecycle", "10.66.66.2/32", InitiatorPrivateKey, ResponderPublicKey);
    PeerRegistry registry{};
    RuntimeCoordinator coordinator{registry};
    WGNX_TEST_REQUIRE(context, ConfigureTestPeers(coordinator, configured, 0), "repeated lifecycle registry setup failed");

    ScriptedPlatform platform{coordinator};
    constexpr std::size_t ActivationCycles = 16;
    bool all_cycles_retired = true;
    for (std::size_t cycle = 0; cycle < ActivationCycles; ++cycle) {
        const auto socket = static_cast<wgnx::platform::socket_handle>(200 + cycle);
        platform.QueueUdpOpenResult({.socket = socket});
        platform.QueueUdpSendResult({});
        const auto now = static_cast<wgnx::platform::ktime_t>(10'000 + cycle * 100);
        const PeerIdentity peer = BeginActivation(coordinator, platform, now);
        const bool activated = platform.CompleteNextResolution() && platform.CompleteNextUdpOpen() && platform.CompleteNextUdpSend();
        Deactivate(coordinator, platform, peer, now + 50);

        // Receive work can have been queued by the initial handshake send. It
        // is intentionally consumed after teardown and must be inert.
        static_cast<void>(platform.CompleteNextUdpReceive());
        const auto protocol = coordinator.ProtocolSnapshot(0);
        const bool timers_retired = !platform.IsTimerArmed(wgnx::wireguard::TimerHook::RetransmitHandshake) &&
                                    !platform.IsTimerArmed(wgnx::wireguard::TimerHook::SendKeepalive) &&
                                    !platform.IsTimerArmed(wgnx::wireguard::TimerHook::NewHandshake) &&
                                    !platform.IsTimerArmed(wgnx::wireguard::TimerHook::ZeroKeyMaterial) &&
                                    !platform.IsTimerArmed(wgnx::wireguard::TimerHook::PersistentKeepalive);
        all_cycles_retired = all_cycles_retired && activated && coordinator.Lifecycle(0)->state == wgnx::PeerRuntimeState::Inactive &&
                             !coordinator.BindingSnapshot(0).IsOpen() && !protocol.instantiated && !platform.HasPendingResolution() &&
                             !platform.HasPendingUdpOpen() && !platform.HasPendingUdpSend() && !platform.HasPendingUdpReceive() &&
                             timers_retired;
    }

    const auto& statistics = platform.GetStatistics();
    WGNX_TEST_REQUIRE(
        context,
        all_cycles_retired && platform.ClosedSockets().size() == ActivationCycles && statistics.resolve_requests == ActivationCycles &&
            statistics.udp_open_requests == ActivationCycles && statistics.udp_send_requests == ActivationCycles &&
            statistics.udp_close_requests == ActivationCycles,
        "repeated peer lifecycle retained bounded runtime work or transport ownership"
    );
}

void TestNifmDoesNotOwnUdpBinding(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;

    runtime::Reset(InitialRuntimeState);
    std::array<wgnx::PeerConfigEntry, 1> configured{};
    FillConfig(&configured[0], "nifm-transport-ownership", "10.66.66.2/32", InitiatorPrivateKey, ResponderPublicKey);
    PeerRegistry registry{};
    RuntimeCoordinator coordinator{registry};
    WGNX_TEST_REQUIRE(context, ConfigureTestPeers(coordinator, configured, 0), "NIFM transport-ownership test setup failed");
    ScriptedPlatform platform{coordinator};
    platform.QueueUdpOpenResult({.socket = 120});
    const PeerIdentity peer = BeginActivation(coordinator, platform, 2'000);
    WGNX_TEST_REQUIRE(
        context,
        platform.CompleteNextResolution() && platform.CompleteNextUdpOpen() && platform.CompleteNextUdpSend(),
        "NIFM transport-ownership test could not establish its initial binding"
    );

    const auto original = coordinator.BindingSnapshot(0);
    const auto rebind = coordinator.Dispatch(
        UdpRebindRequestedEvent{
            .peer = peer,
            .occurred_at = 2'010,
        }
    );
    platform.Execute(rebind);
    platform.QueueUdpOpenResult({.socket = 121});
    WGNX_TEST_REQUIRE(
        context,
        platform.CompleteNextUdpOpen() && !coordinator.BindingSnapshot(0).Matches(original.generation, original.socket) &&
            coordinator.BindingSnapshot(0).socket == 121 &&
            std::ranges::find(platform.ClosedSockets(), 120) != platform.ClosedSockets().end() &&
            std::ranges::find(platform.ClosedSockets(), 121) == platform.ClosedSockets().end(),
        "UDP replacement incorrectly depends on NIFM descriptor ownership"
    );
}

} // namespace wgnx::test
