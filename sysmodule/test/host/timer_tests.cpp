#include "protocol_tests.hpp"
#include "protocol_test_support.hpp"

namespace wgnx::test {

void TestTimerIntent(TestContext &context) {
    runtime::Reset(InitialRuntimeState);
    ProtocolPair pair{};
    WGNX_TEST_REQUIRE(context, pair.Initialize(), "protocol pair initialization failed");

    auto &timers = pair.initiator->timers;
    WGNX_TEST_REQUIRE(context, !wgnx::wireguard::wg_timers_any_pending(timers), "new peer has pending timers");
    wgnx::wireguard::wg_timers_schedule(
        &timers,
        wgnx::wireguard::TimerHook::RetransmitHandshake,
        wgnx::wireguard::TimerDeadlineFromJiffies(5'000),
        pair.initiator->name);
    wgnx::wireguard::wg_timers_schedule(
        &timers,
        wgnx::wireguard::TimerHook::Rekey,
        wgnx::wireguard::TimerDeadlineFromJiffies(120'000),
        pair.initiator->name);
    WGNX_TEST_REQUIRE(
        context,
        timers.retransmit_handshake.pending &&
            timers.retransmit_handshake.deadline ==
                wgnx::wireguard::TimerDeadlineFromJiffies(5'000) &&
            timers.rekey.pending &&
            timers.rekey.deadline == wgnx::wireguard::TimerDeadlineFromJiffies(120'000),
        "timer schedule state or deadline diverged");

    wgnx::wireguard::wg_timers_schedule(
        &timers,
        wgnx::wireguard::TimerHook::RetransmitHandshake,
        wgnx::wireguard::TimerDeadlineFromJiffies(7'500),
        pair.initiator->name);
    WGNX_TEST_REQUIRE(
        context,
        timers.retransmit_handshake.pending &&
            timers.retransmit_handshake.deadline ==
                wgnx::wireguard::TimerDeadlineFromJiffies(7'500),
        "rescheduling did not replace the timer deadline");

    wgnx::wireguard::wg_timers_cancel(
        &timers,
        wgnx::wireguard::TimerHook::RetransmitHandshake,
        pair.initiator->name);
    WGNX_TEST_REQUIRE(
        context,
        !timers.retransmit_handshake.pending &&
            timers.retransmit_handshake.deadline == wgnx::wireguard::TimerDeadline{} &&
            timers.rekey.pending,
        "single timer cancellation changed the wrong timer state");
    wgnx::wireguard::wg_timers_cancel_all(&timers, pair.initiator->name);
    WGNX_TEST_REQUIRE(context, !wgnx::wireguard::wg_timers_any_pending(timers), "cancel-all left timer intent pending");
}

void TestTimerCoordinator(TestContext &context) {
    using namespace wgnx::wireguard;

    TimerCoordinator coordinator{};
    const TimerOwner first_owner{
        .peer_index = 1,
        .activation_generation = 7,
        .protocol_sequence = 3,
    };
    const TimerToken first = coordinator.Arm(TimerHook::ZeroKeyMaterial, first_owner);
    WGNX_TEST_REQUIRE(
        context,
        first.IsValid() && coordinator.IsCurrent(first, first_owner),
        "new timer token was not current for its owner");

    const TimerToken replacement = coordinator.Arm(TimerHook::ZeroKeyMaterial, first_owner);
    WGNX_TEST_REQUIRE(
        context,
        replacement.generation != first.generation &&
            !coordinator.IsCurrent(first, first_owner) &&
            coordinator.IsCurrent(replacement, first_owner),
        "rearming did not invalidate queued work from the previous timer");

    const TimerOwner next_activation{
        .peer_index = first_owner.peer_index,
        .activation_generation = first_owner.activation_generation + 1,
        .protocol_sequence = first_owner.protocol_sequence,
    };
    WGNX_TEST_REQUIRE(
        context,
        !coordinator.IsCurrent(replacement, next_activation),
        "timer token crossed an activation boundary");

    coordinator.Cancel(TimerHook::ZeroKeyMaterial);
    WGNX_TEST_REQUIRE(
        context,
        !coordinator.IsCurrent(replacement, first_owner) &&
            !coordinator.IsArmed(TimerHook::ZeroKeyMaterial),
        "timer cancellation left queued work actionable");

    const TimerToken retry = coordinator.Arm(
        TimerHook::RetransmitHandshake,
        first_owner);
    const TimerOwner next_sequence{
        .peer_index = first_owner.peer_index,
        .activation_generation = first_owner.activation_generation,
        .protocol_sequence = first_owner.protocol_sequence + 1,
    };
    WGNX_TEST_REQUIRE(
        context,
        !coordinator.IsCurrent(retry, next_sequence),
        "retry timer token crossed a handshake-sequence boundary");
}

void TestTimerSchedule(TestContext &context) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::wireguard;

    TimerCoordinator coordinator{};
    TimerSchedule schedule{};
    const TimerOwner owner{
        .peer_index = 2,
        .activation_generation = 9,
        .protocol_sequence = 4,
    };
    const TimerToken first = coordinator.Arm(TimerHook::RetransmitHandshake, owner);
    const auto first_deadline = TimerDeadlineFromJiffies(100);
    WGNX_TEST_REQUIRE(
        context,
        schedule.Arm(first, first_deadline) &&
            schedule.IsArmed(TimerHook::RetransmitHandshake) &&
            schedule.ArmedToken(TimerHook::RetransmitHandshake) == first &&
            schedule.Deadline(TimerHook::RetransmitHandshake) == first_deadline,
        "timer schedule did not retain an armed token and deadline");

    const TimerToken replacement = coordinator.Arm(
        TimerHook::RetransmitHandshake,
        owner);
    const auto replacement_deadline = TimerDeadlineFromJiffies(200);
    WGNX_TEST_REQUIRE(
        context,
        schedule.Arm(replacement, replacement_deadline) &&
            schedule.ArmedToken(TimerHook::RetransmitHandshake) == replacement &&
            schedule.Deadline(TimerHook::RetransmitHandshake) == replacement_deadline,
        "timer schedule replacement retained stale armed state");

    WGNX_TEST_REQUIRE(
        context,
        schedule.CaptureExpiration(TimerHook::RetransmitHandshake) &&
            !schedule.IsArmed(TimerHook::RetransmitHandshake),
        "timer expiration did not consume the physical arm");
    const TimerToken queued = schedule.TakeDelivery(TimerHook::RetransmitHandshake);
    WGNX_TEST_REQUIRE(
        context,
        queued == replacement && coordinator.IsCurrent(queued, owner) &&
            !schedule.TakeDelivery(TimerHook::RetransmitHandshake).IsValid(),
        "timer delivery did not preserve the captured generation");

    const TimerToken stale_queued = replacement;
    const TimerToken current = coordinator.Arm(TimerHook::RetransmitHandshake, owner);
    WGNX_TEST_REQUIRE(
        context,
        schedule.Arm(current, TimerDeadlineFromJiffies(300)) &&
            !coordinator.IsCurrent(stale_queued, owner) &&
            !schedule.Cancel(stale_queued) &&
            schedule.IsArmed(TimerHook::RetransmitHandshake) &&
            schedule.Cancel(current),
        "timer replacement did not make a queued delivery stale");
    WGNX_TEST_REQUIRE(
        context,
        !schedule.IsArmed(TimerHook::RetransmitHandshake) &&
            !schedule.ArmedToken(TimerHook::RetransmitHandshake).IsValid() &&
            schedule.Deadline(TimerHook::RetransmitHandshake) == TimerDeadline{},
        "timer cancellation retained physical schedule state");

    WGNX_TEST_REQUIRE(
        context,
        !schedule.Arm({}, TimerDeadlineFromJiffies(400)) &&
            !schedule.CaptureExpiration(TimerHook::SendKeepalive),
        "timer schedule accepted invalid or unarmed work");
}

} // namespace wgnx::test
