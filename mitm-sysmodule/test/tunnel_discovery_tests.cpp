#include "tunnel_discovery_state.hpp"
#include "tunnel_discovery_tests.hpp"

#include <cstdio>

namespace {

bool Check(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "failure: %s\n", message);
    }
    return condition;
}

} // namespace

bool RunTunnelDiscoveryTests() {
    using wgnx::mitm::TunnelAvailabilityState;
    using wgnx::mitm::TunnelDiscoveryBackoff;

    TunnelDiscoveryBackoff backoff;
    bool passed = true;

    passed = Check(backoff.State() == TunnelAvailabilityState::Bypass, "initial state was not bypass") && passed;
    passed = Check(backoff.RequestForTraffic(0), "initial traffic did not schedule discovery") && passed;
    passed = Check(backoff.State() == TunnelAvailabilityState::DiscoveryPending, "scheduled discovery was not pending") && passed;
    passed = Check(!backoff.RequestForTraffic(0), "pending discovery scheduled duplicate work") && passed;

    backoff.CompleteFailure(0);
    passed = Check(backoff.State() == TunnelAvailabilityState::Bypass, "failed discovery did not return to bypass") && passed;
    passed = Check(backoff.NextRetryNanoseconds() == 250'000'000ULL, "first retry was not 250 ms") && passed;
    passed = Check(!backoff.RequestForTraffic(249'999'999ULL), "backoff allowed early retry") && passed;
    passed = Check(backoff.RequestForTraffic(250'000'000ULL), "backoff did not allow retry at deadline") && passed;

    constexpr std::uint64_t ExpectedDelays[] =
        {500'000'000ULL, 1'000'000'000ULL, 2'000'000'000ULL, 4'000'000'000ULL, 4'000'000'000ULL, 4'000'000'000ULL};
    std::uint64_t now = 250'000'000ULL;
    for (const std::uint64_t expected_delay : ExpectedDelays) {
        backoff.CompleteFailure(now);
        passed = Check(backoff.NextRetryNanoseconds() == now + expected_delay, "retry backoff did not cap at four seconds") && passed;
        now = backoff.NextRetryNanoseconds();
        passed = Check(backoff.RequestForTraffic(now), "retry deadline did not schedule discovery") && passed;
    }

    backoff.CompleteSuccess();
    passed = Check(backoff.State() == TunnelAvailabilityState::Ready, "successful discovery did not publish ready") && passed;
    passed = Check(!backoff.RequestForTraffic(now), "ready tunnel scheduled redundant discovery") && passed;

    backoff.InvalidateReadyClient(now);
    passed = Check(backoff.State() == TunnelAvailabilityState::Bypass, "client invalidation did not return to bypass") && passed;
    passed = Check(backoff.NextRetryNanoseconds() == now + 250'000'000ULL, "client invalidation did not use initial retry") && passed;

    return passed;
}
