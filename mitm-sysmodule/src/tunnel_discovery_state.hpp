#pragma once

#include <cstdint>
#include <limits>

namespace wgnx::mitm {

enum class TunnelAvailabilityState : std::uint8_t {
    Bypass,
    DiscoveryPending,
    Ready,
};

class TunnelDiscoveryBackoff {
  public:
    static constexpr std::uint64_t InitialRetryNanoseconds = 250'000'000ULL;
    static constexpr std::uint32_t MaximumShift = 4;

    [[nodiscard]] bool RequestForTraffic(std::uint64_t now_nanoseconds) {
        if (m_state != TunnelAvailabilityState::Bypass || now_nanoseconds < m_next_retry_nanoseconds) {
            return false;
        }

        m_state = TunnelAvailabilityState::DiscoveryPending;
        return true;
    }

    void CompleteSuccess() {
        m_state = TunnelAvailabilityState::Ready;
        m_failure_count = 0;
        m_next_retry_nanoseconds = 0;
    }

    void CompleteFailure(std::uint64_t now_nanoseconds) {
        m_state = TunnelAvailabilityState::Bypass;
        if (m_failure_count != std::numeric_limits<std::uint32_t>::max()) {
            ++m_failure_count;
        }
        m_next_retry_nanoseconds = SaturatingAdd(now_nanoseconds, RetryDelayNanoseconds());
    }

    void InvalidateReadyClient(std::uint64_t now_nanoseconds) {
        m_state = TunnelAvailabilityState::Bypass;
        m_failure_count = 0;
        m_next_retry_nanoseconds = SaturatingAdd(now_nanoseconds, InitialRetryNanoseconds);
    }

    [[nodiscard]] TunnelAvailabilityState State() const {
        return m_state;
    }

    [[nodiscard]] std::uint64_t NextRetryNanoseconds() const {
        return m_next_retry_nanoseconds;
    }

    [[nodiscard]] std::uint32_t FailureCount() const {
        return m_failure_count;
    }

  private:
    [[nodiscard]] std::uint64_t RetryDelayNanoseconds() const {
        const std::uint32_t shift = m_failure_count > 0 ? m_failure_count - 1 : 0;
        const std::uint32_t clamped_shift = shift < MaximumShift ? shift : MaximumShift;
        return InitialRetryNanoseconds << clamped_shift;
    }

    [[nodiscard]] static std::uint64_t SaturatingAdd(std::uint64_t left, std::uint64_t right) {
        if (left > std::numeric_limits<std::uint64_t>::max() - right) {
            return std::numeric_limits<std::uint64_t>::max();
        }
        return left + right;
    }

    TunnelAvailabilityState m_state{TunnelAvailabilityState::Bypass};
    std::uint64_t m_next_retry_nanoseconds{0};
    std::uint32_t m_failure_count{0};
};

} // namespace wgnx::mitm
