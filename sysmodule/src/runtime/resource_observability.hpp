#pragma once

#include <cstddef>
#include <cstdint>

namespace wgnx::sysmodule::runtime {

struct PendingSlotStatistics {
    static constexpr std::size_t Capacity = 1;

    std::size_t depth{0};
    std::size_t high_watermark{0};
    std::uint64_t admitted{0};
    std::uint64_t taken{0};
    std::uint64_t replaced{0};
    std::uint64_t coalesced{0};
    std::uint64_t cancelled{0};
};

class PendingSlotAccounting {
public:
    void RecordAdmission(bool replaced) {
        ++m_statistics.admitted;
        if (replaced) {
            ++m_statistics.replaced;
        }
        m_statistics.depth = 1;
        m_statistics.high_watermark = 1;
    }

    void RecordTake() {
        ++m_statistics.taken;
        m_statistics.depth = 0;
    }

    void RecordCoalesced() {
        ++m_statistics.coalesced;
    }

    void RecordCancellation() {
        ++m_statistics.cancelled;
        m_statistics.depth = 0;
    }

    const PendingSlotStatistics &Statistics() const {
        return m_statistics;
    }

private:
    PendingSlotStatistics m_statistics{};
};

} // namespace wgnx::sysmodule::runtime
