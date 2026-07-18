#pragma once

#include "runtime/resource_observability.hpp"
#include "runtime/runtime_events.hpp"
#include "wgnx/resource_budget.hpp"

#include <optional>

namespace wgnx::sysmodule::runtime {

enum class EndpointQueueResult : std::uint8_t {
    Scheduled = 0,
    Coalesced,
    Replaced,
};

class EndpointResolver {
public:
    static constexpr std::size_t RequestCapacity =
        wgnx::resource_budget::EndpointRequestSlots;

    [[nodiscard]] EndpointQueueResult Queue(const ResolveEndpointEffect &request);
    [[nodiscard]] std::optional<ResolveEndpointEffect> Take();
    void MarkWorkerIdle();
    void Cancel(const PeerIdentity &peer);
    const PendingSlotStatistics &Statistics() const {
        return m_accounting.Statistics();
    }

private:
    static_assert(RequestCapacity == PendingSlotStatistics::Capacity);

    std::optional<ResolveEndpointEffect> m_pending{};
    PendingSlotAccounting m_accounting{};
    bool m_worker_scheduled{false};
};

static_assert(
    sizeof(EndpointResolver) <=
    wgnx::resource_budget::MaximumEndpointResolverBytes);

} // namespace wgnx::sysmodule::runtime
