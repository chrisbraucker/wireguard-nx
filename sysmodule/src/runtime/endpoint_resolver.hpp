#pragma once

#include "runtime/runtime_events.hpp"

#include <optional>

namespace wgnx::sysmodule::runtime {

enum class EndpointQueueResult : std::uint8_t {
    Scheduled = 0,
    Coalesced,
};

class EndpointResolver {
public:
    [[nodiscard]] EndpointQueueResult Queue(const ResolveEndpointEffect &request);
    [[nodiscard]] std::optional<ResolveEndpointEffect> Take();
    void MarkWorkerIdle();
    void Cancel(const PeerIdentity &peer);

private:
    std::optional<ResolveEndpointEffect> m_pending{};
    bool m_worker_scheduled{false};
};

} // namespace wgnx::sysmodule::runtime
