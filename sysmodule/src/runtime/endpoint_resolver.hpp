#pragma once

#include "runtime/runtime_events.hpp"

#include <optional>

namespace wgnx::sysmodule::runtime {

class EndpointResolver {
public:
    bool Queue(const ResolveEndpointEffect &request);
    std::optional<ResolveEndpointEffect> Take();
    void MarkWorkerIdle();
    void Cancel(const PeerIdentity &peer);

private:
    std::optional<ResolveEndpointEffect> m_pending{};
    bool m_worker_scheduled{false};
};

} // namespace wgnx::sysmodule::runtime
