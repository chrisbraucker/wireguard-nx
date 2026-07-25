#include "runtime/peer/peer_runtime.hpp"

#include <cstdlib>
#include <type_traits>

namespace wgnx::sysmodule::runtime {

EffectBatch PeerRuntime::Handle(const PeerEvent& event) {
    EffectBatch effects = std::visit([this](const auto& value) { return HandleEvent(value); }, event);
    FinalizeTimerEffects(effects);
    if (effects.Size() > GetEventEffectBudget(event)) {
        std::abort();
    }
    return effects;
}

} // namespace wgnx::sysmodule::runtime
