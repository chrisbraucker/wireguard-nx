#pragma once

#include "runtime/runtime_events.hpp"

#include <functional>
#include <utility>

namespace wgnx::sysmodule::runtime {

// Effects may produce a bounded follow-up batch when their completion is
// committed. Drain those batches iteratively so a completion never extends an
// executor worker's call chain.
template <typename ExecuteEffect> void DrainEffectBatches(const EffectBatch& initial, ExecuteEffect&& execute_effect) {
    EffectBatch current = initial;
    while (!current.Empty()) {
        EffectBatch generated{};
        for (const RuntimeEffect& effect : current) {
            std::invoke(execute_effect, effect, generated);
        }
        current = generated;
    }
}

} // namespace wgnx::sysmodule::runtime
