#pragma once

#include "runtime/runtime_coordinator.hpp"
#include "runtime/udp_binding.hpp"
#include "wgnx/platform/packet.hpp"
#include "wgnx/resource_budget.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

#include <stratosphere.hpp>

namespace wgnx::sysmodule::runtime {

class HorizonDispatcher;
class RuntimeEffectExecutor;

class EncryptedReceivePump {
  public:
    static constexpr std::size_t PacketCapacity = wgnx::resource_budget::EncryptedReceiveBytes;

    EncryptedReceivePump(ams::os::Mutex& state_mutex, RuntimeCoordinator& coordinator, HorizonDispatcher& dispatcher)
        : m_state_mutex(state_mutex), m_coordinator(coordinator), m_dispatcher(dispatcher) {}

    [[nodiscard]] UdpRebindQueueResult QueueRebindLocked(const UdpRebindRequest& request);
    void Queue();
    void Run(RuntimeEffectExecutor& effect_executor);

  private:
    bool SnapshotReceiveRuntime(ReceiveRuntimeSnapshot& out);
    void ProcessPendingRebind(RuntimeEffectExecutor& effect_executor);
    NOINLINE void CommitReceivedPacket(
        const ReceiveRuntimeSnapshot& snapshot,
        std::span<const std::uint8_t> packet,
        const wgnx::platform::endpoint& source,
        EffectBatch& out_effects
    );
    void CommitReceiveFailure(
        const ReceiveRuntimeSnapshot& snapshot, const wgnx::platform::udp_receive_result& result, RuntimeEffectExecutor& effect_executor
    );

    ams::os::Mutex& m_state_mutex;
    RuntimeCoordinator& m_coordinator;
    HorizonDispatcher& m_dispatcher;
    UdpRebindQueue m_rebind_requests{};
    std::array<std::uint8_t, PacketCapacity> m_packet_storage{};
    EffectBatch m_receive_effects{};
};

static_assert(sizeof(EncryptedReceivePump) <= wgnx::resource_budget::MaximumEncryptedReceivePumpBytes);

} // namespace wgnx::sysmodule::runtime
