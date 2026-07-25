#pragma once

#include "runtime/packet_transport.hpp"
#include "wgnx/resource_budget.hpp"

#include <cstddef>
#include <cstdint>

namespace wgnx::sysmodule::runtime {

class PacketChannel final : public PacketTransport {
  public:
    static constexpr std::size_t ReceiveCapacity = wgnx::resource_budget::PacketQueueSlots;

    ProcessId ConsumerId() const override {
        return m_owner_process_id;
    }
    bool AcceptsDelivery(wireguard::InnerIpVersion version) const override {
        return version == wireguard::InnerIpVersion::Ipv4;
    }
    bool IsOwnedBy(ProcessId process_id) const override {
        return !m_owner_process_id.IsZero() && m_owner_process_id == process_id;
    }

    std::size_t Claim(ProcessId process_id) override {
        if (m_owner_process_id == process_id) {
            return 0;
        }
        const std::size_t discarded = ClearReceived();
        m_owner_process_id = process_id;
        return discarded;
    }

    std::size_t Release() override {
        const std::size_t discarded = ClearReceived();
        m_owner_process_id = ProcessId{};
        return discarded;
    }

    wireguard::QueuePushResult PushReceived(const wireguard::InnerPacketRecord& record) override {
        return m_received.Push(record);
    }

    const wireguard::InnerPacketRecord* FrontReceived() const override {
        return m_received.Front();
    }

    bool PopReceived(wireguard::InnerPacketRecord* out, wireguard::QueueDisposition disposition) override {
        return m_received.Pop(out, disposition);
    }

    std::size_t ClearReceived() {
        return m_received.Clear(wireguard::QueueDisposition::Cleared);
    }

    std::size_t ReceivedSize() const override {
        return m_received.Size();
    }
    std::size_t ReceivedCapacity() const override {
        return ReceiveCapacity;
    }
    const wireguard::QueueStatistics& Statistics() const override {
        return m_received.Statistics();
    }

  private:
    wireguard::InnerPacketQueue<ReceiveCapacity> m_received{};
    ProcessId m_owner_process_id{};
};

static_assert(sizeof(PacketChannel) <= wgnx::resource_budget::MaximumPacketChannelBytes);

} // namespace wgnx::sysmodule::runtime
