#pragma once

#include "wireguard/inner_packet.hpp"

#include <cstddef>
#include <cstdint>

namespace wgnx::sysmodule::runtime {

class PacketChannel {
public:
    static constexpr std::size_t ReceiveCapacity = 8;

    std::uint64_t OwnerProcessId() const { return m_owner_process_id; }
    bool IsOwnedBy(std::uint64_t process_id) const {
        return m_owner_process_id != 0 && m_owner_process_id == process_id;
    }

    std::size_t Claim(std::uint64_t process_id) {
        if (m_owner_process_id == process_id) {
            return 0;
        }
        const std::size_t discarded = ClearReceived();
        m_owner_process_id = process_id;
        return discarded;
    }

    std::size_t Release() {
        const std::size_t discarded = ClearReceived();
        m_owner_process_id = 0;
        return discarded;
    }

    std::uint64_t AllocatePacketId() {
        const std::uint64_t packet_id = m_next_packet_id++;
        if (m_next_packet_id == 0) {
            m_next_packet_id = 1;
        }
        return packet_id;
    }

    wireguard::QueuePushResult PushReceived(const wireguard::InnerPacketRecord &record) {
        return m_received.Push(record);
    }

    const wireguard::InnerPacketRecord *FrontReceived() const {
        return m_received.Front();
    }

    bool PopReceived(
        wireguard::InnerPacketRecord *out,
        wireguard::QueueDisposition disposition) {
        return m_received.Pop(out, disposition);
    }

    std::size_t ClearReceived() {
        return m_received.Clear(wireguard::QueueDisposition::Cleared);
    }

    std::size_t ReceivedSize() const { return m_received.Size(); }
    constexpr std::size_t ReceivedCapacity() const { return ReceiveCapacity; }
    const wireguard::QueueStatistics &Statistics() const { return m_received.Statistics(); }

private:
    wireguard::InnerPacketQueue<ReceiveCapacity> m_received{};
    std::uint64_t m_owner_process_id{0};
    std::uint64_t m_next_packet_id{1};
};

} // namespace wgnx::sysmodule::runtime
