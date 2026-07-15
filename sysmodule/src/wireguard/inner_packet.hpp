#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace wgnx::wireguard {

constexpr inline std::size_t MaxInnerIpv4PacketSize = 1500;

enum class InnerIpv4ValidationError : std::uint8_t {
    None = 0,
    TooShort,
    TooLarge,
    InvalidVersion,
    InvalidHeaderLength,
    LengthMismatch,
    InvalidHeaderChecksum,
    InvalidPadding,
};

InnerIpv4ValidationError ValidateInnerIpv4Packet(std::span<const std::uint8_t> packet);
InnerIpv4ValidationError ValidatePaddedInnerIpv4Packet(
    std::span<const std::uint8_t> payload,
    std::size_t *out_packet_size);
const char *GetInnerIpv4ValidationErrorName(InnerIpv4ValidationError error);

struct InnerPacketRecord {
    std::array<std::uint8_t, MaxInnerIpv4PacketSize> bytes{};
    std::uint64_t packet_id{0};
    std::uint64_t owner_process_id{0};
    std::uint32_t activation_generation{0};
    std::uint32_t peer_index{0};
    std::uint16_t size{0};
};

enum class QueuePushResult : std::uint8_t {
    Pushed = 0,
    Full,
};

struct QueueStatistics {
    std::uint64_t pushed{0};
    std::uint64_t popped{0};
    std::uint64_t rejected_full{0};
    std::size_t high_watermark{0};
};

template<std::size_t Capacity>
class InnerPacketQueue {
public:
    static_assert(Capacity > 0);

    QueuePushResult Push(const InnerPacketRecord &packet) {
        if (m_count == Capacity) {
            ++m_statistics.rejected_full;
            return QueuePushResult::Full;
        }

        m_records[(m_head + m_count) % Capacity] = packet;
        ++m_count;
        ++m_statistics.pushed;
        if (m_count > m_statistics.high_watermark) {
            m_statistics.high_watermark = m_count;
        }
        return QueuePushResult::Pushed;
    }

    const InnerPacketRecord *Front() const {
        return m_count == 0 ? nullptr : std::addressof(m_records[m_head]);
    }

    bool Pop(InnerPacketRecord *out) {
        if (m_count == 0) {
            return false;
        }

        if (out != nullptr) {
            *out = m_records[m_head];
        }
        m_records[m_head] = {};
        m_head = (m_head + 1) % Capacity;
        --m_count;
        ++m_statistics.popped;
        return true;
    }

    void Clear() {
        for (std::size_t i = 0; i < m_count; ++i) {
            m_records[(m_head + i) % Capacity] = {};
        }
        m_head = 0;
        m_count = 0;
    }

    std::size_t Size() const {
        return m_count;
    }

    constexpr std::size_t CapacityValue() const {
        return Capacity;
    }

    const QueueStatistics &Statistics() const {
        return m_statistics;
    }

private:
    std::array<InnerPacketRecord, Capacity> m_records{};
    std::size_t m_head{0};
    std::size_t m_count{0};
    QueueStatistics m_statistics{};
};

} // namespace wgnx::wireguard
