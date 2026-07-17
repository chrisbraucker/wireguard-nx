#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace wgnx::wireguard {

constexpr inline std::size_t MaxInnerIpv4PacketSize = 1500;
constexpr inline std::size_t MaxInnerIpPacketSize = MaxInnerIpv4PacketSize;

enum class InnerIpVersion : std::uint8_t {
    Unknown = 0,
    Ipv4 = 4,
    Ipv6 = 6,
};

enum class InnerIpValidationError : std::uint8_t {
    None = 0,
    TooShort,
    TooLarge,
    InvalidVersion,
    InvalidHeaderLength,
    LengthMismatch,
    InvalidHeaderChecksum,
    InvalidPadding,
};

using InnerIpv4ValidationError = InnerIpValidationError;

InnerIpv4ValidationError ValidateInnerIpv4Packet(std::span<const std::uint8_t> packet);
InnerIpv4ValidationError ValidatePaddedInnerIpv4Packet(
    std::span<const std::uint8_t> payload,
    std::size_t *out_packet_size);
InnerIpValidationError ValidateInnerIpPacket(
    std::span<const std::uint8_t> packet,
    InnerIpVersion *out_version = nullptr);
InnerIpValidationError ValidatePaddedInnerIpPacket(
    std::span<const std::uint8_t> payload,
    std::size_t *out_packet_size,
    InnerIpVersion *out_version = nullptr);
const char *GetInnerIpValidationErrorName(InnerIpValidationError error);
inline const char *GetInnerIpv4ValidationErrorName(InnerIpv4ValidationError error) {
    return GetInnerIpValidationErrorName(error);
}

struct InnerPacketRecord {
    std::array<std::uint8_t, MaxInnerIpPacketSize> bytes{};
    std::uint64_t packet_id{0};
    std::uint32_t activation_generation{0};
    std::uint32_t peer_index{0};
    std::uint16_t size{0};
};

enum class QueuePushResult : std::uint8_t {
    Pushed = 0,
    Full,
};

enum class QueueDisposition : std::uint8_t {
    Delivered = 0,
    Sent,
    Stale,
    Unavailable,
    SendFailed,
    RetryExhausted,
    Cleared,
};

const char *GetQueueDispositionName(QueueDisposition disposition);

struct QueueStatistics {
    std::uint64_t pushed{0};
    std::uint64_t popped{0};
    std::uint64_t rejected_full{0};
    std::uint64_t delivered{0};
    std::uint64_t sent{0};
    std::uint64_t stale{0};
    std::uint64_t unavailable{0};
    std::uint64_t send_failed{0};
    std::uint64_t retry_exhausted{0};
    std::uint64_t cleared{0};
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

    bool Pop(InnerPacketRecord *out, QueueDisposition disposition) {
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
        RecordDisposition(disposition, 1);
        return true;
    }

    std::size_t Clear(QueueDisposition disposition) {
        const std::size_t cleared = m_count;
        for (std::size_t i = 0; i < m_count; ++i) {
            m_records[(m_head + i) % Capacity] = {};
        }
        m_head = 0;
        m_count = 0;
        m_statistics.popped += cleared;
        RecordDisposition(disposition, cleared);
        return cleared;
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
    void RecordDisposition(QueueDisposition disposition, std::size_t count) {
        const auto value = static_cast<std::uint64_t>(count);
        switch (disposition) {
            case QueueDisposition::Delivered: m_statistics.delivered += value; break;
            case QueueDisposition::Sent: m_statistics.sent += value; break;
            case QueueDisposition::Stale: m_statistics.stale += value; break;
            case QueueDisposition::Unavailable: m_statistics.unavailable += value; break;
            case QueueDisposition::SendFailed: m_statistics.send_failed += value; break;
            case QueueDisposition::RetryExhausted: m_statistics.retry_exhausted += value; break;
            case QueueDisposition::Cleared: m_statistics.cleared += value; break;
        }
    }

    std::array<InnerPacketRecord, Capacity> m_records{};
    std::size_t m_head{0};
    std::size_t m_count{0};
    QueueStatistics m_statistics{};
};

} // namespace wgnx::wireguard
