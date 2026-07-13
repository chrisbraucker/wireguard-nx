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

template<std::size_t Capacity>
class InnerPacketQueue {
public:
    static_assert(Capacity > 0);

    bool Push(const InnerPacketRecord &packet) {
        if (m_count == Capacity) {
            return false;
        }

        m_records[(m_head + m_count) % Capacity] = packet;
        ++m_count;
        return true;
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
        m_head = (m_head + 1) % Capacity;
        --m_count;
        return true;
    }

    void Clear() {
        m_head = 0;
        m_count = 0;
    }

    std::size_t Size() const {
        return m_count;
    }

    constexpr std::size_t CapacityValue() const {
        return Capacity;
    }

private:
    std::array<InnerPacketRecord, Capacity> m_records{};
    std::size_t m_head{0};
    std::size_t m_count{0};
};

} // namespace wgnx::wireguard
