#pragma once

#include "wgnx/platform/udp.hpp"
#include "wgnx/platform/clock.hpp"
#include "wgnx/protocol.hpp"
#include "wireguard/peer_controller.hpp"
#include "wireguard/inner_packet.hpp"
#include "wireguard/timers.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <variant>

namespace wgnx::sysmodule::runtime {

struct PeerIdentity {
    std::uint32_t peer_index{0};
    std::uint32_t activation_generation{0};

    constexpr bool operator==(const PeerIdentity &) const = default;
};

struct ActivationRequestedEvent {
    std::uint32_t peer_index{0};
    wgnx::platform::ktime_t occurred_at{0};
};

struct EndpointResolvedEvent {
    PeerIdentity peer{};
    wgnx::platform::endpoint_resolution_result result{};
    wgnx::platform::ktime_t occurred_at{0};
};

struct UdpBindOpenedEvent {
    PeerIdentity peer{};
    wgnx::platform::endpoint endpoint{};
    std::array<char, sizeof(wgnx::PeerInfo::resolved_endpoint)> endpoint_text{};
    wgnx::platform::socket_handle socket{wgnx::platform::InvalidSocket};
    wgnx::platform::socket_error error{wgnx::platform::socket_error::open_failed};
    std::uint32_t socket_generation{0};
    wgnx::wireguard::TimerDeadline retry_deadline{};
    wgnx::platform::ktime_t occurred_at{0};
};

struct EncryptedDatagramReceivedEvent {
    PeerIdentity peer{};
    std::span<const std::uint8_t> packet{};
    wgnx::platform::endpoint source{};
    std::array<char, sizeof(wgnx::PeerInfo::resolved_endpoint)> source_text{};
    wgnx::wireguard::TimerDeadline keepalive_deadline{};
    wgnx::wireguard::TimerDeadline rekey_deadline{};
    wgnx::wireguard::TimerDeadline zero_key_material_deadline{};
    wgnx::platform::ktime_t occurred_at{0};
};

struct PendingDatagramSentEvent {
    PeerIdentity peer{};
    std::uint32_t datagram_generation{0};
    std::size_t bytes_sent{0};
    wgnx::platform::socket_error error{wgnx::platform::socket_error::send_failed};
    wgnx::platform::ktime_t occurred_at{0};
};

struct InnerPacketStagedEvent {
    PeerIdentity peer{};
    std::span<const std::uint8_t> packet{};
    std::uint64_t packet_id{0};
    wgnx::wireguard::TimerDeadline retry_deadline{};
    wgnx::platform::ktime_t occurred_at{0};
};

struct ProcessOutboundQueueEvent {
    PeerIdentity peer{};
    wgnx::wireguard::TimerDeadline retry_deadline{};
    wgnx::platform::ktime_t occurred_at{0};
};

struct ProtocolTimerExpiredEvent {
    PeerIdentity peer{};
    wgnx::wireguard::TimerHook hook{wgnx::wireguard::TimerHook::RetransmitHandshake};
    wgnx::wireguard::TimerToken token{};
    wgnx::wireguard::TimerDeadline retry_deadline{};
    wgnx::wireguard::TimerDeadline keepalive_deadline{};
    wgnx::wireguard::TimerDeadline zero_key_material_deadline{};
    wgnx::platform::ktime_t occurred_at{0};
};

struct TransportReboundEvent {
    PeerIdentity peer{};
    wgnx::wireguard::TimerDeadline retry_deadline{};
    wgnx::platform::ktime_t occurred_at{0};
};

using PeerEvent = std::variant<
    ActivationRequestedEvent,
    EndpointResolvedEvent,
    UdpBindOpenedEvent,
    EncryptedDatagramReceivedEvent,
    PendingDatagramSentEvent,
    InnerPacketStagedEvent,
    ProcessOutboundQueueEvent,
    ProtocolTimerExpiredEvent,
    TransportReboundEvent>;

struct ResolveEndpointEffect {
    PeerIdentity peer{};
    std::array<char, sizeof(wgnx::PeerConfigEntry::endpoint)> endpoint{};
};

struct OpenUdpBindEffect {
    PeerIdentity peer{};
    wgnx::platform::endpoint endpoint{};
    std::array<char, sizeof(wgnx::PeerInfo::resolved_endpoint)> endpoint_text{};
    std::uint32_t socket_generation{0};
};

struct CloseUdpSocketEffect {
    wgnx::platform::socket_handle socket{wgnx::platform::InvalidSocket};
};

struct SendPendingDatagramEffect {
    PeerIdentity peer{};
    std::uint32_t datagram_generation{0};
};

struct QueueReceiveEffect {
    PeerIdentity peer{};
};

struct ArmProtocolTimerEffect {
    PeerIdentity peer{};
    wgnx::wireguard::TimerHook hook{wgnx::wireguard::TimerHook::RetransmitHandshake};
    wgnx::wireguard::TimerToken token{};
    wgnx::wireguard::TimerDeadline deadline{};
};

struct CancelProtocolTimerEffect {
    PeerIdentity peer{};
    wgnx::wireguard::TimerHook hook{wgnx::wireguard::TimerHook::RetransmitHandshake};
    wgnx::wireguard::TimerToken token{};
};

struct SuspendUdpTransportEffect {
    PeerIdentity peer{};
};

struct QueueInnerPacketSubmissionEffect {
    PeerIdentity peer{};
};

struct PublishDecryptedPacketEffect {
    PeerIdentity peer{};
    std::uint32_t packet_generation{0};
};

using RuntimeEffect = std::variant<
    ResolveEndpointEffect,
    OpenUdpBindEffect,
    CloseUdpSocketEffect,
    SendPendingDatagramEffect,
    QueueReceiveEffect,
    ArmProtocolTimerEffect,
    CancelProtocolTimerEffect,
    SuspendUdpTransportEffect,
    QueueInnerPacketSubmissionEffect,
    PublishDecryptedPacketEffect>;

class EffectBatch {
public:
    static constexpr std::size_t Capacity = 8;

    bool Push(const RuntimeEffect &effect) {
        if (m_size == m_effects.size()) {
            return false;
        }
        m_effects[m_size++] = effect;
        return true;
    }

    bool Append(const EffectBatch &other) {
        if (other.m_size > m_effects.size() - m_size) {
            return false;
        }
        for (const auto &effect : other) {
            m_effects[m_size++] = effect;
        }
        return true;
    }

    constexpr std::size_t Size() const { return m_size; }
    constexpr bool Empty() const { return m_size == 0; }
    constexpr void Clear() { m_size = 0; }
    constexpr const RuntimeEffect *begin() const { return m_effects.data(); }
    constexpr const RuntimeEffect *end() const { return m_effects.data() + m_size; }
    constexpr RuntimeEffect *begin() { return m_effects.data(); }
    constexpr RuntimeEffect *end() { return m_effects.data() + m_size; }

private:
    std::array<RuntimeEffect, Capacity> m_effects{};
    std::size_t m_size{0};
};

inline PeerIdentity GetPeerIdentity(const PeerEvent &event) {
    return std::visit(
        [](const auto &value) -> PeerIdentity {
            using Event = std::remove_cvref_t<decltype(value)>;
            if constexpr (std::is_same_v<Event, ActivationRequestedEvent>) {
                return {.peer_index = value.peer_index};
            } else {
                return value.peer;
            }
        },
        event);
}

} // namespace wgnx::sysmodule::runtime
