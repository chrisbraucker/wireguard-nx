#pragma once

#include "runtime/domain_types.hpp"
#include "wgnx/platform/udp.hpp"
#include "wgnx/platform/clock.hpp"
#include "wgnx/protocol.hpp"
#include "wireguard/peer_controller.hpp"
#include "wireguard/inner_packet.hpp"
#include "wireguard/timers.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <type_traits>
#include <variant>

namespace wgnx::sysmodule::runtime {

struct PeerIdentity {
    PeerIndex peer_index{};
    ActivationGeneration activation_generation{};

    constexpr bool operator==(const PeerIdentity &) const = default;
};

class SynchronousPacketView {
public:
    explicit constexpr SynchronousPacketView(std::span<const std::uint8_t> bytes)
        : m_bytes(bytes) {}

    template<typename Range>
        requires requires(const Range &range) {
            std::span<const std::uint8_t>{range};
        }
    constexpr SynchronousPacketView(const Range &range)
        : m_bytes(std::span<const std::uint8_t>{range}) {}

    constexpr std::span<const std::uint8_t> Bytes() const { return m_bytes; }

private:
    std::span<const std::uint8_t> m_bytes;
};

struct ActivationRequestedEvent {
    PeerIndex peer_index{};
    wgnx::platform::ktime_t occurred_at{0};
};

struct DeactivationRequestedEvent {
    PeerIdentity peer{};
    wgnx::platform::ktime_t occurred_at{0};
};

enum class TransportIoOperation : std::uint8_t {
    Receive = 0,
};

struct TransportFailureEvent {
    PeerIdentity peer{};
    TransportIoOperation operation{TransportIoOperation::Receive};
    wgnx::platform::socket_handle socket{wgnx::platform::InvalidSocket};
    SocketGeneration socket_generation{};
    wgnx::platform::socket_error error{wgnx::platform::socket_error::receive_failed};
    wgnx::platform::ktime_t occurred_at{0};
};

struct EndpointResolvedEvent {
    PeerIdentity peer{};
    wgnx::platform::endpoint_resolution_result result{};
    wgnx::platform::ktime_t occurred_at{0};
};

enum class UdpBindPurpose : std::uint8_t {
    Activation = 0,
    Rebind,
};

struct UdpBindOpenedEvent {
    PeerIdentity peer{};
    wgnx::platform::endpoint endpoint{};
    std::array<char, sizeof(wgnx::PeerInfo::resolved_endpoint)> endpoint_text{};
    wgnx::platform::socket_handle socket{wgnx::platform::InvalidSocket};
    wgnx::platform::socket_error error{wgnx::platform::socket_error::open_failed};
    SocketGeneration socket_generation{};
    UdpBindPurpose purpose{UdpBindPurpose::Activation};
    wgnx::wireguard::TimerDeadline retry_deadline{};
    wgnx::platform::ktime_t occurred_at{0};
};

struct UdpRebindRequestedEvent {
    PeerIdentity peer{};
    wgnx::platform::ktime_t occurred_at{0};
};

struct EncryptedDatagramReceivedEvent {
    PeerIdentity peer{};
    SynchronousPacketView packet{std::span<const std::uint8_t>{}};
    wgnx::platform::endpoint source{};
    std::array<char, sizeof(wgnx::PeerInfo::resolved_endpoint)> source_text{};
    wgnx::wireguard::TimerDeadline keepalive_deadline{};
    wgnx::wireguard::TimerDeadline rekey_deadline{};
    wgnx::wireguard::TimerDeadline zero_key_material_deadline{};
    wgnx::platform::ktime_t occurred_at{0};
};

struct PendingDatagramSentEvent {
    PeerIdentity peer{};
    DatagramGeneration datagram_generation{};
    std::size_t bytes_sent{0};
    wgnx::platform::socket_error error{wgnx::platform::socket_error::send_failed};
    wgnx::platform::ktime_t occurred_at{0};
};

struct InnerPacketStagedEvent {
    PeerIdentity peer{};
    SynchronousPacketView packet{std::span<const std::uint8_t>{}};
    PacketId packet_id{};
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

using PeerEvent = std::variant<
    ActivationRequestedEvent,
    DeactivationRequestedEvent,
    TransportFailureEvent,
    EndpointResolvedEvent,
    UdpBindOpenedEvent,
    UdpRebindRequestedEvent,
    EncryptedDatagramReceivedEvent,
    PendingDatagramSentEvent,
    InnerPacketStagedEvent,
    ProcessOutboundQueueEvent,
    ProtocolTimerExpiredEvent>;

template<typename Event>
consteval std::size_t MaxEffectsForEvent() {
    if constexpr (
        std::is_same_v<Event, ActivationRequestedEvent> ||
        std::is_same_v<Event, DeactivationRequestedEvent> ||
        std::is_same_v<Event, TransportFailureEvent> ||
        std::is_same_v<Event, EndpointResolvedEvent> ||
        std::is_same_v<Event, PendingDatagramSentEvent> ||
        std::is_same_v<Event, InnerPacketStagedEvent> ||
        std::is_same_v<Event, ProcessOutboundQueueEvent>) {
        return 5;
    } else if constexpr (std::is_same_v<Event, UdpBindOpenedEvent>) {
        return 7;
    } else if constexpr (std::is_same_v<Event, UdpRebindRequestedEvent>) {
        return 1;
    } else if constexpr (
        std::is_same_v<Event, EncryptedDatagramReceivedEvent> ||
        std::is_same_v<Event, ProtocolTimerExpiredEvent>) {
        return 6;
    } else {
        static_assert(!sizeof(Event), "Peer event is missing an effect budget");
    }
}

struct ResolveEndpointEffect {
    PeerIdentity peer{};
    std::array<char, sizeof(wgnx::PeerConfigEntry::endpoint)> endpoint{};
};

struct OpenUdpBindEffect {
    PeerIdentity peer{};
    wgnx::platform::endpoint endpoint{};
    std::array<char, sizeof(wgnx::PeerInfo::resolved_endpoint)> endpoint_text{};
    SocketGeneration socket_generation{};
    UdpBindPurpose purpose{UdpBindPurpose::Activation};
};

struct CloseUdpSocketEffect {
    wgnx::platform::socket_handle socket{wgnx::platform::InvalidSocket};
};

struct SendPendingDatagramEffect {
    PeerIdentity peer{};
    DatagramGeneration datagram_generation{};
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

struct QueueInnerPacketSubmissionEffect {
    PeerIdentity peer{};
};

struct PublishDecryptedPacketEffect {
    PeerIdentity peer{};
    PacketGeneration packet_generation{};
};

using RuntimeEffect = std::variant<
    ResolveEndpointEffect,
    OpenUdpBindEffect,
    CloseUdpSocketEffect,
    SendPendingDatagramEffect,
    QueueReceiveEffect,
    ArmProtocolTimerEffect,
    CancelProtocolTimerEffect,
    QueueInnerPacketSubmissionEffect,
    PublishDecryptedPacketEffect>;

class EffectBatch {
public:
    static constexpr std::size_t Capacity = 8;

    enum class InsertionResult : std::uint8_t {
        Inserted = 0,
        CapacityExhausted,
    };

    [[nodiscard]] InsertionResult TryAdd(const RuntimeEffect &effect) {
        if (m_size == m_effects.size()) {
            return InsertionResult::CapacityExhausted;
        }
        m_effects[m_size++] = effect;
        return InsertionResult::Inserted;
    }

    [[nodiscard]] InsertionResult TryAppend(const EffectBatch &other) {
        if (other.m_size > m_effects.size() - m_size) {
            return InsertionResult::CapacityExhausted;
        }
        for (const auto &effect : other) {
            m_effects[m_size++] = effect;
        }
        return InsertionResult::Inserted;
    }

    void Add(const RuntimeEffect &effect) {
        if (TryAdd(effect) != InsertionResult::Inserted) {
            std::abort();
        }
    }

    void Append(const EffectBatch &other) {
        if (TryAppend(other) != InsertionResult::Inserted) {
            std::abort();
        }
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

static_assert(!std::is_constructible_v<RuntimeEffect, SynchronousPacketView>);
static_assert(MaxEffectsForEvent<ActivationRequestedEvent>() <= EffectBatch::Capacity);
static_assert(MaxEffectsForEvent<DeactivationRequestedEvent>() <= EffectBatch::Capacity);
static_assert(MaxEffectsForEvent<TransportFailureEvent>() <= EffectBatch::Capacity);
static_assert(MaxEffectsForEvent<EndpointResolvedEvent>() <= EffectBatch::Capacity);
static_assert(MaxEffectsForEvent<UdpBindOpenedEvent>() <= EffectBatch::Capacity);
static_assert(MaxEffectsForEvent<UdpRebindRequestedEvent>() <= EffectBatch::Capacity);
static_assert(MaxEffectsForEvent<EncryptedDatagramReceivedEvent>() <= EffectBatch::Capacity);
static_assert(MaxEffectsForEvent<PendingDatagramSentEvent>() <= EffectBatch::Capacity);
static_assert(MaxEffectsForEvent<InnerPacketStagedEvent>() <= EffectBatch::Capacity);
static_assert(MaxEffectsForEvent<ProcessOutboundQueueEvent>() <= EffectBatch::Capacity);
static_assert(MaxEffectsForEvent<ProtocolTimerExpiredEvent>() <= EffectBatch::Capacity);

inline std::size_t GetEventEffectBudget(const PeerEvent &event) {
    return std::visit(
        [](const auto &value) {
            using Event = std::remove_cvref_t<decltype(value)>;
            return MaxEffectsForEvent<Event>();
        },
        event);
}

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
