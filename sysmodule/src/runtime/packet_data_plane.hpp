#pragma once

#include "runtime/packet_transport.hpp"
#include "runtime/runtime_events.hpp"
#include "wgnx/platform/clock.hpp"
#include "wireguard/inner_packet.hpp"
#include "wireguard/timers.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace wgnx::sysmodule::runtime {

class RuntimeCoordinator;

enum class PacketSubmissionStatus : std::uint8_t {
    Queued = 0,
    MalformedPacket,
    TunnelUnavailable,
    QueueFull,
    InternalError,
};

struct PacketSubmissionOutcome {
    PacketSubmissionStatus status{PacketSubmissionStatus::InternalError};
    wireguard::InnerIpValidationError validation{
        wireguard::InnerIpValidationError::None};
    PeerIdentity peer{};
    std::uint64_t packet_id{0};
    std::size_t packet_size{0};
    std::size_t queue_depth{0};
    std::size_t discarded_outbound{0};
    std::size_t discarded_inbound{0};
    wgnx::PeerRuntimeState peer_state{wgnx::PeerRuntimeState::Inactive};
    bool has_peer{false};
    bool ownership_transferred{false};
};

enum class PacketDeliveryStatus : std::uint8_t {
    Queued = 0,
    NoConsumer,
    MalformedPacket,
    UnsupportedPacket,
    QueueFull,
    StalePeer,
};

struct PacketDeliveryOutcome {
    PacketDeliveryStatus status{PacketDeliveryStatus::StalePeer};
    wireguard::InnerIpValidationError validation{
        wireguard::InnerIpValidationError::None};
    wireguard::InnerIpVersion version{wireguard::InnerIpVersion::Unknown};
    std::uint64_t packet_id{0};
    std::size_t packet_size{0};
    std::size_t queue_depth{0};
    std::size_t queue_capacity{0};
};

enum class PacketReceiveStatus : std::uint8_t {
    Success = 0,
    QueueEmpty,
    AccessDenied,
    OutputBufferTooSmall,
    StaleActivation,
};

struct PacketReceiveOutcome {
    PacketReceiveStatus status{PacketReceiveStatus::QueueEmpty};
    PeerIdentity peer{};
    std::uint64_t packet_id{0};
    std::size_t packet_size{0};
    std::size_t queue_depth{0};
};

struct PacketClearOutcome {
    std::size_t outbound_count{0};
    std::size_t inbound_count{0};
};

class PacketDataPlane {
public:
    PacketDataPlane(
        RuntimeCoordinator &coordinator,
        PacketTransport &transport)
        : m_coordinator(coordinator), m_transport(transport) {}

    PacketSubmissionOutcome SubmitIpPacket(
        std::span<const std::uint8_t> packet,
        PacketConsumerId consumer_id,
        wireguard::TimerDeadline retry_deadline,
        wgnx::platform::ktime_t occurred_at,
        EffectBatch &out_effects);
    PacketSubmissionOutcome SubmitIpv4Packet(
        std::span<const std::uint8_t> packet,
        PacketConsumerId consumer_id,
        wireguard::TimerDeadline retry_deadline,
        wgnx::platform::ktime_t occurred_at,
        EffectBatch &out_effects);
    PacketSubmissionOutcome SubmitInternalIpPacket(
        std::span<const std::uint8_t> packet,
        wireguard::TimerDeadline retry_deadline,
        wgnx::platform::ktime_t occurred_at,
        EffectBatch &out_effects);

    PacketDeliveryOutcome DeliverDecryptedPacket(
        const PeerIdentity &peer,
        std::span<const std::uint8_t> packet);
    PacketReceiveOutcome ReceivePacket(
        std::span<std::uint8_t> packet,
        PacketConsumerId consumer_id);
    PacketClearOutcome Clear();

private:
    PacketSubmissionOutcome SubmitValidatedPacket(
        std::span<const std::uint8_t> packet,
        PacketConsumerId consumer_id,
        wireguard::TimerDeadline retry_deadline,
        wgnx::platform::ktime_t occurred_at,
        wireguard::InnerIpValidationError validation,
        bool claim_transport,
        EffectBatch &out_effects);
    std::uint64_t AllocatePacketId();

    RuntimeCoordinator &m_coordinator;
    PacketTransport &m_transport;
    std::uint64_t m_next_packet_id{1};
};

} // namespace wgnx::sysmodule::runtime
