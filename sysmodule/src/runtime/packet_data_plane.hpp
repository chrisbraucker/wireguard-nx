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
    wireguard::InnerIpValidationError validation{wireguard::InnerIpValidationError::None};
    PeerIdentity peer{};
    PacketId packet_id{};
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
    wireguard::InnerIpValidationError validation{wireguard::InnerIpValidationError::None};
    wireguard::InnerIpVersion version{wireguard::InnerIpVersion::Unknown};
    PacketId packet_id{};
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
    PacketId packet_id{};
    std::size_t packet_size{0};
    std::size_t queue_depth{0};
};

struct PacketClearOutcome {
    std::size_t outbound_count{0};
    std::size_t inbound_count{0};
};

class PacketDataPlane {
  public:
    PacketDataPlane(RuntimeCoordinator& coordinator, PacketTransport& transport) : m_coordinator(coordinator), m_transport(transport) {}

    [[nodiscard]] PacketSubmissionOutcome SubmitIpPacket(std::span<const std::uint8_t> packet, ProcessId consumer_id,
                                                         const TimerFacts& timer_facts, wgnx::platform::ktime_t occurred_at,
                                                         EffectBatch& out_effects);
    [[nodiscard]] PacketSubmissionOutcome SubmitIpv4Packet(std::span<const std::uint8_t> packet, ProcessId consumer_id,
                                                           const TimerFacts& timer_facts, wgnx::platform::ktime_t occurred_at,
                                                           EffectBatch& out_effects);
    [[nodiscard]] PacketSubmissionOutcome SubmitInternalIpPacket(std::span<const std::uint8_t> packet, const TimerFacts& timer_facts,
                                                                 wgnx::platform::ktime_t occurred_at, EffectBatch& out_effects);

    [[nodiscard]] PacketDeliveryOutcome DeliverDecryptedPacket(const PeerIdentity& peer, std::span<const std::uint8_t> packet);
    [[nodiscard]] PacketReceiveOutcome ReceivePacket(std::span<std::uint8_t> packet, ProcessId consumer_id);
    [[nodiscard]] PacketClearOutcome Clear();

  private:
    PacketSubmissionOutcome SubmitValidatedPacket(std::span<const std::uint8_t> packet, ProcessId consumer_id,
                                                  const TimerFacts& timer_facts, wgnx::platform::ktime_t occurred_at,
                                                  wireguard::InnerIpValidationError validation, bool claim_transport,
                                                  EffectBatch& out_effects);
    PacketId AllocatePacketId();

    RuntimeCoordinator& m_coordinator;
    PacketTransport& m_transport;
    PacketId m_next_packet_id{1};
};

} // namespace wgnx::sysmodule::runtime
