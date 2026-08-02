#pragma once

#include "ip/userspace_ip_adapter.hpp"
#include "runtime/runtime_events.hpp"
#include "wgnx/resource_budget.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace wgnx::sysmodule::runtime {

class UserspaceIpAdapterOwner {
  public:
    struct OperationTicket {
        std::uint32_t generation{};

        [[nodiscard]] constexpr bool IsValid() const {
            return generation != 0;
        }
    };

    enum class QueueResult : std::uint8_t {
        Queued = 0,
        QueueFull,
    };

    enum class OperationKind : std::uint8_t {
        Configure = 0,
        Reset,
        OpenFlow,
        CloseFlow,
        SendDatagram,
        InputPacket,
        RunTimeouts,
    };

    struct Operation {
        OperationKind kind{OperationKind::Reset};
        OperationTicket ticket{};
        ip::UserspaceIpFlow flow{};
        PeerIdentity peer{};
        std::array<std::uint8_t, 4> local_address{};
        std::uint32_t policy_generation{};
        std::uint32_t adapter_epoch{};
        std::uint16_t mtu{};
    };

    void QueueConfigureLocked(const std::array<std::uint8_t, 4>& local_address, std::uint16_t mtu);
    void QueueResetLocked();
    void QueueRunTimeoutsLocked();
    [[nodiscard]] QueueResult QueueOpenFlowLocked(const ip::UserspaceIpFlow& flow, OperationTicket* out_ticket);
    [[nodiscard]] QueueResult QueueCloseFlowLocked(std::uint64_t token, OperationTicket* out_ticket);
    [[nodiscard]] QueueResult QueueSendDatagramLocked(
        std::uint64_t token, std::span<const std::uint8_t> payload, OperationTicket* out_ticket
    );
    [[nodiscard]] QueueResult QueueInputPacketLocked(
        const PeerIdentity& peer,
        std::uint32_t policy_generation,
        std::uint32_t adapter_epoch,
        std::span<const std::uint8_t> packet,
        OperationTicket* out_ticket
    );
    [[nodiscard]] std::optional<Operation> TakeNextLocked();
    [[nodiscard]] ip::UserspaceIpResult Execute(const Operation& operation);
    void CompleteLocked(const Operation& operation, ip::UserspaceIpResult result);
    [[nodiscard]] std::optional<ip::UserspaceIpResult> PeekResultLocked(OperationTicket ticket) const;
    [[nodiscard]] std::optional<ip::UserspaceIpResult> TakeResultLocked(OperationTicket ticket);
    [[nodiscard]] std::span<const ip::UserspaceIpPacket> OutboundPacketsLocked(OperationTicket ticket) const;
    [[nodiscard]] std::span<const std::uint8_t> InputPacketLocked(OperationTicket ticket) const;
    [[nodiscard]] std::span<const ip::UserspaceIpDatagram> InboundDatagramsLocked(OperationTicket ticket) const;
    [[nodiscard]] bool HadInboundDatagramRejectionLocked(OperationTicket ticket) const;
    [[nodiscard]] bool HadInputRejectionLocked(OperationTicket ticket) const;
    [[nodiscard]] bool HasPendingInboundFragmentLocked(OperationTicket ticket) const;
    [[nodiscard]] std::uint32_t AdapterEpochLocked() const;
    [[nodiscard]] std::uint32_t NextTimeoutDelayMs() const;
    void CancelLocked(OperationTicket ticket);

    [[nodiscard]] bool HasPendingWork() const;
    [[nodiscard]] const ip::UserspaceIpAdapter& AdapterForTests() const;

  private:
    struct DataOperationSlot {
        Operation operation{};
        std::array<std::uint8_t, wgnx::MaxInnerIpv4PacketSize> payload{};
        std::uint16_t payload_size{};
        ip::UserspaceIpResult result{ip::UserspaceIpResult::NotInitialized};
        std::uint32_t generation{1};
        bool pending{};
        bool running{};
        bool complete{};
    };

    static_assert(wgnx::resource_budget::UserspaceIpAdapterOperationSlots == 1);

    std::array<std::uint8_t, 4> m_local_address{};
    ip::UserspaceIpAdapter m_adapter{};
    std::uint16_t m_mtu{};
    bool m_configuration_pending{};
    bool m_reset_pending{};
    bool m_timeout_pending{};
    bool m_configuration_active{};
    DataOperationSlot m_data_operation{};
};

static_assert(sizeof(UserspaceIpAdapterOwner) <= wgnx::resource_budget::MaximumUserspaceIpAdapterOwnerBytes);

} // namespace wgnx::sysmodule::runtime
