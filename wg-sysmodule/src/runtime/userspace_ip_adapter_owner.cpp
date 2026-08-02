#include "runtime/userspace_ip_adapter_owner.hpp"

#include <algorithm>

namespace wgnx::sysmodule::runtime {

void UserspaceIpAdapterOwner::QueueConfigureLocked(const std::array<std::uint8_t, 4>& local_address, std::uint16_t mtu) {
    if (m_configuration_active && !m_reset_pending && !m_configuration_pending && m_local_address == local_address && m_mtu == mtu) {
        return;
    }
    m_local_address = local_address;
    m_mtu = mtu;
    m_configuration_pending = true;
}

void UserspaceIpAdapterOwner::QueueResetLocked() {
    m_reset_pending = true;
    m_timeout_pending = false;
    m_configuration_active = false;
}

void UserspaceIpAdapterOwner::QueueRunTimeoutsLocked() {
    if (m_configuration_active && !m_reset_pending) {
        m_timeout_pending = true;
    }
}

UserspaceIpAdapterOwner::QueueResult UserspaceIpAdapterOwner::QueueOpenFlowLocked(
    const ip::UserspaceIpFlow& flow, OperationTicket* out_ticket
) {
    if (out_ticket == nullptr || m_data_operation.pending || m_data_operation.running || m_data_operation.complete) {
        return QueueResult::QueueFull;
    }
    m_data_operation.operation = {
        .kind = OperationKind::OpenFlow,
        .ticket = {.generation = m_data_operation.generation},
        .flow = flow,
    };
    m_data_operation.pending = true;
    *out_ticket = m_data_operation.operation.ticket;
    return QueueResult::Queued;
}

UserspaceIpAdapterOwner::QueueResult UserspaceIpAdapterOwner::QueueCloseFlowLocked(std::uint64_t token, OperationTicket* out_ticket) {
    if (out_ticket == nullptr || m_data_operation.pending || m_data_operation.running || m_data_operation.complete) {
        return QueueResult::QueueFull;
    }
    m_data_operation.operation = {
        .kind = OperationKind::CloseFlow,
        .ticket = {.generation = m_data_operation.generation},
        .flow = {.token = token},
    };
    m_data_operation.pending = true;
    *out_ticket = m_data_operation.operation.ticket;
    return QueueResult::Queued;
}

UserspaceIpAdapterOwner::QueueResult UserspaceIpAdapterOwner::QueueSendDatagramLocked(
    std::uint64_t token, std::span<const std::uint8_t> payload, OperationTicket* out_ticket
) {
    if (out_ticket == nullptr || token == 0 || payload.size() > wgnx::tunnel::MaximumUdpPayloadStorageBytes || m_data_operation.pending ||
        m_data_operation.running || m_data_operation.complete) {
        return QueueResult::QueueFull;
    }
    m_data_operation.operation = {
        .kind = OperationKind::SendDatagram,
        .ticket = {.generation = m_data_operation.generation},
        .flow = {.token = token},
    };
    std::ranges::copy(payload, m_data_operation.payload.begin());
    m_data_operation.payload_size = static_cast<std::uint16_t>(payload.size());
    m_data_operation.pending = true;
    *out_ticket = m_data_operation.operation.ticket;
    return QueueResult::Queued;
}

UserspaceIpAdapterOwner::QueueResult UserspaceIpAdapterOwner::QueueInputPacketLocked(
    const PeerIdentity& peer,
    std::uint32_t policy_generation,
    std::uint32_t adapter_epoch,
    std::span<const std::uint8_t> packet,
    OperationTicket* out_ticket
) {
    if (out_ticket == nullptr || peer.peer_index.IsZero() || peer.activation_generation.IsZero() || policy_generation == 0 ||
        adapter_epoch == 0 || packet.empty() || packet.size() > m_data_operation.payload.size() || m_data_operation.pending ||
        m_data_operation.running || m_data_operation.complete) {
        return QueueResult::QueueFull;
    }
    m_data_operation.operation = {
        .kind = OperationKind::InputPacket,
        .ticket = {.generation = m_data_operation.generation},
        .peer = peer,
        .policy_generation = policy_generation,
        .adapter_epoch = adapter_epoch,
    };
    std::ranges::copy(packet, m_data_operation.payload.begin());
    m_data_operation.payload_size = static_cast<std::uint16_t>(packet.size());
    m_data_operation.pending = true;
    *out_ticket = m_data_operation.operation.ticket;
    return QueueResult::Queued;
}

std::optional<UserspaceIpAdapterOwner::Operation> UserspaceIpAdapterOwner::TakeNextLocked() {
    if (m_reset_pending || m_configuration_pending || m_timeout_pending) {
        const bool reset = m_reset_pending;
        const bool configure = !reset && m_configuration_pending;
        if (reset) {
            m_reset_pending = false;
        } else if (configure) {
            m_configuration_pending = false;
        } else {
            m_timeout_pending = false;
        }
        return Operation{
            .kind = reset       ? OperationKind::Reset
                    : configure ? OperationKind::Configure
                                : OperationKind::RunTimeouts,
            .local_address = m_local_address,
            .mtu = m_mtu,
        };
    }
    if (!m_data_operation.pending) {
        return std::nullopt;
    }
    m_data_operation.pending = false;
    m_data_operation.running = true;
    return m_data_operation.operation;
}

ip::UserspaceIpResult UserspaceIpAdapterOwner::Execute(const Operation& operation) {
    switch (operation.kind) {
    case OperationKind::Configure:
        m_adapter.Reset();
        return m_adapter.Initialize(operation.local_address, operation.mtu) ? ip::UserspaceIpResult::Success
                                                                            : ip::UserspaceIpResult::TransportError;
    case OperationKind::Reset:
        m_adapter.Reset();
        return ip::UserspaceIpResult::Success;
    case OperationKind::OpenFlow:
        return m_adapter.OpenFlow(operation.flow);
    case OperationKind::CloseFlow:
        m_adapter.CloseFlow(operation.flow.token);
        return ip::UserspaceIpResult::Success;
    case OperationKind::SendDatagram:
        m_adapter.ClearOutboundPackets();
        return m_adapter.Send(
            operation.flow.token,
            std::span<const std::uint8_t>(m_data_operation.payload).first(m_data_operation.payload_size)
        );
    case OperationKind::InputPacket:
        m_adapter.ClearInboundDatagrams();
        return m_adapter.Input(std::span<const std::uint8_t>(m_data_operation.payload).first(m_data_operation.payload_size));
    case OperationKind::RunTimeouts:
        m_adapter.RunTimeouts();
        return ip::UserspaceIpResult::Success;
    }
    return ip::UserspaceIpResult::TransportError;
}

void UserspaceIpAdapterOwner::CompleteLocked(const Operation& operation, ip::UserspaceIpResult result) {
    if (!operation.ticket.IsValid()) {
        if (operation.kind == OperationKind::Configure) {
            m_configuration_active = result == ip::UserspaceIpResult::Success;
        } else if (operation.kind == OperationKind::Reset) {
            m_configuration_active = false;
        }
        return;
    }
    if (operation.ticket.generation != m_data_operation.generation || !m_data_operation.running) {
        return;
    }
    m_data_operation.running = false;
    m_data_operation.complete = true;
    m_data_operation.result = result;
}

std::optional<ip::UserspaceIpResult> UserspaceIpAdapterOwner::PeekResultLocked(OperationTicket ticket) const {
    if (!ticket.IsValid() || ticket.generation != m_data_operation.generation || !m_data_operation.complete) {
        return std::nullopt;
    }
    return m_data_operation.result;
}

std::optional<ip::UserspaceIpResult> UserspaceIpAdapterOwner::TakeResultLocked(OperationTicket ticket) {
    const auto result = PeekResultLocked(ticket);
    if (!result) {
        return std::nullopt;
    }
    m_data_operation.complete = false;
    ++m_data_operation.generation;
    if (m_data_operation.generation == 0) {
        ++m_data_operation.generation;
    }
    return result;
}

std::span<const ip::UserspaceIpPacket> UserspaceIpAdapterOwner::OutboundPacketsLocked(OperationTicket ticket) const {
    if (!ticket.IsValid() || ticket.generation != m_data_operation.generation || !m_data_operation.complete ||
        m_data_operation.operation.kind != OperationKind::SendDatagram || m_data_operation.result != ip::UserspaceIpResult::Success) {
        return {};
    }
    return m_adapter.OutboundPackets();
}

std::span<const std::uint8_t> UserspaceIpAdapterOwner::InputPacketLocked(OperationTicket ticket) const {
    if (!ticket.IsValid() || ticket.generation != m_data_operation.generation || !m_data_operation.complete ||
        m_data_operation.operation.kind != OperationKind::InputPacket) {
        return {};
    }
    return std::span<const std::uint8_t>(m_data_operation.payload).first(m_data_operation.payload_size);
}

std::span<const ip::UserspaceIpDatagram> UserspaceIpAdapterOwner::InboundDatagramsLocked(OperationTicket ticket) const {
    if (!ticket.IsValid() || ticket.generation != m_data_operation.generation || !m_data_operation.complete ||
        m_data_operation.operation.kind != OperationKind::InputPacket || m_data_operation.result != ip::UserspaceIpResult::Success) {
        return {};
    }
    return m_adapter.InboundDatagrams();
}

bool UserspaceIpAdapterOwner::HadInboundDatagramRejectionLocked(OperationTicket ticket) const {
    return ticket.IsValid() && ticket.generation == m_data_operation.generation && m_data_operation.complete &&
           m_data_operation.operation.kind == OperationKind::InputPacket && m_data_operation.result == ip::UserspaceIpResult::Success &&
           m_adapter.HadInboundDatagramRejection();
}

bool UserspaceIpAdapterOwner::HadInputRejectionLocked(OperationTicket ticket) const {
    return ticket.IsValid() && ticket.generation == m_data_operation.generation && m_data_operation.complete &&
           m_data_operation.operation.kind == OperationKind::InputPacket && m_data_operation.result == ip::UserspaceIpResult::Success &&
           m_adapter.HadInputRejection();
}

bool UserspaceIpAdapterOwner::HasPendingInboundFragmentLocked(OperationTicket ticket) const {
    return ticket.IsValid() && ticket.generation == m_data_operation.generation && m_data_operation.complete &&
           m_data_operation.operation.kind == OperationKind::InputPacket && m_data_operation.result == ip::UserspaceIpResult::Success &&
           m_adapter.HasPendingInboundFragment();
}

std::uint32_t UserspaceIpAdapterOwner::AdapterEpochLocked() const {
    return m_adapter.Epoch();
}

std::uint32_t UserspaceIpAdapterOwner::NextTimeoutDelayMs() const {
    return m_adapter.NextTimeoutDelayMs();
}

void UserspaceIpAdapterOwner::CancelLocked(OperationTicket ticket) {
    if (!ticket.IsValid() || ticket.generation != m_data_operation.generation) {
        return;
    }
    m_data_operation.pending = false;
    m_data_operation.running = false;
    m_data_operation.complete = false;
    ++m_data_operation.generation;
    if (m_data_operation.generation == 0) {
        ++m_data_operation.generation;
    }
}

bool UserspaceIpAdapterOwner::HasPendingWork() const {
    return m_reset_pending || m_configuration_pending || m_timeout_pending || m_data_operation.pending || m_data_operation.running;
}

const ip::UserspaceIpAdapter& UserspaceIpAdapterOwner::AdapterForTests() const {
    return m_adapter;
}

} // namespace wgnx::sysmodule::runtime
