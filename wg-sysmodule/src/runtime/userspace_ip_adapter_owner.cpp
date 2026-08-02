#include "runtime/userspace_ip_adapter_owner.hpp"

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
    m_configuration_active = false;
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

std::optional<UserspaceIpAdapterOwner::Operation> UserspaceIpAdapterOwner::TakeNextLocked() {
    if (m_reset_pending || m_configuration_pending) {
        const bool reset = m_reset_pending;
        if (reset) {
            m_reset_pending = false;
        } else {
            m_configuration_pending = false;
        }
        return Operation{
            .kind = reset ? OperationKind::Reset : OperationKind::Configure,
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

std::optional<ip::UserspaceIpResult> UserspaceIpAdapterOwner::TakeResultLocked(OperationTicket ticket) {
    if (!ticket.IsValid() || ticket.generation != m_data_operation.generation || !m_data_operation.complete) {
        return std::nullopt;
    }
    m_data_operation.complete = false;
    ++m_data_operation.generation;
    if (m_data_operation.generation == 0) {
        ++m_data_operation.generation;
    }
    return m_data_operation.result;
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
    return m_reset_pending || m_configuration_pending || m_data_operation.pending || m_data_operation.running;
}

const ip::UserspaceIpAdapter& UserspaceIpAdapterOwner::AdapterForTests() const {
    return m_adapter;
}

} // namespace wgnx::sysmodule::runtime
