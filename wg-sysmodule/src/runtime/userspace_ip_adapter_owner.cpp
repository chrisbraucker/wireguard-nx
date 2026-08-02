#include "runtime/userspace_ip_adapter_owner.hpp"

namespace wgnx::sysmodule::runtime {

void UserspaceIpAdapterOwner::QueueConfigure(const std::array<std::uint8_t, 4>& local_address, std::uint16_t mtu) {
    m_local_address = local_address;
    m_mtu = mtu;
    m_configuration_pending = true;
}

void UserspaceIpAdapterOwner::QueueReset() {
    m_reset_pending = true;
}

void UserspaceIpAdapterOwner::Run() {
    const bool reset = m_reset_pending;
    const bool configure = m_configuration_pending;
    m_reset_pending = false;
    m_configuration_pending = false;
    if (reset || configure) {
        m_adapter.Reset();
    }
    if (configure) {
        static_cast<void>(m_adapter.Initialize(m_local_address, m_mtu));
    }
}

bool UserspaceIpAdapterOwner::HasPendingWork() const {
    return m_reset_pending || m_configuration_pending;
}

const ip::UserspaceIpAdapter& UserspaceIpAdapterOwner::AdapterForTests() const {
    return m_adapter;
}

} // namespace wgnx::sysmodule::runtime
