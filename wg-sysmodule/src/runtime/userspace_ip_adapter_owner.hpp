#pragma once

#include "ip/userspace_ip_adapter.hpp"
#include "wgnx/resource_budget.hpp"

#include <array>
#include <cstdint>

namespace wgnx::sysmodule::runtime {

class UserspaceIpAdapterOwner {
  public:
    void QueueConfigure(const std::array<std::uint8_t, 4>& local_address, std::uint16_t mtu);
    void QueueReset();
    void Run();

    [[nodiscard]] bool HasPendingWork() const;
    [[nodiscard]] const ip::UserspaceIpAdapter& AdapterForTests() const;

  private:
    std::array<std::uint8_t, 4> m_local_address{};
    ip::UserspaceIpAdapter m_adapter{};
    std::uint16_t m_mtu{};
    bool m_configuration_pending{};
    bool m_reset_pending{};
};

static_assert(sizeof(UserspaceIpAdapterOwner) <= wgnx::resource_budget::MaximumUserspaceIpAdapterOwnerBytes);

} // namespace wgnx::sysmodule::runtime
