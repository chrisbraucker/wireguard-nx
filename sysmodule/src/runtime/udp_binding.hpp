#pragma once

#include "wgnx/platform/udp.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace wgnx::sysmodule::runtime {

class UdpBinding {
public:
    constexpr UdpBinding() = default;
    ~UdpBinding();

    UdpBinding(const UdpBinding &) = delete;
    UdpBinding &operator=(const UdpBinding &) = delete;
    UdpBinding(UdpBinding &&) = delete;
    UdpBinding &operator=(UdpBinding &&) = delete;

    void SetEndpoint(const wgnx::platform::endpoint &endpoint, const char *text);
    void ClearEndpoint();
    void Reset();

    wgnx::platform::socket_error Open(std::uint32_t generation);
    void Close();
    void Suspend();

    wgnx::platform::socket_error Send(
        std::span<const std::uint8_t> packet,
        std::size_t *sent) const;

    bool HasEndpoint() const { return m_has_endpoint; }
    bool IsOpen() const { return m_socket != wgnx::platform::InvalidSocket; }
    bool IsSuspended() const { return m_suspended; }
    bool Matches(std::uint32_t generation, wgnx::platform::socket_handle socket) const {
        return m_generation == generation && m_socket == socket;
    }

    const wgnx::platform::endpoint &Endpoint() const { return m_endpoint; }
    const char *EndpointText() const { return m_endpoint_text; }
    wgnx::platform::socket_handle Socket() const { return m_socket; }
    std::uint32_t Generation() const { return m_generation; }

private:
    wgnx::platform::endpoint m_endpoint{};
    char m_endpoint_text[64]{};
    wgnx::platform::socket_handle m_socket{wgnx::platform::InvalidSocket};
    std::uint32_t m_generation{0};
    bool m_has_endpoint{false};
    bool m_suspended{false};
};

} // namespace wgnx::sysmodule::runtime
