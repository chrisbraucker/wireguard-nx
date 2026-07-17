#pragma once

#include "wgnx/platform/udp.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace wgnx::sysmodule::runtime {

struct UdpRebindRequest {
    std::size_t peer_index{0};
    std::uint32_t activation_generation{0};
};

class UdpRebindQueue {
public:
    bool Queue(const UdpRebindRequest &request) {
        const bool scheduled = !m_pending;
        m_request = request;
        m_pending = true;
        return scheduled;
    }

    bool Take(UdpRebindRequest &out) {
        if (!m_pending) {
            return false;
        }
        out = m_request;
        m_pending = false;
        return true;
    }

    bool IsPending(const UdpRebindRequest &request) const {
        return m_pending && m_request.peer_index == request.peer_index &&
               m_request.activation_generation == request.activation_generation;
    }

private:
    UdpRebindRequest m_request{};
    bool m_pending{false};
};

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
    void AdoptOpenSocket(
        const wgnx::platform::endpoint &endpoint,
        const char *text,
        std::uint32_t generation,
        wgnx::platform::socket_handle socket);
    void Close();
    void Suspend();
    wgnx::platform::socket_handle ReleaseSocket();

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

    struct SendSnapshot {
        wgnx::platform::endpoint endpoint{};
        wgnx::platform::socket_handle socket{wgnx::platform::InvalidSocket};
        std::uint32_t generation{0};
    };

    bool SnapshotForSend(SendSnapshot &out) const;

private:
    wgnx::platform::endpoint m_endpoint{};
    char m_endpoint_text[64]{};
    wgnx::platform::socket_handle m_socket{wgnx::platform::InvalidSocket};
    std::uint32_t m_generation{0};
    bool m_has_endpoint{false};
    bool m_suspended{false};
};

} // namespace wgnx::sysmodule::runtime
