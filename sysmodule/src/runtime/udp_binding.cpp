#include "runtime/udp_binding.hpp"

#include <cstdio>

namespace wgnx::sysmodule::runtime {

UdpBinding::~UdpBinding() {
    Close();
}

void UdpBinding::SetEndpoint(
    const wgnx::platform::endpoint &endpoint,
    const char *text) {
    m_endpoint = endpoint;
    std::snprintf(m_endpoint_text, sizeof(m_endpoint_text), "%s", text != nullptr ? text : "");
    m_has_endpoint = true;
}

void UdpBinding::ClearEndpoint() {
    m_endpoint = {};
    m_endpoint_text[0] = '\0';
    m_has_endpoint = false;
}

void UdpBinding::Reset() {
    Close();
    ClearEndpoint();
    m_suspended = false;
}

wgnx::platform::socket_error UdpBinding::Open(std::uint32_t generation) {
    Close();
    if (!m_has_endpoint) {
        return wgnx::platform::socket_error::invalid_endpoint;
    }

    const auto error = wgnx::platform::udp_open(&m_socket, m_endpoint.family);
    if (error != wgnx::platform::socket_error::none) {
        m_socket = wgnx::platform::InvalidSocket;
        return error;
    }
    m_generation = generation;
    m_suspended = false;
    return wgnx::platform::socket_error::none;
}

void UdpBinding::AdoptOpenSocket(
    const wgnx::platform::endpoint &endpoint,
    const char *text,
    std::uint32_t generation,
    wgnx::platform::socket_handle socket) {
    Close();
    SetEndpoint(endpoint, text);
    m_socket = socket;
    m_generation = generation;
    m_suspended = false;
}

void UdpBinding::Close() {
    if (m_socket != wgnx::platform::InvalidSocket) {
        wgnx::platform::udp_close(m_socket);
    }
    m_socket = wgnx::platform::InvalidSocket;
    m_generation = 0;
}

void UdpBinding::Suspend() {
    m_suspended = true;
    Close();
}

wgnx::platform::socket_handle UdpBinding::ReleaseSocket() {
    const auto socket = m_socket;
    m_socket = wgnx::platform::InvalidSocket;
    m_generation = 0;
    return socket;
}

wgnx::platform::socket_error UdpBinding::Send(
    std::span<const std::uint8_t> packet,
    std::size_t *sent) const {
    if (m_suspended || !m_has_endpoint || !IsOpen()) {
        return wgnx::platform::socket_error::send_failed;
    }
    return wgnx::platform::udp_send(m_socket, m_endpoint, packet, sent);
}

bool UdpBinding::SnapshotForSend(SendSnapshot &out) const {
    if (m_suspended || !m_has_endpoint || !IsOpen()) {
        return false;
    }
    out = {
        .endpoint = m_endpoint,
        .socket = m_socket,
        .generation = m_generation,
    };
    return true;
}

} // namespace wgnx::sysmodule::runtime
