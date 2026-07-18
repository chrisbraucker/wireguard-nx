#include "runtime/udp_binding.hpp"

#include <cstdio>
#include <cstdlib>

namespace wgnx::sysmodule::runtime {

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

void UdpBinding::AdoptOpenSocket(
    const wgnx::platform::endpoint &endpoint,
    const char *text,
    SocketGeneration generation,
    wgnx::platform::socket_handle socket) {
    // Callers explicitly release any prior socket into a close effect before
    // adopting a replacement. Binding state itself never performs platform I/O.
    if (m_socket != wgnx::platform::InvalidSocket) {
        std::abort();
    }
    SetEndpoint(endpoint, text);
    m_socket = socket;
    m_generation = generation;
    m_suspended = false;
}

wgnx::platform::socket_handle UdpBinding::ReleaseAndSuspend() {
    m_suspended = true;
    return ReleaseSocket();
}

wgnx::platform::socket_handle UdpBinding::ReleaseSocket() {
    const auto socket = m_socket;
    m_socket = wgnx::platform::InvalidSocket;
    m_generation = SocketGeneration{};
    return socket;
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

UdpBinding::Snapshot UdpBinding::StateSnapshot() const {
    Snapshot snapshot{
        .endpoint = m_endpoint,
        .socket = m_socket,
        .generation = m_generation,
        .has_endpoint = m_has_endpoint,
        .suspended = m_suspended,
    };
    std::snprintf(
        snapshot.endpoint_text.data(),
        snapshot.endpoint_text.size(),
        "%s",
        m_endpoint_text);
    return snapshot;
}

} // namespace wgnx::sysmodule::runtime
