#pragma once

#include <cstddef>
#include <cstdint>

#include "wgnx/protocol.hpp"

namespace wgnx::platform {

enum class address_family : std::uint8_t {
    unspecified = 0,
    inet = 1,
    inet6 = 2,
};

struct endpoint {
    address_family family{address_family::unspecified};
    std::uint16_t port{0};
    std::uint8_t address[16]{};
};

struct endpoint_resolution_result {
    bool success{false};
    wgnx::PeerErrorStage error_stage{wgnx::PeerErrorStage::None};
    wgnx::PeerErrorCode error_code{wgnx::PeerErrorCode::None};
    endpoint resolved{};
    char text[sizeof(wgnx::PeerInfo::resolved_endpoint)]{};
};

using socket_handle = std::int32_t;

enum class socket_error : std::uint32_t {
    none = 0,
    invalid_endpoint = 1,
    transport_init_failed = 2,
    open_failed = 3,
    send_failed = 4,
    receive_failed = 5,
};

/*
 * Deviation from Linux:
 * This exposes a compact project-owned endpoint value instead of `sockaddr`
 * unions. The implication is that higher-level runtime and future protocol
 * code stay independent of Horizon networking headers, while the Horizon
 * adapter remains responsible for translating to native socket types.
 */
endpoint_resolution_result resolve_endpoint(const char *configured_endpoint);
bool endpoint_to_string(const endpoint *endpoint, char *out_text, std::size_t out_text_size);

/*
 * Deviation from Linux:
 * `socket_handle` maps directly to a userspace UDP socket descriptor. There is
 * no kernel `sock` wrapper, reference counting, or asynchronous receive path
 * yet; this is only the narrow transport boundary Milestone 3 needs.
 */
constexpr inline socket_handle InvalidSocket = -1;

socket_error udp_open(socket_handle *out_socket, address_family family);
void udp_close(socket_handle socket);
socket_error udp_send(socket_handle socket, const endpoint *destination, const void *data, std::size_t size, std::size_t *out_sent);
socket_error udp_receive(socket_handle socket, void *buffer, std::size_t capacity, std::size_t *out_received, endpoint *out_source);

} // namespace wgnx::platform
