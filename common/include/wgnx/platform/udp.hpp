#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "wgnx/protocol.hpp"

namespace wgnx::platform {

enum class address_family : std::uint8_t {
    unspecified = 0,
    inet = 1,
    inet6 = 2,
};

static_assert(static_cast<std::uint8_t>(address_family::unspecified) == static_cast<std::uint8_t>(wgnx::PeerResolvedFamily::Unspecified));
static_assert(static_cast<std::uint8_t>(address_family::inet) == static_cast<std::uint8_t>(wgnx::PeerResolvedFamily::Inet));
static_assert(static_cast<std::uint8_t>(address_family::inet6) == static_cast<std::uint8_t>(wgnx::PeerResolvedFamily::Inet6));

struct endpoint {
    address_family family{address_family::unspecified};
    std::uint16_t port{0};
    std::array<std::uint8_t, 16> address{};
};

struct endpoint_resolution_result {
    bool success{false};
    wgnx::PeerErrorStage error_stage{wgnx::PeerErrorStage::None};
    wgnx::PeerErrorCode error_code{wgnx::PeerErrorCode::None};
    endpoint resolved{};
    std::array<char, sizeof(wgnx::PeerInfo::resolved_endpoint)> text{};
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

enum class udp_receive_disposition : std::uint8_t {
    datagram = 0,
    retry,
    failure,
};

enum class udp_receive_native_condition : std::uint8_t {
    none = 0,
    would_block,
    timed_out,
    interrupted,
    other,
};

struct udp_receive_result {
    udp_receive_disposition disposition{udp_receive_disposition::failure};
    udp_receive_native_condition native_condition{
        udp_receive_native_condition::other};
    std::size_t bytes_received{0};
    endpoint source{};
    socket_error error{socket_error::receive_failed};
    std::int64_t native_result{-1};
    std::uint32_t native_error{0};
};

[[nodiscard]] constexpr udp_receive_result classify_udp_receive_result(
    std::int64_t native_result,
    udp_receive_native_condition native_condition,
    std::uint32_t native_error,
    const endpoint &source = {}) {
    if (native_result >= 0) {
        return {
            .disposition = udp_receive_disposition::datagram,
            .native_condition = udp_receive_native_condition::none,
            .bytes_received = static_cast<std::size_t>(native_result),
            .source = source,
            .error = socket_error::none,
            .native_result = native_result,
            .native_error = native_error,
        };
    }

    if (native_condition == udp_receive_native_condition::would_block ||
        native_condition == udp_receive_native_condition::timed_out ||
        native_condition == udp_receive_native_condition::interrupted) {
        return {
            .disposition = udp_receive_disposition::retry,
            .native_condition = native_condition,
            .bytes_received = 0,
            .source = {},
            .error = socket_error::none,
            .native_result = native_result,
            .native_error = native_error,
        };
    }

    return {
        .disposition = udp_receive_disposition::failure,
        .native_condition = native_condition,
        .bytes_received = 0,
        .source = {},
        .error = socket_error::receive_failed,
        .native_result = native_result,
        .native_error = native_error,
    };
}

struct NetworkPathSnapshot {
    std::uint32_t initialization_result{0};
    std::uint32_t internet_status_result{0};
    std::uint32_t ip_config_result{0};
    std::uint32_t connection_type{0};
    std::uint32_t connection_status{0};
    std::uint32_t wifi_strength{0};
    std::uint32_t current_address{0};
    std::uint32_t subnet_mask{0};
    std::uint32_t gateway{0};
    std::uint32_t primary_dns{0};
    std::uint32_t secondary_dns{0};

    constexpr bool operator==(const NetworkPathSnapshot &) const = default;
};

/*
 * Deviation from Linux:
 * This exposes a compact project-owned endpoint value instead of `sockaddr`
 * unions. The implication is that higher-level runtime and future protocol
 * code stay independent of Horizon networking headers, while the Horizon
 * adapter remains responsible for translating to native socket types.
 */
endpoint_resolution_result resolve_endpoint(std::string_view configured_endpoint);
bool endpoint_to_string(const endpoint &endpoint, std::span<char> out_text);

/*
 * Deviation from Linux:
 * `socket_handle` maps directly to a userspace UDP socket descriptor. There is
 * no kernel `sock` wrapper, reference counting, or asynchronous receive path
 * yet; this is only the narrow transport boundary Milestone 3 needs.
 */
constexpr inline socket_handle InvalidSocket = -1;

socket_error udp_open(socket_handle *out_socket, address_family family);
void udp_close(socket_handle socket);
socket_error udp_send(
    socket_handle socket,
    const endpoint &destination,
    std::span<const std::uint8_t> data,
    std::size_t *out_sent);
[[nodiscard]] udp_receive_result udp_receive(
    socket_handle socket,
    std::span<std::uint8_t> buffer);

// Samples Horizon's network path. Runtime policy owns comparison and reaction.
NetworkPathSnapshot sample_network_path(std::uint64_t sequence);

} // namespace wgnx::platform
