#pragma once

#include "wireguard/messages.hpp"

#include <span>

namespace wgnx::wireguard {

struct PacketDispatchHandlers {
    void* context{nullptr};
    void (*handshake_initiation)(void* context, const message_handshake_initiation& message){nullptr};
    void (*handshake_response)(void* context, const message_handshake_response& message){nullptr};
    void (*cookie_reply)(void* context, const message_handshake_cookie& message){nullptr};
    void (*transport_data)(void* context, const message_transport_data& header, std::span<const std::uint8_t> payload){nullptr};
};

ParseResult DispatchPacket(std::span<const std::uint8_t> packet, const PacketDispatchHandlers& handlers);

} // namespace wgnx::wireguard
