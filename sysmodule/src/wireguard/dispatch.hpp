#pragma once

#include "wgnx/platform/packet.hpp"

#include "wireguard/messages.hpp"

namespace wgnx::wireguard {

struct PacketDispatchHandlers {
    void *context{nullptr};
    void (*handshake_initiation)(void *context, const message_handshake_initiation &message){nullptr};
    void (*handshake_response)(void *context, const message_handshake_response &message){nullptr};
    void (*cookie_reply)(void *context, const message_handshake_cookie &message){nullptr};
    void (*transport_data)(
        void *context,
        const message_transport_data &header,
        const std::uint8_t *payload,
        std::size_t payload_size){nullptr};
};

ParseResult DispatchPacket(
    const wgnx::platform::packet_buffer *packet,
    const PacketDispatchHandlers &handlers);

} // namespace wgnx::wireguard
