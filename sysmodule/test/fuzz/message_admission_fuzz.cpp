#include "wireguard/dispatch.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace {

void OnHandshakeInitiation(void*, const wgnx::wireguard::message_handshake_initiation&) {}

void OnHandshakeResponse(void*, const wgnx::wireguard::message_handshake_response&) {}

void OnCookieReply(void*, const wgnx::wireguard::message_handshake_cookie&) {}

void OnTransportData(void*, const wgnx::wireguard::message_transport_data&, std::span<const std::uint8_t>) {}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span<const std::uint8_t> packet{data, size};
    const wgnx::wireguard::PacketDispatchHandlers handlers{
        .handshake_initiation = OnHandshakeInitiation,
        .handshake_response = OnHandshakeResponse,
        .cookie_reply = OnCookieReply,
        .transport_data = OnTransportData,
    };
    static_cast<void>(wgnx::wireguard::DispatchPacket(packet, handlers));
    return 0;
}
