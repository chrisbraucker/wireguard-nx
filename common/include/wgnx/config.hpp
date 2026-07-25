#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "wgnx/protocol.hpp"

namespace wgnx {

enum PeerConfigFieldFlags : std::uint32_t {
    PeerConfigField_PrivateKey = 1U << 0,
    PeerConfigField_ListenPort = 1U << 1,
    PeerConfigField_Dns = 1U << 2,
    PeerConfigField_Mtu = 1U << 3,
    PeerConfigField_PublicKey = 1U << 4,
    PeerConfigField_PresharedKey = 1U << 5,
    PeerConfigField_AllowedIps = 1U << 6,
    PeerConfigField_PersistentKeepalive = 1U << 7,
};

struct PeerConfigEntry {
    std::array<char, sizeof(PeerInfo::name)> name{};
    std::array<char, sizeof(PeerInfo::address)> address{};
    std::array<char, sizeof(PeerInfo::endpoint)> endpoint{};
    std::array<char, 64> private_key{};
    std::array<char, 128> dns{};
    std::array<char, 64> public_key{};
    std::array<char, 64> preshared_key{};
    std::array<char, 256> allowed_ips{};
    std::uint16_t listen_port;
    std::uint16_t persistent_keepalive;
    std::uint16_t mtu;
    std::uint16_t reserved0;
    std::uint32_t field_flags;
};

struct PeerConfigSet {
    std::array<PeerConfigEntry, MaxPeers> peers{};
    std::size_t peer_count{0};
};

} // namespace wgnx
