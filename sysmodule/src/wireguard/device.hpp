#pragma once

#include "wgnx/config.hpp"

#include "wireguard/peer.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace wgnx::wireguard {

/*
 * Deviation from Linux:
 * Each current config entry maps to one device with one instantiated peer,
 * because the project config model is currently single-peer per tunnel entry.
 * The implication is that `wg_device` keeps array-based peer ownership for
 * future expansion, but `wg_device_init_from_config_entry` currently populates
 * exactly one peer.
 */
struct wg_device {
    char name[sizeof(wgnx::PeerInfo::name)]{};
    char interface_address[sizeof(wgnx::PeerInfo::address)]{};
    char private_key[sizeof(wgnx::PeerConfigEntry::private_key)]{};
    char dns[sizeof(wgnx::PeerConfigEntry::dns)]{};
    std::uint16_t listen_port{0};
    std::uint16_t mtu{0};
    bool has_private_key{false};
    bool has_dns{false};
    std::array<wg_peer, wgnx::MaxPeers> peers{};
    std::size_t peer_count{0};
};

bool wg_device_init_from_config_entry(wg_device *device, const wgnx::PeerConfigEntry &config);
void wg_device_reset(wg_device *device);
wg_peer *wg_device_first_peer(wg_device *device);
const wg_peer *wg_device_first_peer(const wg_device *device);

} // namespace wgnx::wireguard
