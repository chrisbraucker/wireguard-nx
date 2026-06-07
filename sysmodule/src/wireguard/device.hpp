#pragma once

#include "wgnx/config.hpp"

#include "wireguard/index_allocator.hpp"
#include "wireguard/peer.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace wgnx::wireguard {

enum class wg_index_slot : std::uint8_t {
    None = 0,
    Handshake = 1,
    CurrentKeypair = 2,
    NextKeypair = 3,
    PreviousKeypair = 4,
};

struct wg_index_registry_entry {
    std::uint32_t index{0};
    bool active{false};
};

struct wg_index_registry {
    wg_index_registry_entry handshake{};
    wg_index_registry_entry current_keypair{};
    wg_index_registry_entry next_keypair{};
    wg_index_registry_entry previous_keypair{};
};

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
    wg_index_allocator index_allocator{};
    wg_index_registry index_registry{};
    std::array<wg_peer, wgnx::MaxPeers> peers{};
    std::size_t peer_count{0};
};

bool wg_device_init_from_config_entry(wg_device *device, const wgnx::PeerConfigEntry &config);
void wg_device_reset(wg_device *device);
std::uint32_t wg_device_allocate_index(wg_device *device);
void wg_device_clear_index_registry(wg_device *device);
void wg_device_register_handshake_index(wg_device *device, std::uint32_t index);
void wg_device_refresh_keypair_indices(wg_device *device, const wg_peer *peer);
wg_index_slot wg_device_lookup_index_slot(const wg_device *device, std::uint32_t index);
bool wg_device_index_matches_slot(const wg_device *device, wg_index_slot slot, std::uint32_t index);
noise_keypair *wg_peer_keypair_for_slot(wg_peer *peer, wg_index_slot slot);
const noise_keypair *wg_peer_keypair_for_slot(const wg_peer *peer, wg_index_slot slot);
wg_peer *wg_device_first_peer(wg_device *device);
const wg_peer *wg_device_first_peer(const wg_device *device);

} // namespace wgnx::wireguard
