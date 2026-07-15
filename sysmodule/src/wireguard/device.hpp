#pragma once

#include "wgnx/config.hpp"

#include "wireguard/index_allocator.hpp"
#include "wireguard/peer.hpp"

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
 * Each config entry is a complete tunnel with exactly one remote peer, so the
 * device owns that peer directly. Multi-peer interface support would require a
 * different config and routing model rather than an unused nested peer array.
 */
struct wg_device {
    char name[sizeof(wgnx::PeerInfo::name)]{};
    char interface_address[sizeof(wgnx::PeerInfo::address)]{};
    char dns[sizeof(wgnx::PeerConfigEntry::dns)]{};
    std::uint16_t listen_port{0};
    std::uint16_t mtu{0};
    bool has_private_key{false};
    bool has_dns{false};
    wg_index_allocator index_allocator{};
    wg_index_registry index_registry{};
    wg_peer peer{};
    bool has_peer{false};
};

bool wg_device_init_from_config_entry(wg_device *device, const wgnx::PeerConfigEntry &config);
bool wg_device_init_from_parsed_config(
    wg_device *device,
    const wgnx::PeerConfigEntry &config,
    const noise_private_key &local_private_key,
    const noise_symmetric_key *preshared_key);
void wg_device_reset(wg_device *device);
std::uint32_t wg_device_allocate_index(wg_device *device);
void wg_device_clear_index_registry(wg_device *device);
void wg_device_register_handshake_index(wg_device *device, std::uint32_t index);
bool wg_device_create_handshake_initiation(
    wg_device *device,
    message_handshake_initiation *out_message);
bool wg_device_promote_next_keypair(wg_device *device, wg_peer *peer);
void wg_device_refresh_keypair_indices(wg_device *device, const wg_peer *peer);
wg_index_slot wg_device_lookup_index_slot(const wg_device *device, std::uint32_t index);
bool wg_device_index_matches_slot(const wg_device *device, wg_index_slot slot, std::uint32_t index);
noise_keypair *wg_peer_keypair_for_slot(wg_peer *peer, wg_index_slot slot);
const noise_keypair *wg_peer_keypair_for_slot(const wg_peer *peer, wg_index_slot slot);
wg_peer *wg_device_first_peer(wg_device *device);
const wg_peer *wg_device_first_peer(const wg_device *device);

} // namespace wgnx::wireguard
