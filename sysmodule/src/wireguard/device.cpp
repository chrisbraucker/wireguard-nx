#include "wireguard/device.hpp"

#include <cstdio>

namespace wgnx::wireguard {

namespace {

wg_index_registry_entry *GetRegistryEntry(wg_index_registry *registry, wg_index_slot slot) {
    if (registry == nullptr) {
        return nullptr;
    }

    switch (slot) {
        case wg_index_slot::Handshake:
            return &registry->handshake;
        case wg_index_slot::CurrentKeypair:
            return &registry->current_keypair;
        case wg_index_slot::NextKeypair:
            return &registry->next_keypair;
        case wg_index_slot::PreviousKeypair:
            return &registry->previous_keypair;
        case wg_index_slot::None:
            return nullptr;
    }

    return nullptr;
}

const wg_index_registry_entry *GetRegistryEntry(const wg_index_registry *registry, wg_index_slot slot) {
    return GetRegistryEntry(const_cast<wg_index_registry *>(registry), slot);
}

bool IsRegisteredIndex(const wg_device *device, std::uint32_t index) {
    return wg_device_lookup_index_slot(device, index) != wg_index_slot::None;
}

void SetRegistryEntry(wg_device *device, wg_index_slot slot, std::uint32_t index) {
    if (device == nullptr) {
        return;
    }

    if (wg_index_registry_entry *entry = GetRegistryEntry(&device->index_registry, slot)) {
        entry->index = index;
        entry->active = index != 0;
    }
}

} // namespace

bool wg_device_init_from_config_entry(wg_device *device, const wgnx::PeerConfigEntry &config) {
    if (device == nullptr) {
        return false;
    }

    wg_device_reset(device);
    std::snprintf(device->name, sizeof(device->name), "%s", config.name.data());
    std::snprintf(device->interface_address, sizeof(device->interface_address), "%s", config.address.data());
    std::snprintf(device->private_key, sizeof(device->private_key), "%s", config.private_key.data());
    std::snprintf(device->dns, sizeof(device->dns), "%s", config.dns.data());
    device->listen_port = config.listen_port;
    device->mtu = config.mtu;
    device->has_private_key = config.private_key[0] != '\0';
    device->has_dns = config.dns[0] != '\0';
    wg_index_allocator_init(&device->index_allocator);
    wg_device_clear_index_registry(device);

    wg_peer_init_from_config(&device->peer, config);
    if (!wg_peer_prepare_static_identity(&device->peer, config.private_key.data())) {
        wg_device_reset(device);
        return false;
    }
    device->has_peer = true;
    return true;
}

void wg_device_reset(wg_device *device) {
    if (device == nullptr) {
        return;
    }

    *device = {};
}

std::uint32_t wg_device_allocate_index(wg_device *device) {
    if (device == nullptr) {
        return 0;
    }

    for (int attempt = 0; attempt < 32; ++attempt) {
        const std::uint32_t candidate = wg_index_allocator_next(&device->index_allocator);
        if (candidate != 0 && !IsRegisteredIndex(device, candidate)) {
            return candidate;
        }
    }

    return 0;
}

void wg_device_clear_index_registry(wg_device *device) {
    if (device == nullptr) {
        return;
    }

    device->index_registry = {};
}

void wg_device_register_handshake_index(wg_device *device, std::uint32_t index) {
    SetRegistryEntry(device, wg_index_slot::Handshake, index);
}

void wg_device_refresh_keypair_indices(wg_device *device, const wg_peer *peer) {
    if (device == nullptr) {
        return;
    }

    SetRegistryEntry(device, wg_index_slot::Handshake, 0);
    SetRegistryEntry(
        device,
        wg_index_slot::CurrentKeypair,
        peer != nullptr && peer->current_keypair.IsValid()
            ? peer->current_keypair.LocalIndex()
            : 0);
    SetRegistryEntry(
        device,
        wg_index_slot::NextKeypair,
        peer != nullptr && peer->next_keypair.IsValid()
            ? peer->next_keypair.LocalIndex()
            : 0);
    SetRegistryEntry(
        device,
        wg_index_slot::PreviousKeypair,
        peer != nullptr && peer->previous_keypair.IsValid()
            ? peer->previous_keypair.LocalIndex()
            : 0);
}

wg_index_slot wg_device_lookup_index_slot(const wg_device *device, std::uint32_t index) {
    if (device == nullptr || index == 0) {
        return wg_index_slot::None;
    }

    constexpr wg_index_slot Slots[] = {
        wg_index_slot::Handshake,
        wg_index_slot::CurrentKeypair,
        wg_index_slot::NextKeypair,
        wg_index_slot::PreviousKeypair,
    };
    for (const wg_index_slot slot : Slots) {
        if (const wg_index_registry_entry *entry = GetRegistryEntry(&device->index_registry, slot);
            entry != nullptr && entry->active && entry->index == index) {
            return slot;
        }
    }

    return wg_index_slot::None;
}

bool wg_device_index_matches_slot(const wg_device *device, wg_index_slot slot, std::uint32_t index) {
    if (device == nullptr || index == 0) {
        return false;
    }

    if (const wg_index_registry_entry *entry = GetRegistryEntry(&device->index_registry, slot);
        entry != nullptr && entry->active) {
        return entry->index == index;
    }

    return false;
}

noise_keypair *wg_peer_keypair_for_slot(wg_peer *peer, wg_index_slot slot) {
    if (peer == nullptr) {
        return nullptr;
    }

    switch (slot) {
        case wg_index_slot::CurrentKeypair:
            return &peer->current_keypair;
        case wg_index_slot::NextKeypair:
            return &peer->next_keypair;
        case wg_index_slot::PreviousKeypair:
            return &peer->previous_keypair;
        case wg_index_slot::Handshake:
        case wg_index_slot::None:
            return nullptr;
    }

    return nullptr;
}

const noise_keypair *wg_peer_keypair_for_slot(const wg_peer *peer, wg_index_slot slot) {
    return wg_peer_keypair_for_slot(const_cast<wg_peer *>(peer), slot);
}

wg_peer *wg_device_first_peer(wg_device *device) {
    if (device == nullptr || !device->has_peer) {
        return nullptr;
    }

    return &device->peer;
}

const wg_peer *wg_device_first_peer(const wg_device *device) {
    return wg_device_first_peer(const_cast<wg_device *>(device));
}

} // namespace wgnx::wireguard
