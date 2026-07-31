#include "wireguard/device.hpp"

#include <cstdio>
#include <memory>
#include <utility>

namespace wgnx::wireguard {

namespace {

wg_index_registry_entry* GetRegistryEntry(wg_index_registry* registry, wg_index_slot slot) {
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

const wg_index_registry_entry* GetRegistryEntry(const wg_index_registry* registry, wg_index_slot slot) {
    return GetRegistryEntry(const_cast<wg_index_registry*>(registry), slot);
}

bool IsRegisteredIndex(const wg_device* device, std::uint32_t index) {
    return wg_device_lookup_index_slot(device, index) != wg_index_slot::None;
}

void SetRegistryEntry(wg_device* device, wg_index_slot slot, std::uint32_t index) {
    if (device == nullptr) {
        return;
    }

    if (wg_index_registry_entry* entry = GetRegistryEntry(&device->index_registry, slot)) {
        entry->index = index;
        entry->active = index != 0;
    }
}

} // namespace

bool wg_device_init_from_config_entry(wg_device* device, const wgnx::PeerConfigEntry& config) {
    noise_private_key private_key{};
    noise_symmetric_key preshared_key{};
    if (!noise_parse_private_key(&private_key, config.private_key.data())) {
        return false;
    }
    const noise_symmetric_key* preshared_key_ptr = nullptr;
    if (config.preshared_key[0] != '\0') {
        if (!noise_parse_preshared_key(&preshared_key, config.preshared_key.data())) {
            return false;
        }
        preshared_key_ptr = std::addressof(preshared_key);
    }
    return wg_device_init_from_parsed_config(device, config, private_key, preshared_key_ptr);
}

bool wg_device_init_from_parsed_config(
    wg_device* device,
    const wgnx::PeerConfigEntry& config,
    const noise_private_key& local_private_key,
    const noise_symmetric_key* preshared_key
) {
    if (device == nullptr || !local_private_key.valid) {
        return false;
    }

    wg_device_reset(device);
    wg_index_allocator_init(&device->index_allocator);
    wg_device_clear_index_registry(device);

    if (!wg_peer_initialize(
            &device->peer,
            {
                .name = config.name.data(),
                .local_private_key = std::addressof(local_private_key),
                .remote_public_key = config.public_key.data(),
                .preshared_key = preshared_key,
                .persistent_keepalive_interval = config.persistent_keepalive,
            }
        )) {
        wg_device_reset(device);
        return false;
    }
    device->has_peer = true;
    return true;
}

void wg_device_reset(wg_device* device) {
    if (device == nullptr) {
        return;
    }

    std::destroy_at(device);
    std::construct_at(device);
}

std::uint32_t wg_device_allocate_index(wg_device* device) {
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

void wg_device_clear_index_registry(wg_device* device) {
    if (device == nullptr) {
        return;
    }

    device->index_registry = {};
}

void wg_device_register_handshake_index(wg_device* device, std::uint32_t index) {
    SetRegistryEntry(device, wg_index_slot::Handshake, index);
}

bool wg_device_create_handshake_initiation(wg_device* device, message_handshake_initiation* out_message) {
    wg_peer* peer = wg_device_first_peer(device);
    if (peer == nullptr || out_message == nullptr) {
        return false;
    }

    const std::uint32_t local_index = wg_device_allocate_index(device);
    if (local_index == 0) {
        return false;
    }

    noise_handshake_set_local_index(&peer->handshake, local_index);
    noise_handshake_set_remote_index(&peer->handshake, 0);
    wg_device_register_handshake_index(device, local_index);
    return noise_handshake_create_initiation(out_message, peer);
}

bool wg_device_promote_next_keypair(wg_device* device, wg_peer* peer) {
    if (device == nullptr || peer == nullptr || !peer->next_keypair.IsValid()) {
        return false;
    }

    peer->previous_keypair.Reset();
    peer->previous_keypair = std::move(peer->current_keypair);
    peer->current_keypair.Reset();
    peer->current_keypair = std::move(peer->next_keypair);
    peer->next_keypair.Reset();
    wg_device_refresh_keypair_indices(device, peer);
    return true;
}

void wg_device_refresh_keypair_indices(wg_device* device, const wg_peer* peer) {
    if (device == nullptr) {
        return;
    }

    SetRegistryEntry(device, wg_index_slot::Handshake, 0);
    SetRegistryEntry(
        device,
        wg_index_slot::CurrentKeypair,
        peer != nullptr && peer->current_keypair.IsValid() ? peer->current_keypair.LocalIndex() : 0
    );
    SetRegistryEntry(
        device,
        wg_index_slot::NextKeypair,
        peer != nullptr && peer->next_keypair.IsValid() ? peer->next_keypair.LocalIndex() : 0
    );
    SetRegistryEntry(
        device,
        wg_index_slot::PreviousKeypair,
        peer != nullptr && peer->previous_keypair.IsValid() ? peer->previous_keypair.LocalIndex() : 0
    );
}

wg_index_slot wg_device_lookup_index_slot(const wg_device* device, std::uint32_t index) {
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
        if (const wg_index_registry_entry* entry = GetRegistryEntry(&device->index_registry, slot);
            entry != nullptr && entry->active && entry->index == index) {
            return slot;
        }
    }

    return wg_index_slot::None;
}

bool wg_device_index_matches_slot(const wg_device* device, wg_index_slot slot, std::uint32_t index) {
    if (device == nullptr || index == 0) {
        return false;
    }

    if (const wg_index_registry_entry* entry = GetRegistryEntry(&device->index_registry, slot); entry != nullptr && entry->active) {
        return entry->index == index;
    }

    return false;
}

noise_keypair* wg_peer_keypair_for_slot(wg_peer* peer, wg_index_slot slot) {
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

const noise_keypair* wg_peer_keypair_for_slot(const wg_peer* peer, wg_index_slot slot) {
    return wg_peer_keypair_for_slot(const_cast<wg_peer*>(peer), slot);
}

wg_peer* wg_device_first_peer(wg_device* device) {
    if (device == nullptr || !device->has_peer) {
        return nullptr;
    }

    return &device->peer;
}

const wg_peer* wg_device_first_peer(const wg_device* device) {
    return wg_device_first_peer(const_cast<wg_device*>(device));
}

} // namespace wgnx::wireguard
