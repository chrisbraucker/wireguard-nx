#include "wireguard/device.hpp"

#include <cstdio>

namespace wgnx::wireguard {

bool wg_device_init_from_config_entry(wg_device *device, const wgnx::PeerConfigEntry &config) {
    if (device == nullptr) {
        return false;
    }

    wg_device_reset(device);
    std::snprintf(device->name, sizeof(device->name), "%s", config.name);
    std::snprintf(device->interface_address, sizeof(device->interface_address), "%s", config.address);
    std::snprintf(device->private_key, sizeof(device->private_key), "%s", config.private_key);
    std::snprintf(device->dns, sizeof(device->dns), "%s", config.dns);
    device->listen_port = config.listen_port;
    device->mtu = config.mtu;
    device->has_private_key = config.private_key[0] != '\0';
    device->has_dns = config.dns[0] != '\0';
    wg_index_allocator_init(&device->index_allocator);

    wg_peer_init_from_config(&device->peers[0], config);
    device->peer_count = 1;
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

    return wg_index_allocator_next(&device->index_allocator);
}

wg_peer *wg_device_first_peer(wg_device *device) {
    if (device == nullptr || device->peer_count == 0) {
        return nullptr;
    }

    return &device->peers[0];
}

const wg_peer *wg_device_first_peer(const wg_device *device) {
    return wg_device_first_peer(const_cast<wg_device *>(device));
}

} // namespace wgnx::wireguard
