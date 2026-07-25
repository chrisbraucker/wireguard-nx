#include "runtime/peer_configuration.hpp"

#include "config_loader.hpp"
#include "wireguard/crypto/primitives.hpp"
#include "wireguard/session.hpp"

#include <cstring>
#include <memory>

namespace wgnx::sysmodule::runtime {

namespace {

void ClearEncodedSecrets(wgnx::PeerConfigEntry& entry) {
    wgnx::wireguard::crypto::secure_clear(entry.private_key);
    wgnx::wireguard::crypto::secure_clear(entry.preshared_key);
}

PeerConfigDerivedInfo DeriveSecrets(wgnx::PeerConfigEntry& entry) {
    PeerConfigDerivedInfo derived{};
    const bool private_key_valid =
        wgnx::wireguard::noise_parse_private_key(std::addressof(derived.local_private_key), entry.private_key.data());
    const bool preshared_key_valid =
        entry.preshared_key[0] == '\0' ||
        wgnx::wireguard::noise_parse_preshared_key(std::addressof(derived.preshared_key), entry.preshared_key.data());
    derived.has_preshared_key = entry.preshared_key[0] != '\0' && preshared_key_valid;
    derived.secrets_valid = private_key_valid && preshared_key_valid;
    if (private_key_valid &&
        wgnx::wireguard::noise_derive_public_key_text(derived.derived_public_key, std::addressof(derived.local_private_key))) {
        derived.has_derived_public_key = true;
    }
    ClearEncodedSecrets(entry);
    return derived;
}

} // namespace

bool PeerConfigurationLoader::Load(LoadedPeerConfiguration& out) const {
    out.~LoadedPeerConfiguration();
    std::construct_at(std::addressof(out));
    out.auto_start_peer_index = -1;

    char auto_start_name[sizeof(wgnx::PeerInfo::name)]{};
    const bool has_auto_start_name = LoadAutoStartPeerName(auto_start_name, sizeof(auto_start_name));

    wgnx::PeerConfigSet parsed{};
    if (!LoadPeerConfig(std::addressof(parsed))) {
        return false;
    }

    out.peer_count = parsed.peer_count;
    for (std::size_t index = 0; index < out.peer_count; ++index) {
        out.peers[index] = parsed.peers[index];
        out.derived[index] = DeriveSecrets(out.peers[index]);
        ClearEncodedSecrets(parsed.peers[index]);
        if (has_auto_start_name && std::strncmp(out.peers[index].name.data(), auto_start_name, out.peers[index].name.size()) == 0) {
            out.auto_start_peer_index = static_cast<std::int32_t>(index);
        }
    }
    return true;
}

} // namespace wgnx::sysmodule::runtime
