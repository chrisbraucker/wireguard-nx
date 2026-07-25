#include "wireguard/peer.hpp"

#include "logger.hpp"

#include <cstdio>
#include <cstring>
#include <memory>

namespace wgnx::wireguard {

bool wg_peer_initialize(wg_peer* peer, const PeerInitializationView& config) {
    if (peer == nullptr) {
        return false;
    }

    std::destroy_at(peer);
    std::construct_at(peer);
    std::snprintf(peer->name, sizeof(peer->name), "%s", config.name != nullptr ? config.name : "");
    peer->persistent_keepalive_interval = config.persistent_keepalive_interval;
    peer->has_preshared_key = config.preshared_key != nullptr && config.preshared_key->valid;
    noise_static_identity_reset(&peer->static_identity);
    noise_handshake_material_reset(&peer->handshake_material);
    noise_cookie_reset(&peer->cookie);
    noise_handshake_init(&peer->handshake);
    wg_timers_init(&peer->timers);
    wg_peer_reset_keypairs(peer);
    wg_peer_clear_last_initiation(peer);
    peer->handshake_retry = {};
    if (!noise_static_identity_init_from_keys(&peer->static_identity, config.local_private_key,
                                              config.remote_public_key != nullptr ? config.remote_public_key : "", config.preshared_key)) {
        wgnx::sysmodule::logger::Log("WG peer '%s': invalid static identity or peer keys", peer->name);
        return false;
    }
    if (!noise_precompute_static_static(&peer->handshake_material, &peer->static_identity)) {
        wgnx::sysmodule::logger::Log("WG peer '%s': failed to precompute static-static DH", peer->name);
        noise_static_identity_reset(&peer->static_identity);
        noise_handshake_material_reset(&peer->handshake_material);
        return false;
    }

    return true;
}

void wg_peer_reset_keypairs(wg_peer* peer) {
    if (peer == nullptr) {
        return;
    }

    peer->current_keypair.Reset();
    peer->next_keypair.Reset();
    peer->previous_keypair.Reset();
}

OutboundStagingAction wg_peer_get_outbound_staging_action(const wg_peer& peer, MonotonicTimePoint now) {
    if (peer.staged_outbound_packets.Size() == 0) {
        return OutboundStagingAction::Idle;
    }
    return peer.current_keypair.CanSendAt(now) ? OutboundStagingAction::Send : OutboundStagingAction::InitiateHandshake;
}

std::size_t wg_peer_clear_staged_outbound_packets(wg_peer* peer, QueueDisposition disposition) {
    if (peer == nullptr) {
        return 0;
    }

    const std::size_t count = peer->staged_outbound_packets.Clear(disposition);
    if (count != 0) {
        const QueueStatistics& statistics = peer->staged_outbound_packets.Statistics();
        wgnx::sysmodule::logger::Log(
            "WG staging peer='%s' removed=%zu disposition=%s pushed=%llu popped=%llu sent=%llu send_failed=%llu retry_exhausted=%llu "
            "stale=%llu unavailable=%llu cleared=%llu high_watermark=%zu",
            peer->name, count, GetQueueDispositionName(disposition), static_cast<unsigned long long>(statistics.pushed),
            static_cast<unsigned long long>(statistics.popped), static_cast<unsigned long long>(statistics.sent),
            static_cast<unsigned long long>(statistics.send_failed), static_cast<unsigned long long>(statistics.retry_exhausted),
            static_cast<unsigned long long>(statistics.stale), static_cast<unsigned long long>(statistics.unavailable),
            static_cast<unsigned long long>(statistics.cleared), statistics.high_watermark);
    }
    return count;
}

void wg_peer_clear_last_initiation(wg_peer* peer) {
    if (peer == nullptr) {
        return;
    }

    peer->last_initiation = {};
    peer->has_last_initiation = false;
}

void wg_peer_begin_handshake_retry_sequence(wg_peer* peer) {
    if (peer == nullptr) {
        return;
    }

    peer->handshake_retry.active = true;
    peer->handshake_retry.send_attempts = 1;
    ++peer->handshake_retry.sequence_count;
}

HandshakeRetryTimeoutResult wg_peer_handle_handshake_retry_timeout(wg_peer* peer) {
    if (peer == nullptr || !peer->handshake_retry.active) {
        return {};
    }

    /*
     * wireguard-go permits MaxTimerHandshakes + 2 sends: the initial send,
     * followed by retries numbered 2 through 20. The next expiry gives up.
     */
    constexpr std::uint32_t MaxSendAttempts = MaxTimerHandshakes + 2;
    if (peer->handshake_retry.send_attempts < MaxSendAttempts) {
        ++peer->handshake_retry.send_attempts;
        return {.action = HandshakeRetryTimeoutAction::Retry};
    }

    peer->handshake_retry.active = false;
    ++peer->handshake_retry.exhausted_sequence_count;
    const std::size_t dropped = wg_peer_clear_staged_outbound_packets(peer, QueueDisposition::RetryExhausted);
    wg_peer_clear_last_initiation(peer);
    return {
        .action = HandshakeRetryTimeoutAction::Exhausted,
        .dropped_staged_packets = dropped,
    };
}

void wg_peer_complete_handshake_retry_sequence(wg_peer* peer) {
    if (peer == nullptr) {
        return;
    }

    peer->handshake_retry.active = false;
    peer->handshake_retry.send_attempts = 0;
    wg_peer_clear_last_initiation(peer);
}

void wg_peer_zero_key_material(wg_peer* peer) {
    if (peer == nullptr) {
        return;
    }

    noise_handshake_clear_transcript(peer);
    noise_handshake_init(&peer->handshake);
    wg_peer_complete_handshake_retry_sequence(peer);
    wg_peer_reset_keypairs(peer);
    static_cast<void>(wg_peer_clear_staged_outbound_packets(peer));
}

void wg_peer_scrub_transient_state(wg_peer* peer) {
    if (peer == nullptr) {
        return;
    }

    noise_handshake_clear_transcript(peer);
    noise_cookie_reset(&peer->cookie);
    wg_peer_clear_last_initiation(peer);
    peer->handshake_retry = {};
    wg_peer_reset_keypairs(peer);
    static_cast<void>(wg_peer_clear_staged_outbound_packets(peer));
}

} // namespace wgnx::wireguard
