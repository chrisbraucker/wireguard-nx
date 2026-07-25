#include "runtime/peer/peer_runtime.hpp"

#include "wireguard/messages.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <memory>
#include <utility>

namespace wgnx::sysmodule::runtime {

namespace {

std::int32_t ComputeElapsedSeconds(wgnx::platform::ktime_t timestamp_ns, wgnx::platform::ktime_t now_ns) {
    if (timestamp_ns <= 0 || now_ns < timestamp_ns) {
        return -1;
    }

    const auto elapsed_seconds = (now_ns - timestamp_ns) / wgnx::platform::NSEC_PER_SEC;
    if (elapsed_seconds > static_cast<wgnx::platform::ktime_t>(std::numeric_limits<std::int32_t>::max())) {
        return std::numeric_limits<std::int32_t>::max();
    }
    return static_cast<std::int32_t>(elapsed_seconds);
}

} // namespace
void PeerRuntime::Configure(PeerIndex peer_index, const wgnx::PeerConfigEntry& config, PeerConfigDerivedInfo derived,
                            wgnx::platform::ktime_t now) {
    if (m_binding.Socket() != wgnx::platform::InvalidSocket) {
        std::abort();
    }
    m_binding.ClearEndpoint();
    Deactivate(now);
    m_peer_index = peer_index;
    m_config = config;
    m_derived = std::move(derived);
    ResetLifecycle(wgnx::PeerRuntimeState::Inactive, ActivationGeneration{}, now);
}

wgnx::platform::socket_handle PeerRuntime::ClearConfiguration(wgnx::platform::ktime_t now) {
    const auto socket = m_binding.ReleaseSocket();
    m_binding.ClearEndpoint();
    Deactivate(now);
    m_config = {};
    m_derived = {};
    m_peer_index = {};
    return socket;
}

bool PeerRegistry::Configure(std::span<const wgnx::PeerConfigEntry> configured_peers, std::span<PeerConfigDerivedInfo> derived,
                             std::int32_t auto_start_peer_index, wgnx::platform::ktime_t now) {
    if (configured_peers.size() > m_peers.size() || derived.size() != configured_peers.size() ||
        !IsValidPeerSelection(auto_start_peer_index, static_cast<std::uint32_t>(configured_peers.size()))) {
        return false;
    }

    const auto cleanup_effects = ClearConfiguration(now);
    if (!cleanup_effects.Empty()) {
        // Runtime configuration is only installed before activation. A live
        // replacement must be modelled as an explicit command transition.
        std::abort();
    }

    m_count = static_cast<std::uint32_t>(configured_peers.size());
    for (std::size_t index = 0; index < configured_peers.size(); ++index) {
        m_peers[index].Configure(PeerIndex{static_cast<std::uint32_t>(index)}, configured_peers[index], std::move(derived[index]), now);
    }
    m_auto_start_peer_index = auto_start_peer_index;
    return true;
}

EffectBatch PeerRegistry::ClearConfiguration(wgnx::platform::ktime_t now) {
    EffectBatch effects{};
    for (std::size_t index = 0; index < m_count; ++index) {
        const auto socket = m_peers[index].ClearConfiguration(now);
        if (socket != wgnx::platform::InvalidSocket) {
            effects.Add(CloseUdpSocketEffect{.socket = socket});
        }
    }
    m_count = 0;
    m_active_peer_index = -1;
    m_auto_start_peer_index = -1;
    return effects;
}

bool PeerRegistry::SetActivePeerIndex(std::int32_t peer_index) {
    if (!IsValidSelection(peer_index)) {
        return false;
    }
    m_active_peer_index = peer_index;
    return true;
}

bool PeerRegistry::SetAutoStartPeerIndex(std::int32_t peer_index) {
    if (!IsValidSelection(peer_index)) {
        return false;
    }
    m_auto_start_peer_index = peer_index;
    return true;
}

EffectBatch PeerRegistry::Dispatch(const PeerEvent& event) {
    const PeerIdentity identity = GetPeerIdentity(event);
    if (identity.peer_index.Value() >= m_count) {
        return {};
    }
    return m_peers[identity.peer_index.Value()].Handle(event);
}

const PeerRuntime* PeerRegistry::PeerAt(PeerIndex peer_index) const {
    return peer_index.Value() < m_count ? std::addressof(m_peers[peer_index.Value()]) : nullptr;
}

bool PeerRegistry::HasRuntimeErrors() const {
    for (std::size_t index = 0; index < m_count; ++index) {
        if (m_peers[index].Lifecycle().state == wgnx::PeerRuntimeState::Error) {
            return true;
        }
    }
    return false;
}

std::size_t PeerRegistry::ClearStagedInnerPackets(PeerIndex peer_index) {
    return peer_index.Value() < m_count ? m_peers[peer_index.Value()].ClearStagedInnerPackets() : 0;
}

std::size_t PeerRegistry::ClearAllStagedInnerPackets() {
    std::size_t cleared = 0;
    for (std::size_t index = 0; index < m_count; ++index) {
        cleared += m_peers[index].ClearStagedInnerPackets();
    }
    return cleared;
}

PeerProtocolSnapshot PeerRuntime::ProtocolSnapshot() const {
    const auto* peer = ProtocolPeer();
    return {
        .current_keypair_index = peer != nullptr ? peer->current_keypair.LocalIndex() : 0,
        .previous_keypair_index = peer != nullptr ? peer->previous_keypair.LocalIndex() : 0,
        .instantiated = m_protocol.instantiated,
        .current_keypair_valid = peer != nullptr && peer->current_keypair.IsValid(),
        .next_keypair_valid = peer != nullptr && peer->next_keypair.IsValid(),
        .previous_keypair_valid = peer != nullptr && peer->previous_keypair.IsValid(),
    };
}

bool PeerRuntime::CanSendTransportNow() const {
    const auto* peer = ProtocolPeer();
    return peer != nullptr && peer->current_keypair.CanSendAt(wgnx::wireguard::GetMonotonicTime());
}

bool PeerRuntime::IsTimerCurrent(const wgnx::wireguard::TimerToken& token, const wgnx::wireguard::TimerOwner& owner) const {
    return m_controller.Timers().IsCurrent(token, owner);
}

wgnx::wireguard::TimerOwner PeerRuntime::CurrentTimerOwner(wgnx::wireguard::TimerHook hook) const {
    const auto* peer = ProtocolPeer();
    return {
        .peer_index = m_peer_index.Value(),
        .activation_generation = m_lifecycle.activation_generation.Value(),
        .protocol_sequence =
            hook == wgnx::wireguard::TimerHook::RetransmitHandshake && peer != nullptr ? peer->handshake_retry.sequence_count : 0,
    };
}

void PeerRuntime::ResetLifecycle(wgnx::PeerRuntimeState state, ActivationGeneration activation_generation, wgnx::platform::ktime_t now) {
    m_lifecycle = {};
    m_lifecycle.state = state;
    m_lifecycle.persistent_keepalive_interval = m_config.persistent_keepalive;
    m_lifecycle.activation_generation = activation_generation;
    m_lifecycle.state_changed_ns = now;
}

void PeerRuntime::Deactivate(wgnx::platform::ktime_t now) {
    m_pending_datagram = {};
    m_pending_socket_generation = SocketGeneration{};
    std::ranges::fill(m_decrypted_packet.bytes, 0);
    m_decrypted_packet.size = 0;
    m_decrypted_packet.generation = PacketGeneration{};
    m_controller.Timers().CancelAll();
    m_path_request_generation = PathRequestGeneration{};
    m_path_availability = wgnx::platform::network_path_availability::unknown;
    m_last_path_observation = {};
    m_has_path_observation = false;
    m_rebind_on_path_confirmation = false;
    m_waiting_for_local_path = false;
    m_endpoint_resolution_started = false;
    m_receive_started = false;
    ResetProtocol();
    ResetLifecycle(wgnx::PeerRuntimeState::Inactive, ActivationGeneration{}, now);
}

ActivationGeneration PeerRuntime::BeginActivation(wgnx::platform::ktime_t now) {
    const auto activation_generation = AllocateGeneration(m_next_activation_generation);
    ResetLifecycle(wgnx::PeerRuntimeState::ResolvingEndpoint, activation_generation, now);
    return activation_generation;
}

bool PeerRuntime::EnterHandshaking(ActivationGeneration activation_generation, wgnx::platform::ktime_t now) {
    if (!IsCurrentActivation(activation_generation) || m_lifecycle.state != wgnx::PeerRuntimeState::ResolvingEndpoint) {
        return false;
    }
    m_lifecycle.state = wgnx::PeerRuntimeState::Handshaking;
    m_lifecycle.error_stage = wgnx::PeerErrorStage::None;
    m_lifecycle.last_error_code = static_cast<std::uint32_t>(wgnx::PeerErrorCode::None);
    m_lifecycle.state_ticks = 0;
    m_lifecycle.state_changed_ns = now;
    return true;
}

bool PeerRuntime::EnterActive(ActivationGeneration activation_generation, wgnx::platform::ktime_t now) {
    if (!IsCurrentActivation(activation_generation) || m_lifecycle.state != wgnx::PeerRuntimeState::Handshaking) {
        return false;
    }
    m_lifecycle.state = wgnx::PeerRuntimeState::Active;
    m_lifecycle.error_stage = wgnx::PeerErrorStage::None;
    m_lifecycle.last_error_code = static_cast<std::uint32_t>(wgnx::PeerErrorCode::None);
    m_lifecycle.state_ticks = 0;
    m_lifecycle.established = true;
    m_lifecycle.state_changed_ns = now;
    m_lifecycle.last_handshake_ns = now;
    return true;
}

void PeerRuntime::EnterError(wgnx::PeerErrorStage stage, wgnx::PeerErrorCode code, wgnx::platform::ktime_t now) {
    m_lifecycle.state = wgnx::PeerRuntimeState::Error;
    m_lifecycle.error_stage = stage;
    m_lifecycle.last_error_code = static_cast<std::uint32_t>(code);
    m_lifecycle.state_ticks = 0;
    m_lifecycle.established = false;
    m_lifecycle.state_changed_ns = now;
}

bool PeerRuntime::IsCurrentActivation(ActivationGeneration activation_generation) const {
    return IsCurrentGeneration(m_lifecycle.activation_generation, activation_generation);
}

bool PeerRuntime::IsCurrentPathRequest(ActivationGeneration activation_generation, PathRequestGeneration path_generation) const {
    return IsCurrentActivation(activation_generation) && !path_generation.IsZero() && path_generation == m_path_request_generation;
}

bool PeerRuntime::IsInTransportState() const {
    return m_lifecycle.state == wgnx::PeerRuntimeState::Handshaking || m_lifecycle.state == wgnx::PeerRuntimeState::Active;
}

bool PeerRuntime::AcceptsInnerPacketSubmission() const {
    return m_lifecycle.state == wgnx::PeerRuntimeState::ResolvingEndpoint || IsInTransportState();
}

wgnx::PeerErrorCode PeerRuntime::ValidateConfiguration() const {
    if (m_config.public_key[0] == '\0' || m_config.allowed_ips[0] == '\0') {
        return wgnx::PeerErrorCode::ConfigInvalid;
    }
    if (!m_derived.secrets_valid || !wgnx::wireguard::noise_is_valid_encoded_key(m_config.public_key.data())) {
        return wgnx::PeerErrorCode::KeyInvalid;
    }
    if (m_config.endpoint[0] == '\0') {
        return wgnx::PeerErrorCode::EndpointMissing;
    }
    return wgnx::PeerErrorCode::None;
}

bool PeerRuntime::InstantiateProtocol() {
    ResetProtocol();
    if (!m_derived.secrets_valid || !wgnx::wireguard::wg_device_init_from_parsed_config(
                                        std::addressof(m_protocol.device), m_config, m_derived.local_private_key,
                                        m_derived.has_preshared_key ? std::addressof(m_derived.preshared_key) : nullptr)) {
        return false;
    }
    m_protocol.instantiated = true;
    return true;
}

void PeerRuntime::ResetProtocol() {
    wgnx::wireguard::wg_device_reset(std::addressof(m_protocol.device));
    m_protocol.instantiated = false;
}

wgnx::wireguard::wg_peer* PeerRuntime::ProtocolPeer() {
    return m_protocol.instantiated ? wgnx::wireguard::wg_device_first_peer(std::addressof(m_protocol.device)) : nullptr;
}

const wgnx::wireguard::wg_peer* PeerRuntime::ProtocolPeer() const {
    return m_protocol.instantiated
               ? wgnx::wireguard::wg_device_first_peer(const_cast<wgnx::wireguard::wg_device*>(std::addressof(m_protocol.device)))
               : nullptr;
}

SocketGeneration PeerRuntime::AllocateSocketGeneration() {
    return AllocateGeneration(m_next_socket_generation);
}

DatagramGeneration PeerRuntime::AllocateDatagramGeneration() {
    return AllocateGeneration(m_next_datagram_generation);
}

PacketGeneration PeerRuntime::AllocateDecryptedPacketGeneration() {
    return AllocateGeneration(m_next_decrypted_packet_generation);
}
void PeerRuntime::EnterActivationError(wgnx::PeerErrorStage stage, wgnx::PeerErrorCode code, wgnx::platform::ktime_t now,
                                       EffectBatch* effects) {
    m_pending_datagram = {};
    m_pending_socket_generation = SocketGeneration{};
    std::ranges::fill(m_decrypted_packet.bytes, 0);
    m_decrypted_packet.size = 0;
    m_decrypted_packet.generation = PacketGeneration{};
    ClearStagedInnerPackets();
    if (auto* peer = ProtocolPeer()) {
        wgnx::wireguard::wg_peer_scrub_transient_state(peer);
        wgnx::wireguard::wg_device_clear_index_registry(std::addressof(m_protocol.device));
    }
    EnterError(stage, code, now);
    if (effects == nullptr) {
        return;
    }
    const PeerIdentity identity{
        .peer_index = m_peer_index,
        .activation_generation = m_lifecycle.activation_generation,
    };
    if (m_binding.IsOpen()) {
        effects->Add(CloseUdpSocketEffect{
            .path_generation = m_path_request_generation,
            .socket = m_binding.ReleaseSocket(),
        });
    }
    if (identity.activation_generation.IsZero()) {
        return;
    }
    for (const auto hook : {
             wgnx::wireguard::TimerHook::RetransmitHandshake,
             wgnx::wireguard::TimerHook::SendKeepalive,
             wgnx::wireguard::TimerHook::NewHandshake,
             wgnx::wireguard::TimerHook::ZeroKeyMaterial,
             wgnx::wireguard::TimerHook::PersistentKeepalive,
         }) {
        effects->Add(CancelProtocolTimerEffect{
            .peer = identity,
            .hook = hook,
        });
    }
}

bool PeerRuntime::SnapshotPendingDatagram(ActivationGeneration activation_generation, DatagramGeneration datagram_generation,
                                          PendingDatagramSnapshot& out) const {
    if (!IsCurrentActivation(activation_generation) || !m_pending_datagram.IsPending() ||
        m_pending_datagram.generation != datagram_generation || !m_binding.SnapshotForSend(out.binding)) {
        return false;
    }
    out.size = m_pending_datagram.size;
    out.inner_packet_id = m_pending_datagram.inner_packet_id;
    out.kind = m_pending_datagram.kind;
    std::copy_n(m_pending_datagram.bytes.begin(), out.size, out.bytes.begin());
    return true;
}

bool PeerRuntime::HasPendingDatagram(ActivationGeneration activation_generation, DatagramGeneration datagram_generation) const {
    return IsCurrentActivation(activation_generation) && m_pending_datagram.IsPending() &&
           m_pending_datagram.generation == datagram_generation;
}

bool PeerRuntime::ViewDecryptedPacket(ActivationGeneration activation_generation, PacketGeneration packet_generation,
                                      DecryptedPacketView& out) const {
    if (!IsCurrentActivation(activation_generation) || packet_generation.IsZero() || m_decrypted_packet.generation != packet_generation ||
        m_decrypted_packet.size == 0) {
        return false;
    }
    out = {
        .packet = std::span<const std::uint8_t>(m_decrypted_packet.bytes.data(), m_decrypted_packet.size),
        .generation = m_decrypted_packet.generation,
    };
    return true;
}
void PeerRuntime::RecordReceivedBytes(std::size_t byte_count, wgnx::platform::ktime_t now) {
    m_lifecycle.rx_bytes += byte_count;
    m_lifecycle.last_rx_ns = now;
}

void PeerRuntime::RecordTransmittedBytes(std::size_t byte_count, wgnx::platform::ktime_t now) {
    m_lifecycle.tx_bytes += byte_count;
    m_lifecycle.last_tx_ns = now;
}

wgnx::PeerInfo PeerRuntime::BuildInfo(wgnx::platform::ktime_t now, bool is_active, bool is_auto_start) const {
    wgnx::PeerInfo peer{};
    std::snprintf(peer.name, sizeof(peer.name), "%s", m_config.name.data());
    std::snprintf(peer.address, sizeof(peer.address), "%s", m_config.address.data());
    std::snprintf(peer.endpoint, sizeof(peer.endpoint), "%s", m_config.endpoint.data());
    std::snprintf(peer.resolved_endpoint, sizeof(peer.resolved_endpoint), "%s", m_binding.EndpointText());
    std::snprintf(peer.derived_public_key, sizeof(peer.derived_public_key), "%s",
                  m_derived.has_derived_public_key ? m_derived.derived_public_key : "");
    peer.last_handshake_seconds = ComputeElapsedSeconds(m_lifecycle.last_handshake_ns, now);
    peer.last_rx_seconds = ComputeElapsedSeconds(m_lifecycle.last_rx_ns, now);
    peer.last_tx_seconds = ComputeElapsedSeconds(m_lifecycle.last_tx_ns, now);
    peer.last_debug_probe_seconds = -1;
    peer.last_error_code = m_lifecycle.last_error_code;
    peer.persistent_keepalive_interval = m_lifecycle.persistent_keepalive_interval;
    peer.runtime_state = static_cast<std::uint8_t>(m_lifecycle.state);
    peer.error_stage = static_cast<std::uint8_t>(m_lifecycle.error_stage);
    peer.resolved_family = static_cast<std::uint8_t>(m_binding.Endpoint().family);
    peer.rx_bytes = m_lifecycle.rx_bytes;
    peer.tx_bytes = m_lifecycle.tx_bytes;
    peer.flags = BuildPeerFlags(is_active, is_auto_start, m_lifecycle.established, m_lifecycle.state, m_binding.HasEndpoint());
    return peer;
}

} // namespace wgnx::sysmodule::runtime
