#include "runtime/peer_runtime.hpp"

#include "wireguard/debug_probe.hpp"
#include "wireguard/handshake.hpp"
#include "wireguard/messages.hpp"

#include "logger.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <type_traits>

namespace wgnx::sysmodule::runtime {

namespace {

const char *GetIndexSlotName(wgnx::wireguard::wg_index_slot slot) {
    switch (slot) {
        case wgnx::wireguard::wg_index_slot::None: return "none";
        case wgnx::wireguard::wg_index_slot::Handshake: return "handshake";
        case wgnx::wireguard::wg_index_slot::CurrentKeypair: return "current";
        case wgnx::wireguard::wg_index_slot::NextKeypair: return "next";
        case wgnx::wireguard::wg_index_slot::PreviousKeypair: return "previous";
    }
    return "unknown";
}

std::int32_t ComputeElapsedSeconds(
    wgnx::platform::ktime_t timestamp_ns,
    wgnx::platform::ktime_t now_ns) {
    if (timestamp_ns <= 0 || now_ns < timestamp_ns) {
        return -1;
    }

    const auto elapsed_seconds =
        (now_ns - timestamp_ns) / wgnx::platform::NSEC_PER_SEC;
    if (elapsed_seconds > static_cast<wgnx::platform::ktime_t>(
                              std::numeric_limits<std::int32_t>::max())) {
        return std::numeric_limits<std::int32_t>::max();
    }
    return static_cast<std::int32_t>(elapsed_seconds);
}

} // namespace

void PeerRuntime::ResetLifecycle(
    wgnx::PeerRuntimeState state,
    std::uint32_t activation_generation,
    wgnx::platform::ktime_t now) {
    m_lifecycle = {};
    m_lifecycle.state = state;
    m_lifecycle.persistent_keepalive_interval = config.persistent_keepalive;
    m_lifecycle.activation_generation = activation_generation;
    m_lifecycle.state_changed_ns = now;
}

void PeerRuntime::Deactivate(wgnx::platform::ktime_t now) {
    m_pending_datagram = {};
    std::ranges::fill(m_decrypted_packet.bytes, 0);
    m_decrypted_packet.size = 0;
    m_decrypted_packet.generation = 0;
    controller.Timers().CancelAll();
    ResetProtocol();
    ResetLifecycle(wgnx::PeerRuntimeState::Inactive, 0, now);
}

std::uint32_t PeerRuntime::BeginActivation(wgnx::platform::ktime_t now) {
    const std::uint32_t activation_generation = m_next_activation_generation++;
    if (m_next_activation_generation == 0) {
        m_next_activation_generation = 1;
    }
    ResetLifecycle(
        wgnx::PeerRuntimeState::ResolvingEndpoint,
        activation_generation,
        now);
    return activation_generation;
}

bool PeerRuntime::EnterHandshaking(
    std::uint32_t activation_generation,
    wgnx::platform::ktime_t now) {
    if (!IsCurrentActivation(activation_generation) ||
        m_lifecycle.state != wgnx::PeerRuntimeState::ResolvingEndpoint) {
        return false;
    }
    m_lifecycle.state = wgnx::PeerRuntimeState::Handshaking;
    m_lifecycle.error_stage = wgnx::PeerErrorStage::None;
    m_lifecycle.last_error_code = static_cast<std::uint32_t>(wgnx::PeerErrorCode::None);
    m_lifecycle.state_ticks = 0;
    m_lifecycle.state_changed_ns = now;
    return true;
}

bool PeerRuntime::EnterActive(
    std::uint32_t activation_generation,
    wgnx::platform::ktime_t now) {
    if (!IsCurrentActivation(activation_generation) ||
        m_lifecycle.state != wgnx::PeerRuntimeState::Handshaking) {
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

void PeerRuntime::EnterError(
    wgnx::PeerErrorStage stage,
    wgnx::PeerErrorCode code,
    wgnx::platform::ktime_t now) {
    m_lifecycle.state = wgnx::PeerRuntimeState::Error;
    m_lifecycle.error_stage = stage;
    m_lifecycle.last_error_code = static_cast<std::uint32_t>(code);
    m_lifecycle.state_ticks = 0;
    m_lifecycle.established = false;
    ClearDebugProbeState();
    m_lifecycle.state_changed_ns = now;
}

bool PeerRuntime::IsCurrentActivation(std::uint32_t activation_generation) const {
    return IsCurrentGeneration(m_lifecycle.activation_generation, activation_generation);
}

bool PeerRuntime::IsInTransportState() const {
    return m_lifecycle.state == wgnx::PeerRuntimeState::Handshaking ||
           m_lifecycle.state == wgnx::PeerRuntimeState::Active;
}

bool PeerRuntime::AcceptsInnerPacketSubmission() const {
    return m_lifecycle.state == wgnx::PeerRuntimeState::ResolvingEndpoint ||
           IsInTransportState();
}

wgnx::PeerErrorCode PeerRuntime::ValidateConfiguration() const {
    if (config.public_key[0] == '\0' || config.allowed_ips[0] == '\0') {
        return wgnx::PeerErrorCode::ConfigInvalid;
    }
    if (!derived.secrets_valid ||
        !wgnx::wireguard::noise_is_valid_encoded_key(config.public_key.data())) {
        return wgnx::PeerErrorCode::KeyInvalid;
    }
    if (config.endpoint[0] == '\0') {
        return wgnx::PeerErrorCode::EndpointMissing;
    }
    return wgnx::PeerErrorCode::None;
}

bool PeerRuntime::InstantiateProtocol() {
    ResetProtocol();
    if (!derived.secrets_valid ||
        !wgnx::wireguard::wg_device_init_from_parsed_config(
            std::addressof(protocol.device),
            config,
            derived.local_private_key,
            derived.has_preshared_key ? std::addressof(derived.preshared_key) : nullptr)) {
        return false;
    }
    protocol.instantiated = true;
    return true;
}

void PeerRuntime::ResetProtocol() {
    wgnx::wireguard::wg_device_reset(std::addressof(protocol.device));
    protocol.instantiated = false;
}

wgnx::wireguard::wg_peer *PeerRuntime::ProtocolPeer() {
    return protocol.instantiated
        ? wgnx::wireguard::wg_device_first_peer(std::addressof(protocol.device))
        : nullptr;
}

const wgnx::wireguard::wg_peer *PeerRuntime::ProtocolPeer() const {
    return protocol.instantiated
        ? wgnx::wireguard::wg_device_first_peer(
              const_cast<wgnx::wireguard::wg_device *>(std::addressof(protocol.device)))
        : nullptr;
}

std::uint32_t PeerRuntime::AllocateSocketGeneration() {
    const std::uint32_t generation = m_next_socket_generation++;
    if (m_next_socket_generation == 0) {
        m_next_socket_generation = 1;
    }
    return generation;
}

std::uint32_t PeerRuntime::AllocateDatagramGeneration() {
    const std::uint32_t generation = m_next_datagram_generation++;
    if (m_next_datagram_generation == 0) {
        m_next_datagram_generation = 1;
    }
    return generation;
}

std::uint32_t PeerRuntime::AllocateDecryptedPacketGeneration() {
    const std::uint32_t generation = m_next_decrypted_packet_generation++;
    if (m_next_decrypted_packet_generation == 0) {
        m_next_decrypted_packet_generation = 1;
    }
    return generation;
}

bool PeerRuntime::PrepareHandshakeInitiation(PendingDatagramKind kind) {
    auto *peer = ProtocolPeer();
    if (peer == nullptr || !peer->has_last_initiation || m_pending_datagram.IsPending()) {
        return false;
    }

    PendingDatagram pending{};
    if (wgnx::wireguard::SerializeHandshakeInitiation(
            std::span<std::uint8_t>(pending.bytes).first(
                wgnx::wireguard::HandshakeInitiationSize),
            peer->last_initiation) != wgnx::wireguard::ParseError::None) {
        return false;
    }
    pending.size = wgnx::wireguard::HandshakeInitiationSize;
    pending.generation = AllocateDatagramGeneration();
    pending.kind = kind;
    m_pending_datagram = pending;
    return true;
}

bool PeerRuntime::PrepareHandshakeResponse() {
    auto *peer = ProtocolPeer();
    if (peer == nullptr || m_pending_datagram.IsPending()) {
        return false;
    }

    wgnx::wireguard::message_handshake_response response{};
    PendingDatagram pending{};
    if (!wgnx::wireguard::noise_handshake_create_response(
            std::addressof(response),
            peer) ||
        wgnx::wireguard::SerializeHandshakeResponse(
            std::span<std::uint8_t>(pending.bytes).first(
                wgnx::wireguard::HandshakeResponseSize),
            response) != wgnx::wireguard::ParseError::None ||
        !controller.DeriveResponderSession(protocol.device, *peer)) {
        return false;
    }

    pending.size = wgnx::wireguard::HandshakeResponseSize;
    pending.generation = AllocateDatagramGeneration();
    pending.kind = PendingDatagramKind::HandshakeResponse;
    m_pending_datagram = pending;
    return true;
}

bool PeerRuntime::PrepareTransportDatagram(
    std::span<const std::uint8_t> payload,
    PendingDatagramKind kind,
    std::uint64_t inner_packet_id,
    wgnx::wireguard::TransportDataError &out_error) {
    auto *peer = ProtocolPeer();
    if (peer == nullptr || m_pending_datagram.IsPending()) {
        out_error = wgnx::wireguard::TransportDataError::InvalidKeypair;
        return false;
    }

    PendingDatagram pending{};
    const auto result = wgnx::wireguard::noise_create_transport_data_packet(
        pending.bytes,
        peer->current_keypair,
        payload);
    out_error = result.error;
    if (result.error != wgnx::wireguard::TransportDataError::None) {
        return false;
    }
    pending.size = result.packet_size;
    pending.generation = AllocateDatagramGeneration();
    pending.inner_packet_id = inner_packet_id;
    pending.kind = kind;
    m_pending_datagram = pending;
    return true;
}

bool PeerRuntime::StartHandshake(
    const PeerIdentity &identity,
    wgnx::wireguard::TimerDeadline retry_deadline,
    EffectBatch &effects,
    bool retry) {
    auto *peer = ProtocolPeer();
    if (peer == nullptr || m_pending_datagram.IsPending()) {
        return false;
    }
    const auto transition = retry
        ? controller.HandleHandshakeRetryTimer(protocol.device, *peer)
        : controller.StartHandshake(protocol.device, *peer);
    if (transition.action == wgnx::wireguard::HandshakeTransitionAction::Ignore) {
        return true;
    }
    if (transition.action != wgnx::wireguard::HandshakeTransitionAction::SendInitiation ||
        !PrepareHandshakeInitiation(PendingDatagramKind::HandshakeInitiation)) {
        return false;
    }
    static_cast<void>(effects.Push(ArmProtocolTimerEffect{
        .peer = identity,
        .hook = wgnx::wireguard::TimerHook::RetransmitHandshake,
        .deadline = retry_deadline,
    }));
    static_cast<void>(effects.Push(SendPendingDatagramEffect{
        .peer = identity,
        .datagram_generation = m_pending_datagram.generation,
    }));
    return true;
}

bool PeerRuntime::CanStageInnerPacket() const {
    const auto *peer = ProtocolPeer();
    return peer != nullptr &&
           peer->staged_outbound_packets.Size() <
               peer->staged_outbound_packets.CapacityValue();
}

std::size_t PeerRuntime::ClearStagedInnerPackets() {
    auto *peer = ProtocolPeer();
    return peer != nullptr
        ? wgnx::wireguard::wg_peer_clear_staged_outbound_packets(peer)
        : 0;
}

std::size_t PeerRuntime::StagedInnerPacketCount() const {
    const auto *peer = ProtocolPeer();
    return peer != nullptr ? peer->staged_outbound_packets.Size() : 0;
}

void PeerRuntime::ProcessOutboundQueue(
    const PeerIdentity &identity,
    wgnx::wireguard::TimerDeadline retry_deadline,
    wgnx::platform::ktime_t now,
    EffectBatch &effects) {
    auto *peer = ProtocolPeer();
    if (peer == nullptr || m_pending_datagram.IsPending()) {
        return;
    }

    while (const auto *front = peer->staged_outbound_packets.Front()) {
        if (front->peer_index != identity.peer_index ||
            front->activation_generation != identity.activation_generation) {
            static_cast<void>(peer->staged_outbound_packets.Pop(
                nullptr,
                wgnx::wireguard::QueueDisposition::Stale));
            continue;
        }
        if (m_lifecycle.state == wgnx::PeerRuntimeState::ResolvingEndpoint) {
            return;
        }
        if (!IsInTransportState()) {
            static_cast<void>(peer->staged_outbound_packets.Pop(
                nullptr,
                wgnx::wireguard::QueueDisposition::Unavailable));
            continue;
        }

        const auto action = wgnx::wireguard::wg_peer_get_outbound_staging_action(
            *peer,
            wgnx::wireguard::GetMonotonicTime());
        if (action == wgnx::wireguard::OutboundStagingAction::InitiateHandshake) {
            if (!StartHandshake(identity, retry_deadline, effects, false)) {
                EnterActivationError(
                    wgnx::PeerErrorStage::Handshake,
                    wgnx::PeerErrorCode::HandshakeInitFailed,
                    now,
                    &effects);
            }
            return;
        }
        if (action != wgnx::wireguard::OutboundStagingAction::Send) {
            return;
        }

        wgnx::wireguard::TransportDataError build_error{};
        if (PrepareTransportDatagram(
                std::span<const std::uint8_t>(front->bytes.data(), front->size),
                PendingDatagramKind::TransportData,
                front->packet_id,
                build_error)) {
            static_cast<void>(effects.Push(SendPendingDatagramEffect{
                .peer = identity,
                .datagram_generation = m_pending_datagram.generation,
            }));
            return;
        }

        const auto transition = controller.ApplyStagedSendOutcome(
            *peer,
            wgnx::wireguard::OutboundSendOutcome::BuildFailed(build_error));
        if (transition.action == wgnx::wireguard::StagedPacketAction::InitiateHandshake) {
            if (!StartHandshake(identity, retry_deadline, effects, false)) {
                EnterActivationError(
                    wgnx::PeerErrorStage::Handshake,
                    wgnx::PeerErrorCode::HandshakeInitFailed,
                    now,
                    &effects);
            }
            return;
        }
        if (transition.action == wgnx::wireguard::StagedPacketAction::StopOnTerminalFailure) {
            EnterActivationError(
                wgnx::PeerErrorStage::Internal,
                wgnx::PeerErrorCode::InternalFailure,
                now,
                &effects);
            return;
        }
    }
}

void PeerRuntime::HandlePendingDatagramCompletion(
    const PendingDatagramSentEvent &event,
    EffectBatch &effects) {
    if (!IsCurrentActivation(event.peer.activation_generation) ||
        !m_pending_datagram.IsPending() ||
        m_pending_datagram.generation != event.datagram_generation) {
        return;
    }

    const PendingDatagramKind kind = m_pending_datagram.kind;
    m_pending_datagram = {};
    auto *peer = ProtocolPeer();
    if (event.error == wgnx::platform::socket_error::none) {
        RecordTransmittedBytes(event.bytes_sent, event.occurred_at);
        if (kind == PendingDatagramKind::TransportData && peer != nullptr) {
            static_cast<void>(controller.ApplyStagedSendOutcome(
                *peer,
                wgnx::wireguard::OutboundSendOutcome::Sent()));
            static_cast<void>(effects.Push(QueueInnerPacketSubmissionEffect{
                .peer = event.peer,
            }));
        }
        return;
    }

    if (kind == PendingDatagramKind::TransportData && peer != nullptr) {
        static_cast<void>(controller.ApplyStagedSendOutcome(
            *peer,
            wgnx::wireguard::OutboundSendOutcome::TransportDropped()));
    }
    if (event.error == wgnx::platform::socket_error::send_failed) {
        static_cast<void>(effects.Push(SuspendUdpTransportEffect{.peer = event.peer}));
        return;
    }
    EnterActivationError(
        wgnx::PeerErrorStage::Transport,
        wgnx::PeerErrorCode::TransportSendFailed,
        event.occurred_at,
        &effects);
}

void PeerRuntime::EnterActivationError(
    wgnx::PeerErrorStage stage,
    wgnx::PeerErrorCode code,
    wgnx::platform::ktime_t now,
    EffectBatch *effects) {
    m_pending_datagram = {};
    std::ranges::fill(m_decrypted_packet.bytes, 0);
    m_decrypted_packet.size = 0;
    m_decrypted_packet.generation = 0;
    ClearStagedInnerPackets();
    if (auto *peer = ProtocolPeer()) {
        wgnx::wireguard::wg_peer_scrub_transient_state(peer);
        wgnx::wireguard::wg_device_clear_index_registry(
            std::addressof(protocol.device));
    }
    EnterError(stage, code, now);
    if (effects == nullptr) {
        return;
    }
    const PeerIdentity identity{
        .peer_index = m_peer_index,
        .activation_generation = m_lifecycle.activation_generation,
    };
    if (binding.IsOpen()) {
        static_cast<void>(effects->Push(CloseUdpSocketEffect{
            .socket = binding.ReleaseSocket(),
        }));
    }
    if (identity.activation_generation == 0) {
        return;
    }
    for (const auto hook : {
             wgnx::wireguard::TimerHook::RetransmitHandshake,
             wgnx::wireguard::TimerHook::SendKeepalive,
             wgnx::wireguard::TimerHook::Rekey,
             wgnx::wireguard::TimerHook::ZeroKeyMaterial,
         }) {
        static_cast<void>(effects->Push(CancelProtocolTimerEffect{
            .peer = identity,
            .hook = hook,
        }));
    }
}

void PeerRuntime::FinalizeTimerEffects(EffectBatch &effects) {
    for (auto &effect : effects) {
        std::visit(
            [this](auto &value) {
                using Effect = std::remove_cvref_t<decltype(value)>;
                if constexpr (std::is_same_v<Effect, ArmProtocolTimerEffect>) {
                    if (!IsCurrentActivation(value.peer.activation_generation) ||
                        value.peer.peer_index != m_peer_index) {
                        return;
                    }
                    auto *peer = ProtocolPeer();
                    if (peer == nullptr) {
                        return;
                    }
                    wgnx::wireguard::wg_timers_cancel(
                        std::addressof(peer->timers),
                        value.hook,
                        peer->name);
                    wgnx::wireguard::wg_timers_schedule(
                        std::addressof(peer->timers),
                        value.hook,
                        value.deadline,
                        peer->name);
                    value.token = controller.Timers().Arm(
                        value.hook,
                        {
                            .peer_index = value.peer.peer_index,
                            .activation_generation = value.peer.activation_generation,
                            .protocol_sequence =
                                value.hook ==
                                        wgnx::wireguard::TimerHook::RetransmitHandshake
                                    ? peer->handshake_retry.sequence_count
                                    : 0,
                        });
                } else if constexpr (
                    std::is_same_v<Effect, CancelProtocolTimerEffect>) {
                    if (!IsCurrentActivation(value.peer.activation_generation) ||
                        value.peer.peer_index != m_peer_index) {
                        return;
                    }
                    if (auto *peer = ProtocolPeer()) {
                        wgnx::wireguard::wg_timers_cancel(
                            std::addressof(peer->timers),
                            value.hook,
                            peer->name);
                    }
                    value.token = controller.Timers().Cancel(value.hook);
                }
            },
            effect);
    }
}

bool PeerRuntime::SnapshotPendingDatagram(
    std::uint32_t activation_generation,
    std::uint32_t datagram_generation,
    PendingDatagramSnapshot &out) const {
    if (!IsCurrentActivation(activation_generation) ||
        !m_pending_datagram.IsPending() ||
        m_pending_datagram.generation != datagram_generation ||
        !binding.SnapshotForSend(out.binding)) {
        return false;
    }
    out.size = m_pending_datagram.size;
    out.inner_packet_id = m_pending_datagram.inner_packet_id;
    out.kind = m_pending_datagram.kind;
    std::copy_n(m_pending_datagram.bytes.begin(), out.size, out.bytes.begin());
    return true;
}

bool PeerRuntime::ViewDecryptedPacket(
    std::uint32_t activation_generation,
    std::uint32_t packet_generation,
    DecryptedPacketView &out) const {
    if (!IsCurrentActivation(activation_generation) ||
        packet_generation == 0 ||
        m_decrypted_packet.generation != packet_generation ||
        m_decrypted_packet.size == 0) {
        return false;
    }
    out = {
        .packet = std::span<const std::uint8_t>(
            m_decrypted_packet.bytes.data(),
            m_decrypted_packet.size),
        .generation = m_decrypted_packet.generation,
    };
    return true;
}

void PeerRuntime::UpdateEndpointFromAuthenticatedPacket(
    const EncryptedDatagramReceivedEvent &event) {
    if (event.source.family == wgnx::platform::address_family::unspecified) {
        return;
    }
    binding.SetEndpoint(event.source, event.source_text.data());
}

void PeerRuntime::CompleteInitiatorSession(
    const EncryptedDatagramReceivedEvent &event,
    EffectBatch &effects) {
    auto *peer = ProtocolPeer();
    if (peer == nullptr || !controller.CompleteSession(protocol.device, *peer)) {
        logger::Log(
            "Rejected WG handshake response peer=%u activation=%u reason=session_derivation_failed",
            event.peer.peer_index,
            event.peer.activation_generation);
        return;
    }

    UpdateEndpointFromAuthenticatedPacket(event);
    RecordReceivedBytes(event.packet.size(), event.occurred_at);
    if (m_lifecycle.state == wgnx::PeerRuntimeState::Handshaking) {
        if (!EnterActive(event.peer.activation_generation, event.occurred_at)) {
            return;
        }
    } else {
        m_lifecycle.last_handshake_ns = event.occurred_at;
        m_lifecycle.established = true;
    }

    wgnx::wireguard::TransportDataError build_error{};
    if (!PrepareTransportDatagram(
            {},
            PendingDatagramKind::Keepalive,
            0,
            build_error)) {
        EnterActivationError(
            wgnx::PeerErrorStage::Internal,
            wgnx::PeerErrorCode::InternalFailure,
            event.occurred_at,
            &effects);
        return;
    }

    static_cast<void>(effects.Push(CancelProtocolTimerEffect{
        .peer = event.peer,
        .hook = wgnx::wireguard::TimerHook::RetransmitHandshake,
    }));
    if (peer->persistent_keepalive_interval > 0) {
        static_cast<void>(effects.Push(ArmProtocolTimerEffect{
            .peer = event.peer,
            .hook = wgnx::wireguard::TimerHook::SendKeepalive,
            .deadline = event.keepalive_deadline,
        }));
    }
    static_cast<void>(effects.Push(ArmProtocolTimerEffect{
        .peer = event.peer,
        .hook = wgnx::wireguard::TimerHook::Rekey,
        .deadline = event.rekey_deadline,
    }));
    static_cast<void>(effects.Push(ArmProtocolTimerEffect{
        .peer = event.peer,
        .hook = wgnx::wireguard::TimerHook::ZeroKeyMaterial,
        .deadline = event.zero_key_material_deadline,
    }));
    static_cast<void>(effects.Push(SendPendingDatagramEffect{
        .peer = event.peer,
        .datagram_generation = m_pending_datagram.generation,
    }));
    static_cast<void>(effects.Push(QueueInnerPacketSubmissionEffect{.peer = event.peer}));
}

void PeerRuntime::HandleTransportData(
    const EncryptedDatagramReceivedEvent &event,
    EffectBatch &effects) {
    auto *peer = ProtocolPeer();
    if (peer == nullptr) {
        return;
    }

    wgnx::wireguard::IncomingTransportDataResult result{};
    m_decrypted_packet.size = 0;
    m_decrypted_packet.generation = 0;
    const auto error = wgnx::wireguard::noise_consume_incoming_transport_data_packet(
        event.packet,
        protocol.device,
        *peer,
        m_decrypted_packet.bytes,
        result);
    if (error != wgnx::wireguard::TransportDataError::None) {
        logger::Log(
            "Rejected WG transport data peer=%u activation=%u bytes=%zu source=%s slot=%s err=%s",
            event.peer.peer_index,
            event.peer.activation_generation,
            event.packet.size(),
            event.source_text.data(),
            GetIndexSlotName(result.slot),
            wgnx::wireguard::GetTransportDataErrorName(error));
        return;
    }

    UpdateEndpointFromAuthenticatedPacket(event);
    RecordReceivedBytes(event.packet.size(), event.occurred_at);
    logger::Log(
        "Accepted WG transport data peer=%u activation=%u bytes=%zu payload=%zu source=%s slot=%s counter=%llu promoted=%u",
        event.peer.peer_index,
        event.peer.activation_generation,
        event.packet.size(),
        result.decrypt.payload_size,
        event.source_text.data(),
        GetIndexSlotName(result.slot),
        static_cast<unsigned long long>(result.decrypt.header.counter),
        result.promoted_next_keypair ? 1U : 0U);

    if (result.promoted_next_keypair) {
        controller.ConfirmResponderSession(*peer);
        if (m_lifecycle.state == wgnx::PeerRuntimeState::Handshaking) {
            static_cast<void>(EnterActive(
                event.peer.activation_generation,
                event.occurred_at));
        } else {
            m_lifecycle.last_handshake_ns = event.occurred_at;
            m_lifecycle.established = true;
        }
        static_cast<void>(effects.Push(CancelProtocolTimerEffect{
            .peer = event.peer,
            .hook = wgnx::wireguard::TimerHook::RetransmitHandshake,
        }));
        static_cast<void>(effects.Push(ArmProtocolTimerEffect{
            .peer = event.peer,
            .hook = wgnx::wireguard::TimerHook::Rekey,
            .deadline = event.rekey_deadline,
        }));
        static_cast<void>(effects.Push(ArmProtocolTimerEffect{
            .peer = event.peer,
            .hook = wgnx::wireguard::TimerHook::ZeroKeyMaterial,
            .deadline = event.zero_key_material_deadline,
        }));
        static_cast<void>(effects.Push(QueueInnerPacketSubmissionEffect{.peer = event.peer}));
    }
    if (peer->persistent_keepalive_interval > 0) {
        static_cast<void>(effects.Push(ArmProtocolTimerEffect{
            .peer = event.peer,
            .hook = wgnx::wireguard::TimerHook::SendKeepalive,
            .deadline = event.keepalive_deadline,
        }));
    }

    if (result.decrypt.payload_size == 0) {
        logger::Log(
            "Accepted WG keepalive payload peer=%u activation=%u",
            event.peer.peer_index,
            event.peer.activation_generation);
        return;
    }

    const auto padded_payload = std::span<const std::uint8_t>(
        m_decrypted_packet.bytes.data(),
        result.decrypt.payload_size);
    std::size_t inner_packet_size = 0;
    const auto validation = wgnx::wireguard::ValidatePaddedInnerIpPacket(
        padded_payload,
        std::addressof(inner_packet_size));
    if (validation != wgnx::wireguard::InnerIpValidationError::None) {
        logger::Log(
            "Dropped decrypted inner packet peer=%u activation=%u bytes=%zu validation=%s",
            event.peer.peer_index,
            event.peer.activation_generation,
            padded_payload.size(),
            wgnx::wireguard::GetInnerIpValidationErrorName(validation));
        return;
    }

    m_decrypted_packet.size = inner_packet_size;
    m_decrypted_packet.generation = AllocateDecryptedPacketGeneration();
    static_cast<void>(effects.Push(PublishDecryptedPacketEffect{
        .peer = event.peer,
        .packet_generation = m_decrypted_packet.generation,
    }));
}

void PeerRuntime::HandleEncryptedDatagram(
    const EncryptedDatagramReceivedEvent &event,
    EffectBatch &effects) {
    auto *peer = ProtocolPeer();
    if (!IsCurrentActivation(event.peer.activation_generation) ||
        !IsInTransportState() || peer == nullptr || event.packet.empty()) {
        return;
    }

    const auto type = wgnx::wireguard::InspectMessageType(event.packet);
    if (!type.success) {
        logger::Log(
            "Rejected WG datagram peer=%u activation=%u bytes=%zu source=%s inspect_err=%s",
            event.peer.peer_index,
            event.peer.activation_generation,
            event.packet.size(),
            event.source_text.data(),
            wgnx::wireguard::GetParseErrorName(type.error));
        return;
    }
    if (type.type == wgnx::wireguard::MessageType::TransportData) {
        HandleTransportData(event, effects);
        return;
    }
    if (m_pending_datagram.IsPending()) {
        logger::Log(
            "Dropped WG handshake datagram peer=%u activation=%u type=%s reason=send_pending",
            event.peer.peer_index,
            event.peer.activation_generation,
            wgnx::wireguard::GetMessageTypeName(type.type));
        return;
    }

    const auto outcome = wgnx::wireguard::noise_handshake_consume_incoming_packet(
        event.packet,
        std::addressof(protocol.device),
        peer);
    logger::Log(
        "Processed WG handshake datagram peer=%u activation=%u bytes=%zu source=%s outcome=%s",
        event.peer.peer_index,
        event.peer.activation_generation,
        event.packet.size(),
        event.source_text.data(),
        wgnx::wireguard::GetHandshakePacketOutcomeName(outcome));
    switch (outcome) {
        case wgnx::wireguard::HandshakePacketOutcome::Invalid:
            return;
        case wgnx::wireguard::HandshakePacketOutcome::CookieReplyConsumed:
            RecordReceivedBytes(event.packet.size(), event.occurred_at);
            return;
        case wgnx::wireguard::HandshakePacketOutcome::ResponseConsumed:
            CompleteInitiatorSession(event, effects);
            return;
        case wgnx::wireguard::HandshakePacketOutcome::InitiationConsumed:
            if (!PrepareHandshakeResponse()) {
                logger::Log(
                    "Failed WG handshake response peer=%u activation=%u reason=response_or_session_build",
                    event.peer.peer_index,
                    event.peer.activation_generation);
                return;
            }
            UpdateEndpointFromAuthenticatedPacket(event);
            RecordReceivedBytes(event.packet.size(), event.occurred_at);
            if (peer->persistent_keepalive_interval > 0) {
                static_cast<void>(effects.Push(ArmProtocolTimerEffect{
                    .peer = event.peer,
                    .hook = wgnx::wireguard::TimerHook::SendKeepalive,
                    .deadline = event.keepalive_deadline,
                }));
            }
            static_cast<void>(effects.Push(ArmProtocolTimerEffect{
                .peer = event.peer,
                .hook = wgnx::wireguard::TimerHook::ZeroKeyMaterial,
                .deadline = event.zero_key_material_deadline,
            }));
            static_cast<void>(effects.Push(SendPendingDatagramEffect{
                .peer = event.peer,
                .datagram_generation = m_pending_datagram.generation,
            }));
            return;
    }
}

void PeerRuntime::RecordReceivedBytes(
    std::size_t byte_count,
    wgnx::platform::ktime_t now) {
    m_lifecycle.rx_bytes += byte_count;
    m_lifecycle.last_rx_ns = now;
}

void PeerRuntime::RecordTransmittedBytes(
    std::size_t byte_count,
    wgnx::platform::ktime_t now) {
    m_lifecycle.tx_bytes += byte_count;
    m_lifecycle.last_tx_ns = now;
}

bool PeerRuntime::SetDebugProbeState(
    wgnx::DebugTriggerAction action,
    wgnx::DebugProbeStatus status,
    wgnx::platform::ktime_t now) {
    const bool valid_transition =
        wgnx::wireguard::CanTransitionDebugProbeStatus(m_lifecycle.debug_probe_status, status);
    m_lifecycle.debug_probe_action = action;
    m_lifecycle.debug_probe_status = status;
    m_lifecycle.debug_probe_state_changed_ns = now;
    return valid_transition;
}

void PeerRuntime::ClearDebugProbeState() {
    m_lifecycle.debug_probe_action = wgnx::DebugTriggerAction::None;
    m_lifecycle.debug_probe_status = wgnx::DebugProbeStatus::None;
    m_lifecycle.debug_probe_state_changed_ns = 0;
}

wgnx::PeerInfo PeerRuntime::BuildInfo(
    wgnx::platform::ktime_t now,
    bool is_active,
    bool is_auto_start) const {
    wgnx::PeerInfo peer{};
    std::snprintf(peer.name, sizeof(peer.name), "%s", config.name.data());
    std::snprintf(peer.address, sizeof(peer.address), "%s", config.address.data());
    std::snprintf(peer.endpoint, sizeof(peer.endpoint), "%s", config.endpoint.data());
    std::snprintf(
        peer.resolved_endpoint,
        sizeof(peer.resolved_endpoint),
        "%s",
        binding.EndpointText());
    std::snprintf(
        peer.derived_public_key,
        sizeof(peer.derived_public_key),
        "%s",
        derived.has_derived_public_key ? derived.derived_public_key : "");
    peer.last_handshake_seconds = ComputeElapsedSeconds(m_lifecycle.last_handshake_ns, now);
    peer.last_rx_seconds = ComputeElapsedSeconds(m_lifecycle.last_rx_ns, now);
    peer.last_tx_seconds = ComputeElapsedSeconds(m_lifecycle.last_tx_ns, now);
    peer.last_debug_probe_seconds =
        ComputeElapsedSeconds(m_lifecycle.debug_probe_state_changed_ns, now);
    peer.last_error_code = m_lifecycle.last_error_code;
    peer.debug_probe_action = static_cast<std::uint32_t>(m_lifecycle.debug_probe_action);
    peer.debug_probe_status = static_cast<std::uint32_t>(m_lifecycle.debug_probe_status);
    peer.persistent_keepalive_interval = m_lifecycle.persistent_keepalive_interval;
    peer.runtime_state = static_cast<std::uint8_t>(m_lifecycle.state);
    peer.error_stage = static_cast<std::uint8_t>(m_lifecycle.error_stage);
    peer.resolved_family = static_cast<std::uint8_t>(binding.Endpoint().family);
    peer.rx_bytes = m_lifecycle.rx_bytes;
    peer.tx_bytes = m_lifecycle.tx_bytes;
    peer.flags = BuildPeerFlags(
        is_active,
        is_auto_start,
        m_lifecycle.established,
        m_lifecycle.state,
        binding.HasEndpoint());
    return peer;
}

EffectBatch PeerRuntime::Handle(const PeerEvent &event) {
    EffectBatch effects = std::visit(
        [this](const auto &value) {
            EffectBatch effects{};
            using Event = std::remove_cvref_t<decltype(value)>;
            if constexpr (std::is_same_v<Event, ActivationRequestedEvent>) {
                const auto config_error = ValidateConfiguration();
                if (config_error != wgnx::PeerErrorCode::None) {
                    EnterActivationError(
                        config_error == wgnx::PeerErrorCode::ConfigInvalid
                            ? wgnx::PeerErrorStage::Config
                            : wgnx::PeerErrorStage::ResolveEndpoint,
                        config_error,
                        value.occurred_at,
                        &effects);
                    return effects;
                }

                binding.ClearEndpoint();
                m_pending_datagram = {};
                std::ranges::fill(m_decrypted_packet.bytes, 0);
                m_decrypted_packet.size = 0;
                m_decrypted_packet.generation = 0;
                ResetProtocol();
                const PeerIdentity identity{
                    .peer_index = value.peer_index,
                    .activation_generation = BeginActivation(value.occurred_at),
                };
                ResolveEndpointEffect resolve{.peer = identity};
                std::snprintf(
                    resolve.endpoint.data(),
                    resolve.endpoint.size(),
                    "%s",
                    config.endpoint.data());
                static_cast<void>(effects.Push(resolve));
            } else if constexpr (std::is_same_v<Event, EndpointResolvedEvent>) {
                if (!IsCurrentActivation(value.peer.activation_generation) ||
                    m_lifecycle.state != wgnx::PeerRuntimeState::ResolvingEndpoint) {
                    return effects;
                }
                if (!value.result.success) {
                    EnterActivationError(
                        value.result.error_stage,
                        value.result.error_code,
                        value.occurred_at,
                        &effects);
                    return effects;
                }
                binding.SetEndpoint(value.result.resolved, value.result.text.data());
                OpenUdpBindEffect open{
                    .peer = value.peer,
                    .endpoint = value.result.resolved,
                    .socket_generation = AllocateSocketGeneration(),
                };
                std::snprintf(
                    open.endpoint_text.data(),
                    open.endpoint_text.size(),
                    "%s",
                    value.result.text.data());
                static_cast<void>(effects.Push(open));
            } else if constexpr (std::is_same_v<Event, UdpBindOpenedEvent>) {
                if (!IsCurrentActivation(value.peer.activation_generation) ||
                    m_lifecycle.state != wgnx::PeerRuntimeState::ResolvingEndpoint) {
                    if (value.socket != wgnx::platform::InvalidSocket) {
                        static_cast<void>(effects.Push(CloseUdpSocketEffect{.socket = value.socket}));
                    }
                    return effects;
                }
                if (value.error != wgnx::platform::socket_error::none ||
                    value.socket == wgnx::platform::InvalidSocket) {
                    if (value.socket != wgnx::platform::InvalidSocket) {
                        static_cast<void>(effects.Push(CloseUdpSocketEffect{.socket = value.socket}));
                    }
                    EnterActivationError(
                        wgnx::PeerErrorStage::Transport,
                        wgnx::PeerErrorCode::TransportOpenFailed,
                        value.occurred_at,
                        &effects);
                    return effects;
                }

                binding.AdoptOpenSocket(
                    value.endpoint,
                    value.endpoint_text.data(),
                    value.socket_generation,
                    value.socket);
                if (!InstantiateProtocol()) {
                    EnterActivationError(
                        wgnx::PeerErrorStage::Config,
                        wgnx::PeerErrorCode::KeyInvalid,
                        value.occurred_at,
                        &effects);
                    return effects;
                }
                if (!EnterHandshaking(value.peer.activation_generation, value.occurred_at)) {
                    static_cast<void>(effects.Push(CloseUdpSocketEffect{
                        .socket = binding.ReleaseSocket(),
                    }));
                    return effects;
                }
                auto *peer = ProtocolPeer();
                const auto transition = peer != nullptr
                    ? controller.StartHandshake(protocol.device, *peer)
                    : wgnx::wireguard::HandshakeTransition{
                          .action = wgnx::wireguard::HandshakeTransitionAction::Fatal};
                if (transition.action != wgnx::wireguard::HandshakeTransitionAction::SendInitiation ||
                    !PrepareHandshakeInitiation(PendingDatagramKind::HandshakeInitiation)) {
                    EnterActivationError(
                        wgnx::PeerErrorStage::Handshake,
                        wgnx::PeerErrorCode::HandshakeInitFailed,
                        value.occurred_at,
                        &effects);
                    return effects;
                }
                static_cast<void>(effects.Push(ArmProtocolTimerEffect{
                    .peer = value.peer,
                    .hook = wgnx::wireguard::TimerHook::RetransmitHandshake,
                    .deadline = value.retry_deadline,
                }));
                static_cast<void>(effects.Push(SendPendingDatagramEffect{
                    .peer = value.peer,
                    .datagram_generation = m_pending_datagram.generation,
                }));
                static_cast<void>(effects.Push(QueueReceiveEffect{.peer = value.peer}));
            } else if constexpr (std::is_same_v<Event, EncryptedDatagramReceivedEvent>) {
                HandleEncryptedDatagram(value, effects);
            } else if constexpr (std::is_same_v<Event, PendingDatagramSentEvent>) {
                HandlePendingDatagramCompletion(value, effects);
            } else if constexpr (std::is_same_v<Event, InnerPacketStagedEvent>) {
                auto *peer = ProtocolPeer();
                if (!IsCurrentActivation(value.peer.activation_generation) ||
                    !AcceptsInnerPacketSubmission() || peer == nullptr ||
                    value.packet.empty() ||
                    value.packet.size() > m_staging_record.bytes.size()) {
                    return effects;
                }
                m_staging_record = {};
                m_staging_record.packet_id = value.packet_id;
                m_staging_record.activation_generation = value.peer.activation_generation;
                m_staging_record.peer_index = value.peer.peer_index;
                m_staging_record.size = static_cast<std::uint16_t>(value.packet.size());
                std::copy(value.packet.begin(), value.packet.end(), m_staging_record.bytes.begin());
                if (peer->staged_outbound_packets.Push(m_staging_record) ==
                        wgnx::wireguard::QueuePushResult::Full) {
                    return effects;
                }
                if (IsInTransportState()) {
                    ProcessOutboundQueue(
                        value.peer,
                        value.retry_deadline,
                        value.occurred_at,
                        effects);
                }
            } else if constexpr (std::is_same_v<Event, ProcessOutboundQueueEvent>) {
                if (IsCurrentActivation(value.peer.activation_generation)) {
                    ProcessOutboundQueue(
                        value.peer,
                        value.retry_deadline,
                        value.occurred_at,
                        effects);
                }
            } else if constexpr (std::is_same_v<Event, ProtocolTimerExpiredEvent>) {
                if (!IsCurrentActivation(value.peer.activation_generation) ||
                    value.token.hook != value.hook ||
                    value.token.owner.peer_index != value.peer.peer_index ||
                    value.token.owner.activation_generation !=
                        value.peer.activation_generation) {
                    return effects;
                }
                auto *peer = ProtocolPeer();
                if (peer == nullptr) {
                    return effects;
                }
                const wgnx::wireguard::TimerOwner current_owner{
                    .peer_index = value.peer.peer_index,
                    .activation_generation = value.peer.activation_generation,
                    .protocol_sequence =
                        value.hook == wgnx::wireguard::TimerHook::RetransmitHandshake
                            ? peer->handshake_retry.sequence_count
                            : 0,
                };
                if (!controller.Timers().IsCurrent(value.token, current_owner)) {
                    logger::Log(
                        "Ignored stale WG timer event hook=%s token_peer=%u current_peer=%u token_activation=%u current_activation=%u token_sequence=%u current_sequence=%u generation=%u",
                        wgnx::wireguard::GetTimerHookName(value.hook),
                        value.token.owner.peer_index,
                        value.peer.peer_index,
                        value.token.owner.activation_generation,
                        value.peer.activation_generation,
                        value.token.owner.protocol_sequence,
                        current_owner.protocol_sequence,
                        value.token.generation);
                    return effects;
                }
                logger::Log(
                    "WG timer peer='%s' fire hook=%s generation=%u",
                    peer->name,
                    wgnx::wireguard::GetTimerHookName(value.hook),
                    value.token.generation);
                if (binding.IsSuspended() &&
                    value.hook != wgnx::wireguard::TimerHook::ZeroKeyMaterial) {
                    static_cast<void>(effects.Push(CancelProtocolTimerEffect{
                        .peer = value.peer,
                        .hook = value.hook,
                    }));
                    logger::Log(
                        "WG timer canceled for suspended UDP transport peer=%u activation=%u hook=%s",
                        value.peer.peer_index,
                        value.peer.activation_generation,
                        wgnx::wireguard::GetTimerHookName(value.hook));
                    return effects;
                }
                if (!IsInTransportState() &&
                    value.hook != wgnx::wireguard::TimerHook::ZeroKeyMaterial) {
                    return effects;
                }
                switch (value.hook) {
                    case wgnx::wireguard::TimerHook::RetransmitHandshake: {
                        static_cast<void>(effects.Push(CancelProtocolTimerEffect{
                            .peer = value.peer,
                            .hook = value.hook,
                        }));
                        const auto transition = controller.HandleHandshakeRetryTimer(
                            protocol.device,
                            *peer);
                        if (transition.action ==
                            wgnx::wireguard::HandshakeTransitionAction::Exhausted) {
                            if (!peer->timers.zero_key_material.pending) {
                                static_cast<void>(effects.Push(ArmProtocolTimerEffect{
                                    .peer = value.peer,
                                    .hook = wgnx::wireguard::TimerHook::ZeroKeyMaterial,
                                    .deadline = value.zero_key_material_deadline,
                                }));
                            }
                            return effects;
                        }
                        if (transition.action ==
                                wgnx::wireguard::HandshakeTransitionAction::SendInitiation &&
                            PrepareHandshakeInitiation(
                                PendingDatagramKind::HandshakeInitiation)) {
                            static_cast<void>(effects.Push(ArmProtocolTimerEffect{
                                .peer = value.peer,
                                .hook = value.hook,
                                .deadline = value.retry_deadline,
                            }));
                            static_cast<void>(effects.Push(SendPendingDatagramEffect{
                                .peer = value.peer,
                                .datagram_generation = m_pending_datagram.generation,
                            }));
                        } else if (transition.action !=
                                   wgnx::wireguard::HandshakeTransitionAction::Ignore) {
                            EnterActivationError(
                                wgnx::PeerErrorStage::Handshake,
                                wgnx::PeerErrorCode::HandshakeInitFailed,
                                value.occurred_at,
                                &effects);
                        }
                        return effects;
                    }
                    case wgnx::wireguard::TimerHook::SendKeepalive: {
                        if (m_lifecycle.state != wgnx::PeerRuntimeState::Active) {
                            return effects;
                        }
                        if (!peer->current_keypair.CanSendAt(
                                wgnx::wireguard::GetMonotonicTime())) {
                            if (!StartHandshake(
                                    value.peer,
                                    value.retry_deadline,
                                    effects,
                                    false)) {
                                EnterActivationError(
                                    wgnx::PeerErrorStage::Handshake,
                                    wgnx::PeerErrorCode::HandshakeInitFailed,
                                    value.occurred_at,
                                    &effects);
                            }
                            return effects;
                        }
                        wgnx::wireguard::TransportDataError build_error{};
                        if (!PrepareTransportDatagram(
                                {},
                                PendingDatagramKind::Keepalive,
                                0,
                                build_error)) {
                            EnterActivationError(
                                wgnx::PeerErrorStage::Internal,
                                wgnx::PeerErrorCode::InternalFailure,
                                value.occurred_at,
                                &effects);
                            return effects;
                        }
                        if (peer->persistent_keepalive_interval > 0) {
                            static_cast<void>(effects.Push(ArmProtocolTimerEffect{
                                .peer = value.peer,
                                .hook = value.hook,
                                .deadline = value.keepalive_deadline,
                            }));
                        }
                        static_cast<void>(effects.Push(SendPendingDatagramEffect{
                            .peer = value.peer,
                            .datagram_generation = m_pending_datagram.generation,
                        }));
                        return effects;
                    }
                    case wgnx::wireguard::TimerHook::Rekey:
                        if (m_lifecycle.state == wgnx::PeerRuntimeState::Active &&
                            !StartHandshake(
                                value.peer,
                                value.retry_deadline,
                                effects,
                                false)) {
                            EnterActivationError(
                                wgnx::PeerErrorStage::Handshake,
                                wgnx::PeerErrorCode::HandshakeInitFailed,
                                value.occurred_at,
                                &effects);
                        }
                        return effects;
                    case wgnx::wireguard::TimerHook::ZeroKeyMaterial:
                        static_cast<void>(effects.Push(CancelProtocolTimerEffect{
                            .peer = value.peer,
                            .hook = value.hook,
                        }));
                        wgnx::wireguard::wg_peer_zero_key_material(peer);
                        wgnx::wireguard::wg_device_clear_index_registry(
                            std::addressof(protocol.device));
                        logger::Log(
                            "WG zeroed stale handshake and keypair material peer=%u activation=%u; peer and UDP binding preserved",
                            value.peer.peer_index,
                            value.peer.activation_generation);
                        return effects;
                }
            } else if constexpr (std::is_same_v<Event, TransportReboundEvent>) {
                if (!IsCurrentActivation(value.peer.activation_generation) ||
                    !IsInTransportState() || !binding.IsOpen()) {
                    return effects;
                }
                auto *peer = ProtocolPeer();
                if (peer == nullptr) {
                    return effects;
                }
                if (m_lifecycle.state == wgnx::PeerRuntimeState::Active &&
                    peer->current_keypair.CanSendAt(
                        wgnx::wireguard::GetMonotonicTime())) {
                    wgnx::wireguard::TransportDataError build_error{};
                    if (!PrepareTransportDatagram(
                            {},
                            PendingDatagramKind::Keepalive,
                            0,
                            build_error)) {
                        EnterActivationError(
                            wgnx::PeerErrorStage::Internal,
                            wgnx::PeerErrorCode::InternalFailure,
                            value.occurred_at,
                            &effects);
                        return effects;
                    }
                    static_cast<void>(effects.Push(SendPendingDatagramEffect{
                        .peer = value.peer,
                        .datagram_generation = m_pending_datagram.generation,
                    }));
                } else if (!StartHandshake(
                               value.peer,
                               value.retry_deadline,
                               effects,
                               false)) {
                    EnterActivationError(
                        wgnx::PeerErrorStage::Handshake,
                        wgnx::PeerErrorCode::HandshakeInitFailed,
                        value.occurred_at,
                        &effects);
                }
            }
            return effects;
        },
        event);
    FinalizeTimerEffects(effects);
    return effects;
}

} // namespace wgnx::sysmodule::runtime
