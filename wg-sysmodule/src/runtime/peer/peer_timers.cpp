#include "runtime/peer/peer_runtime.hpp"

#include "development_config.hpp"
#include "logger.hpp"

#include <chrono>
#include <memory>
#include <type_traits>

namespace wgnx::sysmodule::runtime {
wgnx::wireguard::TimerDeadline PeerRuntime::HandshakeRetryDeadline(const TimerFacts& timer_facts) const {
    return timer_facts.now + wgnx::wireguard::GetHandshakeRetryDelay(timer_facts.random_u32);
}

wgnx::wireguard::TimerDeadline PeerRuntime::KeepaliveDeadline(const TimerFacts& timer_facts) const {
    return timer_facts.now + wgnx::wireguard::KeepaliveTimeout;
}

wgnx::wireguard::TimerDeadline PeerRuntime::NewHandshakeDeadline(const TimerFacts& timer_facts) const {
    return timer_facts.now + wgnx::wireguard::KeepaliveTimeout + wgnx::wireguard::GetHandshakeRetryDelay(timer_facts.random_u32);
}

wgnx::wireguard::TimerDeadline PeerRuntime::PersistentKeepaliveDeadline(const TimerFacts& timer_facts) const {
    return timer_facts.now + std::chrono::seconds{m_config.persistent_keepalive};
}

wgnx::wireguard::TimerDeadline PeerRuntime::ZeroKeyMaterialDeadline(const TimerFacts& timer_facts) const {
    return timer_facts.now + wgnx::wireguard::ZeroKeyMaterialAfterTime;
}

void PeerRuntime::OnAuthenticatedPacketTraversal(const PeerIdentity& identity, const TimerFacts& timer_facts, EffectBatch& effects) {
    const auto* peer = ProtocolPeer();
    if (peer != nullptr && peer->persistent_keepalive_interval > 0) {
        effects.Add(
            ArmProtocolTimerEffect{
                .peer = identity,
                .hook = wgnx::wireguard::TimerHook::PersistentKeepalive,
                .deadline = PersistentKeepaliveDeadline(timer_facts),
            }
        );
    }
}

void PeerRuntime::OnAuthenticatedPacketSent(const PeerIdentity& identity, EffectBatch& effects) {
    effects.Add(
        CancelProtocolTimerEffect{
            .peer = identity,
            .hook = wgnx::wireguard::TimerHook::SendKeepalive,
        }
    );
}

void PeerRuntime::OnAuthenticatedPacketReceived(const PeerIdentity& identity, EffectBatch& effects) {
    effects.Add(
        CancelProtocolTimerEffect{
            .peer = identity,
            .hook = wgnx::wireguard::TimerHook::NewHandshake,
        }
    );
}

void PeerRuntime::RefreshKeyFreshness(
    const PeerIdentity& identity, const TimerFacts& timer_facts, wgnx::platform::ktime_t now, EffectBatch& effects
) {
    const auto* peer = ProtocolPeer();
    if (peer == nullptr || !peer->current_keypair.NeedsRekeyAt(wgnx::wireguard::GetMonotonicTime()) || m_pending_datagram.IsPending() ||
        peer->handshake_retry.active) {
        return;
    }
    if (!StartHandshake(identity, timer_facts, effects, false)) {
        EnterActivationError(wgnx::PeerErrorStage::Handshake, wgnx::PeerErrorCode::HandshakeInitFailed, now, &effects);
    }
}

void PeerRuntime::OnDataPacketSent(const PeerIdentity& identity, const TimerFacts& timer_facts, EffectBatch& effects) {
    const auto* peer = ProtocolPeer();
    if (peer != nullptr && !peer->timers.new_handshake.pending) {
        effects.Add(
            ArmProtocolTimerEffect{
                .peer = identity,
                .hook = wgnx::wireguard::TimerHook::NewHandshake,
                .deadline = NewHandshakeDeadline(timer_facts),
            }
        );
    }
}

void PeerRuntime::OnDataPacketReceived(const PeerIdentity& identity, const TimerFacts& timer_facts, EffectBatch& effects) {
    auto* peer = ProtocolPeer();
    if (peer == nullptr) {
        return;
    }
    if (peer->timers.send_keepalive.pending) {
        peer->timers.need_another_keepalive = true;
        return;
    }
    effects.Add(
        ArmProtocolTimerEffect{
            .peer = identity,
            .hook = wgnx::wireguard::TimerHook::SendKeepalive,
            .deadline = KeepaliveDeadline(timer_facts),
        }
    );
}

void PeerRuntime::OnSessionDerived(const PeerIdentity& identity, const TimerFacts& timer_facts, EffectBatch& effects) {
    effects.Add(
        ArmProtocolTimerEffect{
            .peer = identity,
            .hook = wgnx::wireguard::TimerHook::ZeroKeyMaterial,
            .deadline = ZeroKeyMaterialDeadline(timer_facts),
        }
    );
}

void PeerRuntime::OnHandshakeComplete(const PeerIdentity& identity, EffectBatch& effects) {
    effects.Add(
        CancelProtocolTimerEffect{
            .peer = identity,
            .hook = wgnx::wireguard::TimerHook::RetransmitHandshake,
        }
    );
}
void PeerRuntime::FinalizeTimerEffects(EffectBatch& effects) {
    for (auto& effect : effects) {
        std::visit(
            [this](auto& value) {
                using Effect = std::remove_cvref_t<decltype(value)>;
                if constexpr (std::is_same_v<Effect, ArmProtocolTimerEffect>) {
                    if (!IsCurrentActivation(value.peer.activation_generation) || value.peer.peer_index != m_peer_index) {
                        return;
                    }
                    auto* peer = ProtocolPeer();
                    if (peer == nullptr) {
                        return;
                    }
                    wgnx::wireguard::wg_timers_cancel(std::addressof(peer->timers), value.hook, peer->name);
                    wgnx::wireguard::wg_timers_schedule(std::addressof(peer->timers), value.hook, value.deadline, peer->name);
                    value.token = m_controller.Timers().Arm(
                        value.hook,
                        {
                            .peer_index = value.peer.peer_index.Value(),
                            .activation_generation = value.peer.activation_generation.Value(),
                            .protocol_sequence =
                                value.hook == wgnx::wireguard::TimerHook::RetransmitHandshake ? peer->handshake_retry.sequence_count : 0,
                        }
                    );
                } else if constexpr (std::is_same_v<Effect, CancelProtocolTimerEffect>) {
                    if (!IsCurrentActivation(value.peer.activation_generation) || value.peer.peer_index != m_peer_index) {
                        return;
                    }
                    if (auto* peer = ProtocolPeer()) {
                        wgnx::wireguard::wg_timers_cancel(std::addressof(peer->timers), value.hook, peer->name);
                    }
                    value.token = m_controller.Timers().Cancel(value.hook);
                }
            },
            effect
        );
    }
}

void PeerRuntime::SuspendTransport(const PeerIdentity& identity, EffectBatch& effects) {
    if (m_binding.IsSuspended()) {
        logger::Log(
            "UDP transport already suspended peer=%u activation=%u",
            identity.peer_index.Value(),
            identity.activation_generation.Value()
        );
        return;
    }

    const auto binding = m_binding.StateSnapshot();
    logger::Log(
        "Suspending UDP transport for local-path unavailability peer=%u activation=%u socket_generation=%u socket=%d; preserving "
        "peer and protocol state",
        identity.peer_index.Value(),
        identity.activation_generation.Value(),
        binding.generation.Value(),
        static_cast<int>(binding.socket)
    );
    for (const auto hook : {
             wgnx::wireguard::TimerHook::RetransmitHandshake,
             wgnx::wireguard::TimerHook::SendKeepalive,
             wgnx::wireguard::TimerHook::NewHandshake,
             wgnx::wireguard::TimerHook::PersistentKeepalive,
         }) {
        effects.Add(
            CancelProtocolTimerEffect{
                .peer = identity,
                .hook = hook,
            }
        );
    }
    const auto socket = m_binding.ReleaseAndSuspend();
    if (socket != wgnx::platform::InvalidSocket) {
        effects.Add(CloseUdpSocketEffect{.path_generation = m_path_request_generation, .socket = socket});
    }
    logger::Log(
        "UDP transport suspended for local-path unavailability peer=%u activation=%u old_socket_generation=%u old_socket=%d state=%s",
        identity.peer_index.Value(),
        identity.activation_generation.Value(),
        binding.generation.Value(),
        static_cast<int>(socket),
        wgnx::GetPeerRuntimeStateName(m_lifecycle.state)
    );
}

void PeerRuntime::RecoverTransport(
    const PeerIdentity& identity, const TimerFacts& timer_facts, wgnx::platform::ktime_t now, EffectBatch& effects
) {
    const auto binding = m_binding.StateSnapshot();
    if (m_pending_datagram.IsPending()) {
        logger::Log(
            "UDP recovery deferred peer=%u activation=%u state=%s reason=pending_datagram kind=%s generation=%u binding_open=%u "
            "binding_suspended=%u socket_generation=%u socket=%d",
            identity.peer_index.Value(),
            identity.activation_generation.Value(),
            wgnx::GetPeerRuntimeStateName(m_lifecycle.state),
            GetPendingDatagramKindName(m_pending_datagram.kind),
            m_pending_datagram.generation.Value(),
            binding.IsOpen() ? 1U : 0U,
            binding.suspended ? 1U : 0U,
            binding.generation.Value(),
            static_cast<int>(binding.socket)
        );
        return;
    }
    auto* peer = ProtocolPeer();
    if (peer == nullptr) {
        logger::Log(
            "UDP recovery skipped peer=%u activation=%u state=%s reason=no_protocol_peer binding_open=%u binding_suspended=%u "
            "socket_generation=%u socket=%d",
            identity.peer_index.Value(),
            identity.activation_generation.Value(),
            wgnx::GetPeerRuntimeStateName(m_lifecycle.state),
            binding.IsOpen() ? 1U : 0U,
            binding.suspended ? 1U : 0U,
            binding.generation.Value(),
            static_cast<int>(binding.socket)
        );
        return;
    }
    const bool current_key_can_send = peer->current_keypair.CanSendAt(wgnx::wireguard::GetMonotonicTime());
    if (m_lifecycle.state == wgnx::PeerRuntimeState::Active && current_key_can_send) {
        if (StagedInnerPacketCount() != 0) {
            logger::Log(
                "UDP recovery draining staged inner packets peer=%u activation=%u count=%zu socket_generation=%u socket=%d",
                identity.peer_index.Value(),
                identity.activation_generation.Value(),
                StagedInnerPacketCount(),
                binding.generation.Value(),
                static_cast<int>(binding.socket)
            );
            ProcessOutboundQueue(identity, timer_facts, now, effects);
            if (m_pending_datagram.IsPending()) {
                return;
            }
        }
        logger::Log(
            "UDP recovery selected keepalive peer=%u activation=%u socket_generation=%u socket=%d",
            identity.peer_index.Value(),
            identity.activation_generation.Value(),
            binding.generation.Value(),
            static_cast<int>(binding.socket)
        );
        wgnx::wireguard::TransportDataError build_error{};
        if (!PrepareTransportDatagram({}, PendingDatagramKind::Keepalive, PacketId{}, build_error)) {
            EnterActivationError(wgnx::PeerErrorStage::Internal, wgnx::PeerErrorCode::InternalFailure, now, &effects);
            return;
        }
        effects.Add(
            SendPendingDatagramEffect{
                .peer = identity,
                .datagram_generation = m_pending_datagram.generation,
            }
        );
        return;
    }

    logger::Log(
        "UDP recovery selected handshake peer=%u activation=%u state=%s current_key_can_send=%u socket_generation=%u socket=%d",
        identity.peer_index.Value(),
        identity.activation_generation.Value(),
        wgnx::GetPeerRuntimeStateName(m_lifecycle.state),
        current_key_can_send ? 1U : 0U,
        binding.generation.Value(),
        static_cast<int>(binding.socket)
    );
    if (!StartHandshake(identity, timer_facts, effects, false)) {
        EnterActivationError(wgnx::PeerErrorStage::Handshake, wgnx::PeerErrorCode::HandshakeInitFailed, now, &effects);
    }
}

EffectBatch PeerRuntime::HandleEvent(const ProtocolTimerExpiredEvent& event) {
    EffectBatch effects{};
    if (!IsCurrentActivation(event.peer.activation_generation) || event.token.hook != event.hook ||
        event.token.owner.peer_index != event.peer.peer_index.Value() ||
        event.token.owner.activation_generation != event.peer.activation_generation.Value()) {
        return effects;
    }
    auto* peer = ProtocolPeer();
    if (peer == nullptr) {
        return effects;
    }
    const wgnx::wireguard::TimerOwner current_owner{
        .peer_index = event.peer.peer_index.Value(),
        .activation_generation = event.peer.activation_generation.Value(),
        .protocol_sequence = event.hook == wgnx::wireguard::TimerHook::RetransmitHandshake ? peer->handshake_retry.sequence_count : 0,
    };
    if (!m_controller.Timers().IsCurrent(event.token, current_owner)) {
        logger::Log(
            "Ignored stale WG timer event hook=%s token_peer=%u current_peer=%u token_activation=%u current_activation=%u "
            "token_sequence=%u current_sequence=%u generation=%u",
            wgnx::wireguard::GetTimerHookName(event.hook),
            event.token.owner.peer_index,
            event.peer.peer_index.Value(),
            event.token.owner.activation_generation,
            event.peer.activation_generation.Value(),
            event.token.owner.protocol_sequence,
            current_owner.protocol_sequence,
            event.token.generation
        );
        return effects;
    }
    logger::Log(
        "WG timer peer='%s' fire hook=%s generation=%u",
        peer->name,
        wgnx::wireguard::GetTimerHookName(event.hook),
        event.token.generation
    );
    effects.Add(
        CancelProtocolTimerEffect{
            .peer = event.peer,
            .hook = event.hook,
        }
    );
    if (m_binding.IsSuspended() && event.hook != wgnx::wireguard::TimerHook::ZeroKeyMaterial) {
        logger::Log(
            "WG timer canceled for suspended UDP transport peer=%u activation=%u hook=%s",
            event.peer.peer_index.Value(),
            event.peer.activation_generation.Value(),
            wgnx::wireguard::GetTimerHookName(event.hook)
        );
        return effects;
    }
    if (!IsInTransportState() && event.hook != wgnx::wireguard::TimerHook::ZeroKeyMaterial) {
        return effects;
    }
    switch (event.hook) {
    case wgnx::wireguard::TimerHook::RetransmitHandshake: {
        const auto transition = m_controller.HandleHandshakeRetryTimer(m_protocol.device, *peer);
        if (transition.action == wgnx::wireguard::HandshakeTransitionAction::Exhausted) {
            if (!peer->timers.zero_key_material.pending) {
                effects.Add(
                    ArmProtocolTimerEffect{
                        .peer = event.peer,
                        .hook = wgnx::wireguard::TimerHook::ZeroKeyMaterial,
                        .deadline = ZeroKeyMaterialDeadline(event.timer_facts),
                    }
                );
            }
            return effects;
        }
        if (transition.action == wgnx::wireguard::HandshakeTransitionAction::SendInitiation &&
            PrepareHandshakeInitiation(PendingDatagramKind::HandshakeInitiation)) {
            effects.Add(
                SendPendingDatagramEffect{
                    .peer = event.peer,
                    .datagram_generation = m_pending_datagram.generation,
                }
            );
        } else if (transition.action != wgnx::wireguard::HandshakeTransitionAction::Ignore) {
            EnterActivationError(wgnx::PeerErrorStage::Handshake, wgnx::PeerErrorCode::HandshakeInitFailed, event.occurred_at, &effects);
        }
        return effects;
    }
    case wgnx::wireguard::TimerHook::SendKeepalive: {
        if (m_lifecycle.state != wgnx::PeerRuntimeState::Active) {
            return effects;
        }
        if (!peer->current_keypair.CanSendAt(wgnx::wireguard::GetMonotonicTime())) {
            if (!StartHandshake(event.peer, event.timer_facts, effects, false)) {
                EnterActivationError(
                    wgnx::PeerErrorStage::Handshake,
                    wgnx::PeerErrorCode::HandshakeInitFailed,
                    event.occurred_at,
                    &effects
                );
            }
            return effects;
        }
        wgnx::wireguard::TransportDataError build_error{};
        if (!PrepareTransportDatagram({}, PendingDatagramKind::Keepalive, PacketId{}, build_error)) {
            EnterActivationError(wgnx::PeerErrorStage::Internal, wgnx::PeerErrorCode::InternalFailure, event.occurred_at, &effects);
            return effects;
        }
        const bool need_another_keepalive = peer->timers.need_another_keepalive;
        peer->timers.need_another_keepalive = false;
        if (need_another_keepalive) {
            effects.Add(
                ArmProtocolTimerEffect{
                    .peer = event.peer,
                    .hook = event.hook,
                    .deadline = KeepaliveDeadline(event.timer_facts),
                }
            );
        }
        effects.Add(
            SendPendingDatagramEffect{
                .peer = event.peer,
                .datagram_generation = m_pending_datagram.generation,
            }
        );
        return effects;
    }
    case wgnx::wireguard::TimerHook::NewHandshake:
        if (m_lifecycle.state == wgnx::PeerRuntimeState::Active && !StartHandshake(event.peer, event.timer_facts, effects, false)) {
            EnterActivationError(wgnx::PeerErrorStage::Handshake, wgnx::PeerErrorCode::HandshakeInitFailed, event.occurred_at, &effects);
        }
        return effects;
    case wgnx::wireguard::TimerHook::PersistentKeepalive:
        if (m_lifecycle.state != wgnx::PeerRuntimeState::Active || peer->persistent_keepalive_interval == 0) {
            return effects;
        }
        if (!peer->current_keypair.CanSendAt(wgnx::wireguard::GetMonotonicTime())) {
            if (!StartHandshake(event.peer, event.timer_facts, effects, false)) {
                EnterActivationError(
                    wgnx::PeerErrorStage::Handshake,
                    wgnx::PeerErrorCode::HandshakeInitFailed,
                    event.occurred_at,
                    &effects
                );
            }
            return effects;
        }
        {
            wgnx::wireguard::TransportDataError build_error{};
            if (!PrepareTransportDatagram({}, PendingDatagramKind::Keepalive, PacketId{}, build_error)) {
                EnterActivationError(wgnx::PeerErrorStage::Internal, wgnx::PeerErrorCode::InternalFailure, event.occurred_at, &effects);
                return effects;
            }
        }
        effects.Add(
            SendPendingDatagramEffect{
                .peer = event.peer,
                .datagram_generation = m_pending_datagram.generation,
            }
        );
        return effects;
    case wgnx::wireguard::TimerHook::ZeroKeyMaterial:
        wgnx::wireguard::wg_peer_zero_key_material(peer);
        wgnx::wireguard::wg_device_clear_index_registry(std::addressof(m_protocol.device));
        logger::Log(
            "WG zeroed stale handshake and keypair material peer=%u activation=%u; peer and UDP binding preserved",
            event.peer.peer_index.Value(),
            event.peer.activation_generation.Value()
        );
        return effects;
    }
    return effects;
}

} // namespace wgnx::sysmodule::runtime
