#include "runtime/peer/peer_runtime.hpp"

#include "development_config.hpp"
#include "logger.hpp"

#include <algorithm>
#include <cstdio>
#include <memory>

namespace wgnx::sysmodule::runtime {

namespace {

wgnx::PeerErrorCode MapSocketError(wgnx::platform::socket_error error) {
    switch (error) {
        case wgnx::platform::socket_error::none:
            return wgnx::PeerErrorCode::None;
        case wgnx::platform::socket_error::transport_init_failed:
            return wgnx::PeerErrorCode::TransportInitFailed;
        case wgnx::platform::socket_error::open_failed:
            return wgnx::PeerErrorCode::TransportOpenFailed;
        case wgnx::platform::socket_error::send_failed:
            return wgnx::PeerErrorCode::TransportSendFailed;
        case wgnx::platform::socket_error::receive_failed:
            return wgnx::PeerErrorCode::TransportReceiveFailed;
        case wgnx::platform::socket_error::invalid_endpoint:
            return wgnx::PeerErrorCode::InternalFailure;
    }
    return wgnx::PeerErrorCode::InternalFailure;
}

} // namespace

EffectBatch PeerRuntime::HandleEvent(const ActivationRequestedEvent &event) {
    EffectBatch effects{};
                const auto config_error = ValidateConfiguration();
                if (config_error != wgnx::PeerErrorCode::None) {
                    EnterActivationError(
                        config_error == wgnx::PeerErrorCode::ConfigInvalid
                            ? wgnx::PeerErrorStage::Config
                            : wgnx::PeerErrorStage::ResolveEndpoint,
                        config_error,
                        event.occurred_at,
                        &effects);
                    return effects;
                }

                m_binding.ClearEndpoint();
                m_pending_datagram = {};
                m_pending_socket_generation = SocketGeneration{};
                std::ranges::fill(m_decrypted_packet.bytes, 0);
                m_decrypted_packet.size = 0;
                m_decrypted_packet.generation = PacketGeneration{};
                ResetProtocol();
                const PeerIdentity identity{
                    .peer_index = event.peer_index,
                    .activation_generation = BeginActivation(event.occurred_at),
                };
                ResolveEndpointEffect resolve{.peer = identity};
                std::snprintf(
                    resolve.endpoint.data(),
                    resolve.endpoint.size(),
                    "%s",
                    m_config.endpoint.data());
                effects.Add(resolve);
    return effects;
}

EffectBatch PeerRuntime::HandleEvent(const DeactivationRequestedEvent &event) {
    EffectBatch effects{};
                if (!IsCurrentActivation(event.peer.activation_generation)) {
                    return effects;
                }
                if (m_binding.IsOpen()) {
                    effects.Add(CloseUdpSocketEffect{
                        .socket = m_binding.ReleaseSocket(),
                    });
                }
                if (auto *peer = ProtocolPeer()) {
                    for (const auto hook : {
                             wgnx::wireguard::TimerHook::RetransmitHandshake,
                             wgnx::wireguard::TimerHook::SendKeepalive,
                             wgnx::wireguard::TimerHook::Rekey,
                             wgnx::wireguard::TimerHook::ZeroKeyMaterial,
                         }) {
                        wgnx::wireguard::wg_timers_cancel(
                            std::addressof(peer->timers), hook, peer->name);
                        effects.Add(CancelProtocolTimerEffect{
                            .peer = event.peer,
                            .hook = hook,
                            .token = m_controller.Timers().Cancel(hook),
                        });
                    }
                }
                Deactivate(event.occurred_at);
    return effects;
}

EffectBatch PeerRuntime::HandleEvent(const TransportFailureEvent &event) {
    EffectBatch effects{};
                if (!IsCurrentActivation(event.peer.activation_generation) ||
                    !IsInTransportState() ||
                    !m_binding.Matches(event.socket_generation, event.socket)) {
                    return effects;
                }
                const auto code = MapSocketError(event.error);
                if (code == wgnx::PeerErrorCode::None) {
                    return effects;
                }
                if (code == wgnx::PeerErrorCode::TransportSendFailed ||
                    code == wgnx::PeerErrorCode::TransportReceiveFailed) {
                    logger::Log(
                        "Nonterminal WG transport I/O failure peer=%u activation=%u state=%s operation=%s error=%s",
                        event.peer.peer_index.Value(),
                        event.peer.activation_generation.Value(),
                        wgnx::GetPeerRuntimeStateName(m_lifecycle.state),
                        event.operation == TransportIoOperation::Receive
                            ? "receive worker"
                            : "unknown",
                        wgnx::GetPeerErrorCodeName(code));
                    if constexpr (development_config::SuspendUdpTransportOnFirstIoFailure) {
                        SuspendTransport(event.peer, effects);
                    }
                    return effects;
                }
                EnterActivationError(
                    wgnx::PeerErrorStage::Transport,
                    code,
                    event.occurred_at,
                    &effects);
    return effects;
}

EffectBatch PeerRuntime::HandleEvent(const EndpointResolvedEvent &event) {
    EffectBatch effects{};
                if (!IsCurrentActivation(event.peer.activation_generation) ||
                    m_lifecycle.state != wgnx::PeerRuntimeState::ResolvingEndpoint) {
                    return effects;
                }
                if (!event.result.success) {
                    EnterActivationError(
                        event.result.error_stage,
                        event.result.error_code,
                        event.occurred_at,
                        &effects);
                    return effects;
                }
                m_binding.SetEndpoint(event.result.resolved, event.result.text.data());
                OpenUdpBindEffect open{
                    .peer = event.peer,
                    .endpoint = event.result.resolved,
                    .socket_generation = AllocateSocketGeneration(),
                };
                m_pending_socket_generation = open.socket_generation;
                m_pending_bind_purpose = open.purpose;
                std::snprintf(
                    open.endpoint_text.data(),
                    open.endpoint_text.size(),
                    "%s",
                    event.result.text.data());
                effects.Add(open);
    return effects;
}

EffectBatch PeerRuntime::HandleEvent(const UdpBindOpenedEvent &event) {
    EffectBatch effects{};
                if (event.socket_generation.IsZero() ||
                    event.socket_generation != m_pending_socket_generation ||
                    event.purpose != m_pending_bind_purpose) {
                    if (event.socket != wgnx::platform::InvalidSocket) {
                        effects.Add(
                            CloseUdpSocketEffect{.socket = event.socket});
                    }
                    return effects;
                }
                m_pending_socket_generation = SocketGeneration{};
                if (event.purpose == UdpBindPurpose::Rebind) {
                    if (!IsCurrentActivation(event.peer.activation_generation) ||
                        !IsInTransportState() || !m_binding.HasEndpoint()) {
                        if (event.socket != wgnx::platform::InvalidSocket) {
                            effects.Add(
                                CloseUdpSocketEffect{.socket = event.socket});
                        }
                        return effects;
                    }
                    if (event.error != wgnx::platform::socket_error::none ||
                        event.socket == wgnx::platform::InvalidSocket) {
                        if (event.socket != wgnx::platform::InvalidSocket) {
                            effects.Add(
                                CloseUdpSocketEffect{.socket = event.socket});
                        }
                        logger::Log(
                            "UDP bind bump open failed peer=%u activation=%u error=%u; peer state preserved",
                            event.peer.peer_index.Value(),
                            event.peer.activation_generation.Value(),
                            static_cast<unsigned int>(event.error));
                        return effects;
                    }

                    const auto old_socket = m_binding.ReleaseSocket();
                    m_binding.AdoptOpenSocket(
                        event.endpoint,
                        event.endpoint_text.data(),
                        event.socket_generation,
                        event.socket);
                    if (old_socket != wgnx::platform::InvalidSocket) {
                        effects.Add(
                            CloseUdpSocketEffect{.socket = old_socket});
                    }
                    logger::Log(
                        "Completed UDP bind bump peer=%u activation=%u socket_generation=%u socket=%d old_socket=%d",
                        event.peer.peer_index.Value(),
                        event.peer.activation_generation.Value(),
                        event.socket_generation.Value(),
                        static_cast<int>(event.socket),
                        static_cast<int>(old_socket));
                    RecoverTransport(
                        event.peer,
                        event.timer_facts,
                        event.occurred_at,
                        effects);
                    effects.Add(QueueReceiveEffect{.peer = event.peer});
                    return effects;
                }
                if (!IsCurrentActivation(event.peer.activation_generation) ||
                    m_lifecycle.state != wgnx::PeerRuntimeState::ResolvingEndpoint) {
                    if (event.socket != wgnx::platform::InvalidSocket) {
                        effects.Add(CloseUdpSocketEffect{.socket = event.socket});
                    }
                    return effects;
                }
                if (event.error != wgnx::platform::socket_error::none ||
                    event.socket == wgnx::platform::InvalidSocket) {
                    if (event.socket != wgnx::platform::InvalidSocket) {
                        effects.Add(CloseUdpSocketEffect{.socket = event.socket});
                    }
                    EnterActivationError(
                        wgnx::PeerErrorStage::Transport,
                        wgnx::PeerErrorCode::TransportOpenFailed,
                        event.occurred_at,
                        &effects);
                    return effects;
                }

                m_binding.AdoptOpenSocket(
                    event.endpoint,
                    event.endpoint_text.data(),
                    event.socket_generation,
                    event.socket);
                if (!InstantiateProtocol()) {
                    EnterActivationError(
                        wgnx::PeerErrorStage::Config,
                        wgnx::PeerErrorCode::KeyInvalid,
                        event.occurred_at,
                        &effects);
                    return effects;
                }
                if (!EnterHandshaking(event.peer.activation_generation, event.occurred_at)) {
                    effects.Add(CloseUdpSocketEffect{
                        .socket = m_binding.ReleaseSocket(),
                    });
                    return effects;
                }
                auto *peer = ProtocolPeer();
                const auto transition = peer != nullptr
                    ? m_controller.StartHandshake(m_protocol.device, *peer)
                    : wgnx::wireguard::HandshakeTransition{
                          .action = wgnx::wireguard::HandshakeTransitionAction::Fatal};
                if (transition.action != wgnx::wireguard::HandshakeTransitionAction::SendInitiation ||
                    !PrepareHandshakeInitiation(PendingDatagramKind::HandshakeInitiation)) {
                    EnterActivationError(
                        wgnx::PeerErrorStage::Handshake,
                        wgnx::PeerErrorCode::HandshakeInitFailed,
                        event.occurred_at,
                        &effects);
                    return effects;
                }
                effects.Add(ArmProtocolTimerEffect{
                    .peer = event.peer,
                    .hook = wgnx::wireguard::TimerHook::RetransmitHandshake,
                    .deadline = HandshakeRetryDeadline(event.timer_facts),
                });
                effects.Add(SendPendingDatagramEffect{
                    .peer = event.peer,
                    .datagram_generation = m_pending_datagram.generation,
                });
                effects.Add(QueueReceiveEffect{.peer = event.peer});
    return effects;
}

EffectBatch PeerRuntime::HandleEvent(const UdpRebindRequestedEvent &event) {
    EffectBatch effects{};
                if (!IsCurrentActivation(event.peer.activation_generation) ||
                    !IsInTransportState() || !m_binding.HasEndpoint()) {
                    return effects;
                }
                const auto binding = m_binding.StateSnapshot();
                OpenUdpBindEffect open{
                    .peer = event.peer,
                    .endpoint = binding.endpoint,
                    .socket_generation = AllocateSocketGeneration(),
                    .purpose = UdpBindPurpose::Rebind,
                };
                m_pending_socket_generation = open.socket_generation;
                m_pending_bind_purpose = open.purpose;
                std::snprintf(
                    open.endpoint_text.data(),
                    open.endpoint_text.size(),
                    "%s",
                    binding.endpoint_text.data());
                effects.Add(open);
    return effects;
}

} // namespace wgnx::sysmodule::runtime
