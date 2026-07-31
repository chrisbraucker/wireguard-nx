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

EffectBatch PeerRuntime::HandleEvent(const ActivationRequestedEvent& event) {
    EffectBatch effects{};
    const auto config_error = ValidateConfiguration();
    if (config_error != wgnx::PeerErrorCode::None) {
        EnterActivationError(
            config_error == wgnx::PeerErrorCode::ConfigInvalid ? wgnx::PeerErrorStage::Config : wgnx::PeerErrorStage::ResolveEndpoint,
            config_error,
            event.occurred_at,
            &effects
        );
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
    m_path_request_generation = AllocateGeneration(m_next_path_request_generation);
    m_path_availability = wgnx::platform::network_path_availability::unknown;
    m_last_path_observation = {};
    m_has_path_observation = false;
    m_rebind_on_path_confirmation = false;
    m_waiting_for_local_path = true;
    m_endpoint_resolution_started = false;
    m_receive_started = false;
    effects.Add(
        StartNetworkPathRequestEffect{
            .peer = identity,
            .path_generation = m_path_request_generation,
        }
    );
    return effects;
}

EffectBatch PeerRuntime::HandleEvent(const DeactivationRequestedEvent& event) {
    EffectBatch effects{};
    if (!IsCurrentActivation(event.peer.activation_generation)) {
        return effects;
    }
    if (!m_path_request_generation.IsZero()) {
        effects.Add(
            StopNetworkPathRequestEffect{
                .peer = event.peer,
                .path_generation = m_path_request_generation,
            }
        );
    }
    if (m_binding.IsOpen()) {
        effects.Add(
            CloseUdpSocketEffect{
                .path_generation = m_path_request_generation,
                .socket = m_binding.ReleaseSocket(),
            }
        );
    }
    if (auto* peer = ProtocolPeer()) {
        for (const auto hook : {
                 wgnx::wireguard::TimerHook::RetransmitHandshake,
                 wgnx::wireguard::TimerHook::SendKeepalive,
                 wgnx::wireguard::TimerHook::NewHandshake,
                 wgnx::wireguard::TimerHook::ZeroKeyMaterial,
                 wgnx::wireguard::TimerHook::PersistentKeepalive,
             }) {
            wgnx::wireguard::wg_timers_cancel(std::addressof(peer->timers), hook, peer->name);
            effects.Add(
                CancelProtocolTimerEffect{
                    .peer = event.peer,
                    .hook = hook,
                    .token = m_controller.Timers().Cancel(hook),
                }
            );
        }
    }
    Deactivate(event.occurred_at);
    return effects;
}

EffectBatch PeerRuntime::HandleEvent(const NetworkPathRequestStartedEvent& event) {
    EffectBatch effects{};
    if (!IsCurrentPathRequest(event.peer.activation_generation, event.path_generation)) {
        return effects;
    }
    if (!event.success) {
        logger::Log(
            "NIFM path request start failed peer=%u activation=%u path_generation=%u; waiting for peer reactivation",
            event.peer.peer_index.Value(),
            event.peer.activation_generation.Value(),
            event.path_generation.Value()
        );
    }
    return effects;
}

EffectBatch PeerRuntime::HandleEvent(const NetworkPathAvailabilityChangedEvent& event) {
    EffectBatch effects{};
    if (!IsCurrentPathRequest(event.peer.activation_generation, event.path_generation)) {
        return effects;
    }

    if (!m_has_path_observation || m_last_path_observation != event.observation) {
        logger::Log(
            "NIFM path observation peer=%u activation=%u path_generation=%u availability=%s raw=%u state_rc=0x%08x operation_rc=0x%08x",
            event.peer.peer_index.Value(),
            event.peer.activation_generation.Value(),
            event.path_generation.Value(),
            wgnx::platform::get_network_path_availability_name(event.observation.availability),
            static_cast<unsigned int>(event.observation.raw_state),
            event.observation.state_result,
            event.observation.operation_result
        );
        m_last_path_observation = event.observation;
        m_has_path_observation = true;
    }

    const auto next = event.observation.availability;
    if (next == wgnx::platform::network_path_availability::unknown) {
        if (m_path_availability == wgnx::platform::network_path_availability::available && IsInTransportState() && m_binding.IsOpen() &&
            !m_rebind_on_path_confirmation) {
            m_rebind_on_path_confirmation = true;
            logger::Log(
                "NIFM local path became indeterminate peer=%u activation=%u path_generation=%u; retaining socket and scheduling "
                "one rebind on confirmed availability",
                event.peer.peer_index.Value(),
                event.peer.activation_generation.Value(),
                event.path_generation.Value()
            );
        }
        return effects;
    }

    if (next == m_path_availability) {
        if (next == wgnx::platform::network_path_availability::available && m_rebind_on_path_confirmation) {
            m_rebind_on_path_confirmation = false;
            logger::Log(
                "NIFM local path confirmed after indeterminate state peer=%u activation=%u path_generation=%u; requesting one "
                "controlled rebind",
                event.peer.peer_index.Value(),
                event.peer.activation_generation.Value(),
                event.path_generation.Value()
            );
            effects.Append(HandleEvent(
                UdpRebindRequestedEvent{
                    .peer = event.peer,
                    .occurred_at = event.occurred_at,
                }
            ));
        }
        return effects;
    }

    const auto previous = m_path_availability;
    m_path_availability = next;
    logger::Log(
        "NIFM local-path transition peer=%u activation=%u path_generation=%u %s->%s raw=%u state_rc=0x%08x operation_rc=0x%08x",
        event.peer.peer_index.Value(),
        event.peer.activation_generation.Value(),
        event.path_generation.Value(),
        wgnx::platform::get_network_path_availability_name(previous),
        wgnx::platform::get_network_path_availability_name(next),
        static_cast<unsigned int>(event.observation.raw_state),
        event.observation.state_result,
        event.observation.operation_result
    );

    if (next == wgnx::platform::network_path_availability::unavailable) {
        m_rebind_on_path_confirmation = false;
        m_waiting_for_local_path = true;
        if (m_binding.IsOpen()) {
            SuspendTransport(event.peer, effects);
        }
        return effects;
    }

    m_waiting_for_local_path = false;
    if (!m_endpoint_resolution_started && m_lifecycle.state == wgnx::PeerRuntimeState::ResolvingEndpoint) {
        ResolveEndpointEffect resolve{
            .peer = event.peer,
            .path_generation = m_path_request_generation,
        };
        std::snprintf(resolve.endpoint.data(), resolve.endpoint.size(), "%s", m_config.endpoint.data());
        m_endpoint_resolution_started = true;
        effects.Add(resolve);
        return effects;
    }

    if (m_binding.IsSuspended() && IsInTransportState() && m_binding.HasEndpoint()) {
        effects.Append(HandleEvent(
            UdpRebindRequestedEvent{
                .peer = event.peer,
                .occurred_at = event.occurred_at,
            }
        ));
    }
    return effects;
}

EffectBatch PeerRuntime::HandleEvent(const TransportFailureEvent& event) {
    EffectBatch effects{};
    if (!IsCurrentActivation(event.peer.activation_generation) || !IsInTransportState() ||
        !m_binding.Matches(event.socket_generation, event.socket)) {
        return effects;
    }
    const auto code = MapSocketError(event.error);
    if (code == wgnx::PeerErrorCode::None) {
        return effects;
    }
    if (code == wgnx::PeerErrorCode::TransportSendFailed || code == wgnx::PeerErrorCode::TransportReceiveFailed) {
        logger::Log(
            "Nonterminal WG transport I/O failure peer=%u activation=%u state=%s operation=%s error=%s",
            event.peer.peer_index.Value(),
            event.peer.activation_generation.Value(),
            wgnx::GetPeerRuntimeStateName(m_lifecycle.state),
            event.operation == TransportIoOperation::Receive ? "receive worker" : "datagram send",
            wgnx::GetPeerErrorCodeName(code)
        );
        return effects;
    }
    EnterActivationError(wgnx::PeerErrorStage::Transport, code, event.occurred_at, &effects);
    return effects;
}

EffectBatch PeerRuntime::HandleEvent(const EndpointResolvedEvent& event) {
    EffectBatch effects{};
    if (!IsCurrentPathRequest(event.peer.activation_generation, event.path_generation) ||
        m_lifecycle.state != wgnx::PeerRuntimeState::ResolvingEndpoint || m_waiting_for_local_path ||
        m_path_availability != wgnx::platform::network_path_availability::available) {
        return effects;
    }
    if (!event.result.success) {
        EnterActivationError(event.result.error_stage, event.result.error_code, event.occurred_at, &effects);
        return effects;
    }
    m_binding.SetEndpoint(event.result.resolved, event.result.text.data());
    OpenUdpBindEffect open{
        .peer = event.peer,
        .path_generation = m_path_request_generation,
        .endpoint = event.result.resolved,
        .socket_generation = AllocateSocketGeneration(),
    };
    m_pending_socket_generation = open.socket_generation;
    m_pending_bind_purpose = open.purpose;
    std::snprintf(open.endpoint_text.data(), open.endpoint_text.size(), "%s", event.result.text.data());
    effects.Add(open);
    return effects;
}

EffectBatch PeerRuntime::HandleEvent(const UdpBindOpenedEvent& event) {
    EffectBatch effects{};
    if (event.socket_generation.IsZero() || !IsCurrentPathRequest(event.peer.activation_generation, event.path_generation) ||
        event.socket_generation != m_pending_socket_generation || event.purpose != m_pending_bind_purpose) {
        if (event.socket != wgnx::platform::InvalidSocket) {
            effects.Add(CloseUdpSocketEffect{.path_generation = m_path_request_generation, .socket = event.socket});
        }
        return effects;
    }
    m_pending_socket_generation = SocketGeneration{};
    if (event.purpose == UdpBindPurpose::Rebind) {
        if (!IsCurrentActivation(event.peer.activation_generation) || !IsInTransportState() || !m_binding.HasEndpoint() ||
            m_waiting_for_local_path || m_path_availability != wgnx::platform::network_path_availability::available) {
            if (event.socket != wgnx::platform::InvalidSocket) {
                effects.Add(CloseUdpSocketEffect{.path_generation = m_path_request_generation, .socket = event.socket});
            }
            return effects;
        }
        if (event.error != wgnx::platform::socket_error::none || event.socket == wgnx::platform::InvalidSocket) {
            if (event.socket != wgnx::platform::InvalidSocket) {
                effects.Add(CloseUdpSocketEffect{.path_generation = m_path_request_generation, .socket = event.socket});
            }
            logger::Log(
                "UDP bind bump open failed peer=%u activation=%u error=%u; peer state preserved",
                event.peer.peer_index.Value(),
                event.peer.activation_generation.Value(),
                static_cast<unsigned int>(event.error)
            );
            return effects;
        }

        const auto old_socket = m_binding.ReleaseSocket();
        m_binding.AdoptOpenSocket(event.endpoint, event.endpoint_text.data(), event.socket_generation, event.socket);
        if (old_socket != wgnx::platform::InvalidSocket) {
            effects.Add(CloseUdpSocketEffect{.path_generation = m_path_request_generation, .socket = old_socket});
        }
        logger::Log(
            "Completed UDP bind bump peer=%u activation=%u socket_generation=%u socket=%d old_socket=%d",
            event.peer.peer_index.Value(),
            event.peer.activation_generation.Value(),
            event.socket_generation.Value(),
            static_cast<int>(event.socket),
            static_cast<int>(old_socket)
        );
        RecoverTransport(event.peer, event.timer_facts, event.occurred_at, effects);
        effects.Add(QueueReceiveEffect{.peer = event.peer});
        return effects;
    }
    if (!IsCurrentActivation(event.peer.activation_generation) || m_lifecycle.state != wgnx::PeerRuntimeState::ResolvingEndpoint ||
        m_waiting_for_local_path || m_path_availability != wgnx::platform::network_path_availability::available) {
        if (event.socket != wgnx::platform::InvalidSocket) {
            effects.Add(CloseUdpSocketEffect{.path_generation = m_path_request_generation, .socket = event.socket});
        }
        return effects;
    }
    if (event.error != wgnx::platform::socket_error::none || event.socket == wgnx::platform::InvalidSocket) {
        if (event.socket != wgnx::platform::InvalidSocket) {
            effects.Add(CloseUdpSocketEffect{.path_generation = m_path_request_generation, .socket = event.socket});
        }
        EnterActivationError(wgnx::PeerErrorStage::Transport, wgnx::PeerErrorCode::TransportOpenFailed, event.occurred_at, &effects);
        return effects;
    }

    m_binding.AdoptOpenSocket(event.endpoint, event.endpoint_text.data(), event.socket_generation, event.socket);
    if (!InstantiateProtocol()) {
        EnterActivationError(wgnx::PeerErrorStage::Config, wgnx::PeerErrorCode::KeyInvalid, event.occurred_at, &effects);
        return effects;
    }
    if (!EnterHandshaking(event.peer.activation_generation, event.occurred_at)) {
        effects.Add(
            CloseUdpSocketEffect{
                .path_generation = m_path_request_generation,
                .socket = m_binding.ReleaseSocket(),
            }
        );
        return effects;
    }
    auto* peer = ProtocolPeer();
    const auto transition = peer != nullptr
                                ? m_controller.StartHandshake(m_protocol.device, *peer)
                                : wgnx::wireguard::HandshakeTransition{.action = wgnx::wireguard::HandshakeTransitionAction::Fatal};
    if (transition.action != wgnx::wireguard::HandshakeTransitionAction::SendInitiation ||
        !PrepareHandshakeInitiation(PendingDatagramKind::HandshakeInitiation)) {
        EnterActivationError(wgnx::PeerErrorStage::Handshake, wgnx::PeerErrorCode::HandshakeInitFailed, event.occurred_at, &effects);
        return effects;
    }
    effects.Add(
        SendPendingDatagramEffect{
            .peer = event.peer,
            .datagram_generation = m_pending_datagram.generation,
        }
    );
    return effects;
}

EffectBatch PeerRuntime::HandleEvent(const UdpRebindRequestedEvent& event) {
    EffectBatch effects{};
    if (!IsCurrentActivation(event.peer.activation_generation) || !IsInTransportState() || !m_binding.HasEndpoint()) {
        return effects;
    }
    if (m_waiting_for_local_path || m_path_availability != wgnx::platform::network_path_availability::available ||
        m_path_request_generation.IsZero() || !m_pending_socket_generation.IsZero()) {
        return effects;
    }
    const auto binding = m_binding.StateSnapshot();
    OpenUdpBindEffect open{
        .peer = event.peer,
        .path_generation = m_path_request_generation,
        .endpoint = binding.endpoint,
        .socket_generation = AllocateSocketGeneration(),
        .replaces_socket = binding.socket,
        .purpose = UdpBindPurpose::Rebind,
    };
    m_pending_socket_generation = open.socket_generation;
    m_pending_bind_purpose = open.purpose;
    std::snprintf(open.endpoint_text.data(), open.endpoint_text.size(), "%s", binding.endpoint_text.data());
    effects.Add(open);
    return effects;
}

} // namespace wgnx::sysmodule::runtime
