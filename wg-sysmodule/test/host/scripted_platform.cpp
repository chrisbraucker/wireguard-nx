#include "scripted_platform.hpp"

#include "runtime/effect_drain.hpp"

#include <algorithm>
#include <cstdio>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>

namespace wgnx::test {

namespace {

using namespace wgnx::sysmodule::runtime;

wgnx::platform::endpoint_resolution_result DefaultResolutionResult() {
    wgnx::platform::endpoint_resolution_result result{
        .success = true,
        .resolved = {
            .family = wgnx::platform::address_family::inet,
            .port = 51820,
            .address = {192, 0, 2, 1},
        },
    };
    std::snprintf(result.text.data(), result.text.size(), "192.0.2.1:51820");
    return result;
}

} // namespace

ScriptedPlatform::ScriptedPlatform(RuntimeCoordinator& coordinator, wgnx::platform::ktime_t initial_time)
    : m_coordinator(coordinator), m_now(initial_time) {}

void ScriptedPlatform::QueueResolutionResult(const wgnx::platform::endpoint_resolution_result& result) {
    m_resolution_results.push_back(result);
}

void ScriptedPlatform::QueueUdpOpenResult(UdpOpenResult result) {
    m_udp_open_results.push_back(result);
}

void ScriptedPlatform::QueueUdpSendResult(UdpSendResult result) {
    m_udp_send_results.push_back(result);
}

void ScriptedPlatform::QueueUdpReceiveResult(UdpReceiveResult result) {
    m_udp_receive_results.push_back(std::move(result));
}

void ScriptedPlatform::QueuePersistenceResult(bool success) {
    m_persistence_results.push_back(success);
}

void ScriptedPlatform::Execute(const EffectBatch& effects) {
    DrainEffectBatches(effects, [this](const RuntimeEffect& effect, EffectBatch& generated) { ExecuteEffect(effect, generated); });
}

bool ScriptedPlatform::CompleteNextResolution() {
    const std::optional<ResolveEndpointEffect> request = m_resolver.Take();
    if (!request.has_value()) {
        m_resolver.MarkWorkerIdle();
        return false;
    }

    Execute(m_coordinator.Dispatch(
        EndpointResolvedEvent{
            .peer = request->peer,
            .path_generation = request->path_generation,
            .result = TakeResolutionResult(),
            .occurred_at = NextTime(),
        }
    ));
    if (!HasPendingResolution()) {
        m_resolver.MarkWorkerIdle();
    }
    return true;
}

bool ScriptedPlatform::CompleteNextUdpOpen() {
    if (m_udp_open_requests.empty()) {
        return false;
    }

    const OpenUdpBindEffect request = m_udp_open_requests.front();
    m_udp_open_requests.pop_front();
    UdpOpenResult result = TakeUdpOpenResult();
    Execute(m_coordinator.Dispatch(
        UdpBindOpenedEvent{
            .peer = request.peer,
            .path_generation = request.path_generation,
            .endpoint = request.endpoint,
            .endpoint_text = request.endpoint_text,
            .socket = result.socket,
            .error = result.error,
            .socket_generation = request.socket_generation,
            .purpose = request.purpose,
            .timer_facts = {.now = wgnx::wireguard::TimerDeadlineFromJiffies(500)},
            .occurred_at = NextTime(),
        }
    ));
    return true;
}

bool ScriptedPlatform::CompleteNextUdpSend() {
    if (m_udp_send_requests.empty()) {
        return false;
    }

    const SendPendingDatagramEffect request = m_udp_send_requests.front();
    m_udp_send_requests.pop_front();
    PendingDatagramSnapshot snapshot{};
    const bool available = m_coordinator.SnapshotPendingDatagram(request.peer, request.datagram_generation, snapshot);
    const UdpSendResult result = available ? TakeUdpSendResult() : UdpSendResult{.error = wgnx::platform::socket_error::send_failed};
    Execute(m_coordinator.Dispatch(
        PendingDatagramSentEvent{
            .peer = request.peer,
            .datagram_generation = request.datagram_generation,
            .bytes_sent = result.error == wgnx::platform::socket_error::none && result.bytes_sent == 0 && available ? snapshot.size
                                                                                                                    : result.bytes_sent,
            .error = result.error,
            .occurred_at = NextTime(),
        }
    ));
    return true;
}

bool ScriptedPlatform::CompleteNextUdpReceive() {
    if (m_udp_receive_requests.empty()) {
        return false;
    }

    ReceiveRuntimeSnapshot snapshot{};
    while (!m_udp_receive_requests.empty()) {
        const QueueReceiveEffect request = m_udp_receive_requests.front();
        m_udp_receive_requests.pop_front();
        if (m_coordinator.SnapshotReceiveRuntime(snapshot) && snapshot.peer == request.peer) {
            break;
        }
    }
    if (snapshot.peer.activation_generation.IsZero()) {
        return false;
    }
    if (m_udp_receive_results.empty()) {
        return false;
    }

    UdpReceiveResult result = std::move(m_udp_receive_results.front());
    m_udp_receive_results.pop_front();

    if (result.kind == UdpReceiveResult::Kind::Failure) {
        Execute(m_coordinator.Dispatch(
            TransportFailureEvent{
                .peer = snapshot.peer,
                .operation = TransportIoOperation::Receive,
                .socket = snapshot.socket,
                .socket_generation = snapshot.socket_generation,
                .error = result.error,
                .occurred_at = NextTime(),
            }
        ));
        return true;
    }

    std::array<char, sizeof(wgnx::PeerInfo::resolved_endpoint)> source_text{};
    std::snprintf(source_text.data(), source_text.size(), "scripted-peer");
    Execute(m_coordinator.Dispatch(
        EncryptedDatagramReceivedEvent{
            .peer = snapshot.peer,
            .packet = std::span<const std::uint8_t>(result.bytes).first(result.size),
            .source = result.source,
            .source_text = source_text,
            .timer_facts = {.now = wgnx::wireguard::TimerDeadlineFromJiffies(500)},
            .occurred_at = NextTime(),
        }
    ));
    return true;
}

bool ScriptedPlatform::CaptureTimerExpiration(wgnx::wireguard::TimerHook hook) {
    return m_timers.CaptureExpiration(hook);
}

bool ScriptedPlatform::DeliverCapturedTimer(wgnx::wireguard::TimerHook hook) {
    const auto token = m_timers.TakeDelivery(hook);
    if (!token.IsValid()) {
        return false;
    }

    Execute(m_coordinator.Dispatch(
        ProtocolTimerExpiredEvent{
            .peer =
                {
                    .peer_index = PeerIndex{token.owner.peer_index},
                    .activation_generation = ActivationGeneration{token.owner.activation_generation},
                },
            .hook = hook,
            .token = token,
            .timer_facts = {.now = wgnx::wireguard::TimerDeadlineFromJiffies(500)},
            .occurred_at = NextTime(),
        }
    ));
    return true;
}

bool ScriptedPlatform::CancelResolution(const PeerIdentity& peer) {
    const auto before = m_resolver.Statistics().cancelled;
    m_resolver.Cancel(peer);
    return m_resolver.Statistics().cancelled != before;
}

bool ScriptedPlatform::PersistAutoStart(AutoStartPersistenceState& state, const AutoStartPersistenceRequest& request) {
    if (!state.IsCurrent(request)) {
        return false;
    }

    ++m_statistics.persistence_attempts;
    bool success = true;
    if (!m_persistence_results.empty()) {
        success = m_persistence_results.front();
        m_persistence_results.pop_front();
    }
    return success && state.IsCurrent(request);
}

bool ScriptedPlatform::HasPendingResolution() const {
    return m_resolver.Statistics().depth != 0;
}

bool ScriptedPlatform::HasPendingUdpOpen() const {
    return !m_udp_open_requests.empty();
}

bool ScriptedPlatform::HasPendingUdpSend() const {
    return !m_udp_send_requests.empty();
}

bool ScriptedPlatform::HasPendingUdpReceive() const {
    return !m_udp_receive_requests.empty();
}

bool ScriptedPlatform::IsTimerArmed(wgnx::wireguard::TimerHook hook) const {
    return m_timers.IsArmed(hook);
}

std::span<const wgnx::platform::socket_handle> ScriptedPlatform::ClosedSockets() const {
    return m_closed_sockets;
}

const ScriptedPlatform::Statistics& ScriptedPlatform::GetStatistics() const {
    return m_statistics;
}

void ScriptedPlatform::ExecuteEffect(const RuntimeEffect& effect, EffectBatch& generated) {
    std::visit(
        [this, &generated](const auto& value) {
            using Effect = std::remove_cvref_t<decltype(value)>;
            if constexpr (std::is_same_v<Effect, ResolveEndpointEffect>) {
                ++m_statistics.resolve_requests;
                static_cast<void>(m_resolver.Queue(value));
            } else if constexpr (std::is_same_v<Effect, StartNetworkPathRequestEffect>) {
                generated.Append(m_coordinator.Dispatch(
                    NetworkPathRequestStartedEvent{
                        .peer = value.peer,
                        .path_generation = value.path_generation,
                        .success = true,
                        .occurred_at = NextTime(),
                    }
                ));
                generated.Append(m_coordinator.Dispatch(
                    NetworkPathAvailabilityChangedEvent{
                        .peer = value.peer,
                        .path_generation = value.path_generation,
                        .observation =
                            {
                                .availability = wgnx::platform::network_path_availability::available,
                                .raw_state = wgnx::platform::network_path_raw_state::available,
                                .request_generation = value.path_generation.Value(),
                            },
                        .occurred_at = NextTime(),
                    }
                ));
            } else if constexpr (std::is_same_v<Effect, StopNetworkPathRequestEffect>) {
                static_cast<void>(value);
            } else if constexpr (std::is_same_v<Effect, OpenUdpBindEffect>) {
                ++m_statistics.udp_open_requests;
                m_udp_open_requests.push_back(value);
            } else if constexpr (std::is_same_v<Effect, CloseUdpSocketEffect>) {
                if (value.socket != wgnx::platform::InvalidSocket) {
                    ++m_statistics.udp_close_requests;
                    m_closed_sockets.push_back(value.socket);
                }
            } else if constexpr (std::is_same_v<Effect, SendPendingDatagramEffect>) {
                ++m_statistics.udp_send_requests;
                m_udp_send_requests.push_back(value);
            } else if constexpr (std::is_same_v<Effect, QueueReceiveEffect>) {
                ++m_statistics.udp_receive_requests;
                m_udp_receive_requests.push_back(value);
            } else if constexpr (std::is_same_v<Effect, ArmProtocolTimerEffect>) {
                if (m_coordinator.IsCurrentTimerEffect(value)) {
                    static_cast<void>(m_timers.Arm(value.token, value.deadline));
                }
            } else if constexpr (std::is_same_v<Effect, CancelProtocolTimerEffect>) {
                static_cast<void>(m_timers.Cancel(value.token));
            } else if constexpr (std::is_same_v<Effect, QueueInnerPacketSubmissionEffect> ||
                                 std::is_same_v<Effect, PublishDecryptedPacketEffect> ||
                                 std::is_same_v<Effect, ArmDebugProbeTimeoutEffect> ||
                                 std::is_same_v<Effect, CancelDebugProbeTimeoutEffect>) {
                static_cast<void>(generated);
            }
        },
        effect
    );
}

wgnx::platform::endpoint_resolution_result ScriptedPlatform::TakeResolutionResult() {
    if (m_resolution_results.empty()) {
        return DefaultResolutionResult();
    }
    auto result = std::move(m_resolution_results.front());
    m_resolution_results.pop_front();
    return result;
}

ScriptedPlatform::UdpOpenResult ScriptedPlatform::TakeUdpOpenResult() {
    if (m_udp_open_results.empty()) {
        return {.socket = m_next_socket++};
    }
    const UdpOpenResult result = m_udp_open_results.front();
    m_udp_open_results.pop_front();
    return result;
}

ScriptedPlatform::UdpSendResult ScriptedPlatform::TakeUdpSendResult() {
    if (m_udp_send_results.empty()) {
        return {};
    }
    const UdpSendResult result = m_udp_send_results.front();
    m_udp_send_results.pop_front();
    return result;
}

wgnx::platform::ktime_t ScriptedPlatform::NextTime() {
    return ++m_now;
}

} // namespace wgnx::test
