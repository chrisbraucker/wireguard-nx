#include "runtime/runtime_effect_executor.hpp"

#include "runtime/debug_probe_runner.hpp"
#include "runtime/effect_drain.hpp"
#include "runtime/encrypted_receive_pump.hpp"
#include "runtime/endpoint_resolver.hpp"
#include "runtime/horizon_dispatcher.hpp"
#include "runtime/network_path_observer.hpp"
#include "runtime/packet_data_plane.hpp"
#include "runtime/runtime_coordinator.hpp"
#include "runtime/timer_scheduler.hpp"

#include "logger.hpp"
#include "wgnx/platform/clock.hpp"
#include "wgnx/platform/random.hpp"
#include "wgnx/platform/udp.hpp"
#include "wireguard/debug_probe.hpp"
#include "wireguard/inner_packet.hpp"
#include "wireguard/timers.hpp"

#include <array>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <type_traits>

namespace wgnx::sysmodule::runtime {

namespace {

constexpr wgnx::platform::jiffies_t DebugProbeTimeoutJiffies =
    5U * wgnx::platform::HZ;

wgnx::platform::ktime_t GetRuntimeNowNs() {
    return wgnx::platform::ktime_get_coarse_boottime_ns();
}

} // namespace

NOINLINE void RuntimeEffectExecutor::ExecuteOpenUdpBind(
    const OpenUdpBindEffect &effect,
    EffectBatch &generated) {
    wgnx::platform::socket_handle socket = wgnx::platform::InvalidSocket;
    const auto error = wgnx::platform::udp_open(
        std::addressof(socket),
        effect.endpoint.family);
    logger::Log(
        "UDP bind open completion peer=%u activation=%u socket_generation=%u socket=%d endpoint=%s error=%u",
        effect.peer.peer_index.Value(),
        effect.peer.activation_generation.Value(),
        effect.socket_generation.Value(),
        static_cast<int>(socket),
        effect.endpoint_text.data(),
        static_cast<unsigned int>(error));
    const auto timer_facts = CaptureTimerFacts();
    EffectBatch completion{};
    {
        std::scoped_lock lock(m_state_mutex);
        completion = m_coordinator.Dispatch(UdpBindOpenedEvent{
            .peer = effect.peer,
            .endpoint = effect.endpoint,
            .endpoint_text = effect.endpoint_text,
            .socket = socket,
            .error = error,
            .socket_generation = effect.socket_generation,
            .purpose = effect.purpose,
            .timer_facts = timer_facts,
            .occurred_at = GetRuntimeNowNs(),
        });
    }
    generated.Append(completion);
}

NOINLINE void RuntimeEffectExecutor::ExecutePendingDatagramSend(
    const SendPendingDatagramEffect &effect,
    EffectBatch &generated) {
    PendingDatagramSnapshot snapshot{};
    bool snapshot_available = false;
    UdpBinding::Snapshot binding{};
    EffectBatch completion{};
    {
        std::scoped_lock lock(m_state_mutex);
        snapshot_available = m_coordinator.SnapshotPendingDatagram(
            effect.peer,
            effect.datagram_generation,
            snapshot);
        if (!snapshot_available) {
            binding = m_coordinator.BindingSnapshot(effect.peer.peer_index.Value());
        }
    }

    if (!snapshot_available) {
        logger::Log(
            "Abandoned encrypted datagram send peer=%u activation=%u datagram_generation=%u reason=snapshot_rejected binding_open=%u binding_suspended=%u socket_generation=%u socket=%d",
            effect.peer.peer_index.Value(),
            effect.peer.activation_generation.Value(),
            effect.datagram_generation.Value(),
            binding.IsOpen() ? 1U : 0U,
            binding.suspended ? 1U : 0U,
            binding.generation.Value(),
            static_cast<int>(binding.socket));

        {
            std::scoped_lock lock(m_state_mutex);
            completion = m_coordinator.Dispatch(PendingDatagramSentEvent{
                .peer = effect.peer,
                .datagram_generation = effect.datagram_generation,
                .error = wgnx::platform::socket_error::send_failed,
                .occurred_at = GetRuntimeNowNs(),
            });
        }
        generated.Append(completion);
        return;
    }

    std::size_t sent = 0;
    const auto error = wgnx::platform::udp_send(
        snapshot.binding.socket,
        snapshot.binding.endpoint,
        std::span<const std::uint8_t>(snapshot.bytes).first(snapshot.size),
        std::addressof(sent));
    logger::Log(
        "Encrypted datagram send completion peer=%u activation=%u datagram_generation=%u kind=%s packet_id=%llu bytes=%zu sent=%zu socket_generation=%u socket=%d error=%u",
        effect.peer.peer_index.Value(),
        effect.peer.activation_generation.Value(),
        effect.datagram_generation.Value(),
        GetPendingDatagramKindName(snapshot.kind),
        static_cast<unsigned long long>(snapshot.inner_packet_id.Value()),
        snapshot.size,
        sent,
        snapshot.binding.generation.Value(),
        static_cast<int>(snapshot.binding.socket),
        static_cast<unsigned int>(error));

    {
        std::scoped_lock lock(m_state_mutex);
        completion = m_coordinator.Dispatch(PendingDatagramSentEvent{
            .peer = effect.peer,
            .datagram_generation = effect.datagram_generation,
            .bytes_sent = sent,
            .error = error,
            .occurred_at = GetRuntimeNowNs(),
        });
    }
    generated.Append(completion);
}

NOINLINE void RuntimeEffectExecutor::ExecutePublishDecryptedPacket(
    const PublishDecryptedPacketEffect &effect) {
    bool cancel_debug_timeout = false;
    {
        std::scoped_lock lock(m_state_mutex);
        DecryptedPacketView view{};
        if (m_coordinator.ViewDecryptedPacket(
                effect.peer,
                effect.packet_generation,
                view)) {
            cancel_debug_timeout = PublishDecryptedPacketLocked(effect.peer, view.packet);
        }
    }
    if (cancel_debug_timeout) {
        m_timer_scheduler.CancelDebugProbeTimeout();
    }
}

void RuntimeEffectExecutor::Execute(const EffectBatch &effects) {
    ON_SCOPE_EXIT { logger::Flush(); };
    DrainEffectBatches(
        effects,
        [this](const RuntimeEffect &effect, EffectBatch &generated) {
            std::visit(
                [this, &generated](const auto &value) {
                    using Effect = std::remove_cvref_t<decltype(value)>;
                    if constexpr (std::is_same_v<Effect, ResolveEndpointEffect>) {
                        bool current = false;
                        bool schedule = false;
                        {
                            std::scoped_lock lock(m_state_mutex);
                            current = m_coordinator.IsActiveIdentity(value.peer);
                            if (current) {
                                schedule =
                                    m_endpoint_resolver.Queue(value) ==
                                    EndpointQueueResult::Scheduled;
                            }
                        }
                        if (current) {
                            logger::Log(
                                "Queued endpoint resolution for peer %u activation=%u endpoint='%s' schedule=%u",
                                value.peer.peer_index.Value(),
                                value.peer.activation_generation.Value(),
                                value.endpoint.data(),
                                schedule ? 1U : 0U);
                        }
                        if (schedule) {
                            m_dispatcher.QueueResolve();
                        }
                    } else if constexpr (std::is_same_v<Effect, OpenUdpBindEffect>) {
                        ExecuteOpenUdpBind(value, generated);
                    } else if constexpr (std::is_same_v<Effect, CloseUdpSocketEffect>) {
                        if (value.socket != wgnx::platform::InvalidSocket) {
                            wgnx::platform::udp_close(value.socket);
                        }
                    } else if constexpr (std::is_same_v<Effect, SendPendingDatagramEffect>) {
                        ExecutePendingDatagramSend(value, generated);
                    } else if constexpr (std::is_same_v<Effect, QueueReceiveEffect>) {
                        bool current = false;
                        {
                            std::scoped_lock lock(m_state_mutex);
                            current = m_coordinator.IsActiveTransportIdentity(value.peer);
                        }
                        if (current) {
                            m_receive_pump.Queue();
                        }
                    } else if constexpr (std::is_same_v<Effect, ArmProtocolTimerEffect>) {
                        bool current = false;
                        {
                            std::scoped_lock lock(m_state_mutex);
                            current = m_coordinator.IsCurrentTimerEffect(value);
                        }
                        if (current) {
                            m_timer_scheduler.ArmProtocolTimer(
                                value.token,
                                value.deadline);
                        }
                    } else if constexpr (std::is_same_v<Effect, CancelProtocolTimerEffect>) {
                        m_timer_scheduler.CancelProtocolTimer(value.token);
                    } else if constexpr (std::is_same_v<Effect, QueueInnerPacketSubmissionEffect>) {
                        bool current = false;
                        {
                            std::scoped_lock lock(m_state_mutex);
                            current =
                                m_coordinator.IsActiveEstablishedIdentity(value.peer);
                        }
                        if (current) {
                            m_dispatcher.QueueInnerPacketSubmission();
                        }
                    } else if constexpr (std::is_same_v<Effect, PublishDecryptedPacketEffect>) {
                        ExecutePublishDecryptedPacket(value);
                    } else if constexpr (std::is_same_v<Effect, ArmDebugProbeTimeoutEffect>) {
                        bool current = false;
                        {
                            std::scoped_lock lock(m_state_mutex);
                            current = m_debug_probe_runner.Peer() == value.peer &&
                                      m_debug_probe_runner.Status() == wgnx::DebugProbeStatus::Sent;
                        }
                        if (current) {
                            m_timer_scheduler.ArmDebugProbeTimeout(value.deadline);
                        }
                    } else if constexpr (std::is_same_v<Effect, CancelDebugProbeTimeoutEffect>) {
                        m_timer_scheduler.CancelDebugProbeTimeout();
                    }
                },
                effect);
        });
}

bool RuntimeEffectExecutor::PublishDecryptedPacketLocked(
    const PeerIdentity &peer,
    std::span<const std::uint8_t> inner_packet) {
    const auto probe = m_debug_probe_runner.HandleDecryptedPacket(
        peer,
        inner_packet,
        GetRuntimeNowNs());
    if (probe.consumed) {
        // The concrete cancellation runs after the caller releases the daemon lock.
    }
    if (probe.validation == wgnx::wireguard::DebugProbeReplyValidation::Valid) {
        char inner_source[16] = {};
        char inner_destination[16] = {};
        wgnx::wireguard::FormatIpv4Text(
            probe.info.source_ipv4,
            inner_source,
            sizeof(inner_source));
        wgnx::wireguard::FormatIpv4Text(
            probe.info.destination_ipv4,
            inner_destination,
            sizeof(inner_destination));
        logger::Log(
            "Validated debug ICMP reply for peer %u action=%s source=%s destination=%s seq=%u activation=%u",
            peer.peer_index.Value(),
            wgnx::GetDebugTriggerActionName(probe.info.action),
            inner_source,
            inner_destination,
            static_cast<unsigned int>(probe.info.sequence),
            probe.info.activation_generation);
        return true;
    }

    if (probe.consumed) {
        logger::Log(
            "Rejected debug ICMP reply metadata for peer %u validation=%s payload=%zu",
            peer.peer_index.Value(),
            wgnx::wireguard::GetDebugProbeReplyValidationName(probe.validation),
            inner_packet.size());
        return true;
    }

    const auto delivery = m_packet_data_plane.DeliverDecryptedPacket(peer, inner_packet);
    switch (delivery.status) {
        case PacketDeliveryStatus::Queued:
            logger::Log(
                "Queued decrypted inner packet id=%llu peer=%u activation=%u bytes=%zu depth=%zu",
                static_cast<unsigned long long>(delivery.packet_id.Value()),
                peer.peer_index.Value(),
                peer.activation_generation.Value(),
                inner_packet.size(),
                delivery.queue_depth);
            break;
        case PacketDeliveryStatus::NoConsumer:
            logger::Log(
                "Dropped decrypted inner packet peer=%u activation=%u bytes=%zu reason=no_consumer",
                peer.peer_index.Value(),
                peer.activation_generation.Value(),
                inner_packet.size());
            break;
        case PacketDeliveryStatus::MalformedPacket:
            logger::Log(
                "Dropped decrypted inner packet peer=%u activation=%u bytes=%zu validation=%s",
                peer.peer_index.Value(),
                peer.activation_generation.Value(),
                inner_packet.size(),
                wgnx::wireguard::GetInnerIpValidationErrorName(delivery.validation));
            break;
        case PacketDeliveryStatus::UnsupportedPacket:
            logger::Log(
                "Dropped decrypted inner packet peer=%u activation=%u bytes=%zu reason=unsupported_transport_ip_version version=%u",
                peer.peer_index.Value(),
                peer.activation_generation.Value(),
                inner_packet.size(),
                static_cast<unsigned int>(delivery.version));
            break;
        case PacketDeliveryStatus::QueueFull:
            logger::Log(
                "Dropped decrypted inner packet peer=%u activation=%u bytes=%zu reason=rx_queue_full capacity=%zu",
                peer.peer_index.Value(),
                peer.activation_generation.Value(),
                inner_packet.size(),
                delivery.queue_capacity);
            break;
        case PacketDeliveryStatus::StalePeer:
            break;
    }
    return probe.consumed;
}

bool RuntimeEffectExecutor::TakeDebugPayloadSubmission(
    DebugProbeRequest &out_request) {
    std::scoped_lock lock(m_state_mutex);
    return m_debug_probe_runner.TakePending(out_request);
}

void RuntimeEffectExecutor::CommitDebugPayloadSubmission(
    const DebugProbeRequest &request) {
    EffectBatch effects{};
    const auto timer_facts = CaptureTimerFacts();
    const auto random_seed = wgnx::platform::get_random_u32_below(
        std::numeric_limits<std::uint32_t>::max());
    const auto debug_timeout_deadline =
        wgnx::platform::get_jiffies_64() + DebugProbeTimeoutJiffies;
    std::unique_lock lock(m_state_mutex);
    if (!m_coordinator.IsActiveIdentity(request.peer)) {
        static_cast<void>(m_debug_probe_runner.MarkFailed(
            request,
            wgnx::DebugProbeStatus::StaleActivation,
            GetRuntimeNowNs()));
        logger::Log(
            "Discarded queued payload submission for stale peer %u activation=%u",
            request.peer.peer_index.Value(),
            request.peer.activation_generation.Value());
        return;
    }

    const auto *lifecycle =
        m_coordinator.Lifecycle(request.peer.peer_index.Value());
    const auto binding =
        m_coordinator.BindingSnapshot(request.peer.peer_index.Value());
    AMS_ABORT_UNLESS(lifecycle != nullptr);
    if (!m_coordinator.IsActiveEstablishedIdentity(request.peer) ||
        !binding.IsOpen()) {
        static_cast<void>(m_debug_probe_runner.MarkFailed(
            request,
            lifecycle->activation_generation == request.peer.activation_generation
                ? wgnx::DebugProbeStatus::InvalidState
                : wgnx::DebugProbeStatus::StaleActivation,
            GetRuntimeNowNs()));
        logger::Log(
            "Discarded queued payload submission for peer %u state=%s activation=%u current_activation=%u",
            request.peer.peer_index.Value(),
            wgnx::GetPeerRuntimeStateName(lifecycle->state),
            request.peer.activation_generation.Value(),
            lifecycle->activation_generation.Value());
        return;
    }

    std::array<std::uint8_t, wgnx::wireguard::DebugProbePacketSize> payload{};
    const std::size_t payload_size = m_debug_probe_runner.BuildPacket(
        request,
        payload,
        random_seed);
    if (payload_size == 0) {
        char target_text[16] = {};
        std::array<std::uint8_t, 4> target_ipv4{};
        wgnx::wireguard::CopyDebugTargetIpv4(request.action, target_ipv4);
        wgnx::wireguard::FormatIpv4Text(
            target_ipv4,
            target_text,
            sizeof(target_text));
        static_cast<void>(m_debug_probe_runner.MarkFailed(
            request,
            wgnx::DebugProbeStatus::BuildFailed,
            GetRuntimeNowNs()));
        logger::Log(
            "Failed to build debug ICMP packet for peer %u activation=%u action=%s source=%s target=%s",
            request.peer.peer_index.Value(),
            request.peer.activation_generation.Value(),
            wgnx::GetDebugTriggerActionName(request.action),
            request.source_address.data(),
            target_text);
        return;
    }

    char target_text[16] = {};
    std::array<std::uint8_t, 4> target_ipv4{};
    wgnx::wireguard::CopyDebugTargetIpv4(request.action, target_ipv4);
    wgnx::wireguard::FormatIpv4Text(
        target_ipv4,
        target_text,
        sizeof(target_text));
    logger::Log(
        "Built debug ICMP packet for peer %u activation=%u action=%s source=%s target=%s bytes=%zu",
        request.peer.peer_index.Value(),
        request.peer.activation_generation.Value(),
        wgnx::GetDebugTriggerActionName(request.action),
        request.source_address.data(),
        target_text,
        payload_size);
    const auto submission = m_packet_data_plane.SubmitInternalIpPacket(
        std::span<const std::uint8_t>(payload.data(), payload_size),
        timer_facts,
        GetRuntimeNowNs(),
        effects);
    if (submission.status != PacketSubmissionStatus::Queued) {
        static_cast<void>(m_debug_probe_runner.MarkFailed(
            request,
            wgnx::DebugProbeStatus::SendFailed,
            GetRuntimeNowNs()));
        logger::Log(
            "Failed to stage debug payload peer=%u activation=%u status=%u",
            request.peer.peer_index.Value(),
            request.peer.activation_generation.Value(),
            static_cast<unsigned int>(submission.status));
        return;
    }

    static_cast<void>(m_debug_probe_runner.MarkSent(request, GetRuntimeNowNs()));
    effects.Add(ArmDebugProbeTimeoutEffect{
        .peer = request.peer,
        .deadline = debug_timeout_deadline,
    });
    lock.unlock();
    Execute(effects);
}

void RuntimeEffectExecutor::RunDebugPayloadSubmission() {
    ON_SCOPE_EXIT { logger::Flush(); };
    DebugProbeRequest request{};
    while (TakeDebugPayloadSubmission(request)) {
        CommitDebugPayloadSubmission(request);
    }
}

void RuntimeEffectExecutor::RunInnerPacketSubmission() {
    ON_SCOPE_EXIT { logger::Flush(); };
    EffectBatch effects{};
    const auto timer_facts = CaptureTimerFacts();
    {
        std::scoped_lock lock(m_state_mutex);
        PeerPacketStateSnapshot peer{};
        if (!m_coordinator.SnapshotPacketState(peer)) {
            return;
        }
        effects = m_coordinator.Dispatch(ProcessOutboundQueueEvent{
            .peer = peer.identity,
            .timer_facts = timer_facts,
            .occurred_at = GetRuntimeNowNs(),
        });
    }
    Execute(effects);
}

void RuntimeEffectExecutor::RunEndpointResolver() {
    ON_SCOPE_EXIT { logger::Flush(); };
    while (true) {
        std::optional<ResolveEndpointEffect> request{};
        {
            std::scoped_lock lock(m_state_mutex);
            request = m_endpoint_resolver.Take();
            if (!request.has_value()) {
                m_endpoint_resolver.MarkWorkerIdle();
            }
        }
        if (!request.has_value()) {
            return;
        }

        const auto result =
            wgnx::platform::resolve_endpoint(request->endpoint.data());
        logger::Log(
            "Endpoint resolution completion peer=%u activation=%u endpoint='%s' success=%u stage=%s code=%s resolved=%s",
            request->peer.peer_index.Value(),
            request->peer.activation_generation.Value(),
            request->endpoint.data(),
            result.success ? 1U : 0U,
            wgnx::GetPeerErrorStageName(result.error_stage),
            wgnx::GetPeerErrorCodeName(result.error_code),
            result.text.data());
        EffectBatch effects{};
        {
            std::scoped_lock lock(m_state_mutex);
            effects = m_coordinator.Dispatch(EndpointResolvedEvent{
                .peer = request->peer,
                .result = result,
                .occurred_at = GetRuntimeNowNs(),
            });
        }
        Execute(effects);
    }
}

void RuntimeEffectExecutor::RunProtocolTimer(
    wgnx::wireguard::TimerHook hook,
    const wgnx::wireguard::TimerToken &token) {
    ON_SCOPE_EXIT { logger::Flush(); };
    const auto timer_facts = CaptureTimerFacts();
    std::unique_lock lock(m_state_mutex);
    if (!token.IsValid() || token.hook != hook ||
        token.owner.peer_index >= m_coordinator.PeerCount()) {
        return;
    }

    const EffectBatch effects = m_coordinator.Dispatch(
        ProtocolTimerExpiredEvent{
            .peer = {
                .peer_index = PeerIndex{token.owner.peer_index},
                .activation_generation =
                    ActivationGeneration{token.owner.activation_generation},
            },
            .hook = hook,
            .token = token,
            .timer_facts = timer_facts,
            .occurred_at = GetRuntimeNowNs(),
        });
    lock.unlock();
    Execute(effects);
}

void RuntimeEffectExecutor::RunDebugProbeTimeout() {
    ON_SCOPE_EXIT { logger::Flush(); };
    std::scoped_lock lock(m_state_mutex);
    const auto peer = m_debug_probe_runner.Peer();
    const auto action = m_debug_probe_runner.Action();
    if (!m_debug_probe_runner.HandleTimeout(GetRuntimeNowNs())) {
        return;
    }
    logger::Log(
        "Debug payload probe timed out for peer %u action=%s activation=%u",
        peer.peer_index.Value(),
        wgnx::GetDebugTriggerActionName(action),
        peer.activation_generation.Value());
}

void RuntimeEffectExecutor::RunNetworkPathObservation() {
    ON_SCOPE_EXIT { logger::Flush(); };
    bool has_active_transport = false;
    {
        std::scoped_lock lock(m_state_mutex);
        has_active_transport = m_coordinator.ActivePeerIndex() >= 0;
    }
    if (!has_active_transport) {
        return;
    }

    const auto sequence = m_network_path_observer.BeginObservation();
    const auto snapshot = wgnx::platform::sample_network_path(sequence);
    static_cast<void>(m_network_path_observer.Commit({
        .sequence = sequence,
        .snapshot = snapshot,
    }));
}

} // namespace wgnx::sysmodule::runtime
