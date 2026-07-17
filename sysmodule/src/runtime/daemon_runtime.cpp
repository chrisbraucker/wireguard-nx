#include "runtime/daemon_runtime.hpp"
#include "runtime/debug_probe_runner.hpp"
#include "runtime/endpoint_resolver.hpp"
#include "runtime/horizon_dispatcher.hpp"
#include "runtime/network_path_observer.hpp"
#include "runtime/packet_channel.hpp"
#include "runtime/packet_data_plane.hpp"
#include "runtime/peer_configuration.hpp"
#include "runtime/peer_runtime.hpp"
#include "runtime/runtime_coordinator.hpp"
#include "runtime/runtime_contracts.hpp"
#include "runtime/timer_scheduler.hpp"
#include "runtime/udp_binding.hpp"

#include "config_loader.hpp"
#include "development_config.hpp"
#include "logger.hpp"
#include "wgnx/platform/clock.hpp"
#include "wgnx/platform/packet.hpp"
#include "wgnx/platform/random.hpp"
#include "wgnx/platform/udp.hpp"
#include "wgnx/platform/work.hpp"
#include "wireguard/data.hpp"
#include "wireguard/device.hpp"
#include "wireguard/handshake.hpp"
#include "wireguard/inner_packet.hpp"
#include "wireguard/peer_controller.hpp"
#include "wireguard/session.hpp"
#include "wireguard/timer_coordinator.hpp"
#include "wireguard/timers.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mutex>
#include <span>
#include <type_traits>

namespace wgnx::sysmodule {

namespace {

struct DaemonState {
    runtime::PeerRegistry peers{};
    bool initialized{false};
};

constexpr inline wgnx::platform::jiffies_t DebugProbeTimeoutJiffies = 5U * wgnx::platform::HZ;
constexpr inline wgnx::platform::jiffies_t NetworkPathObservationJiffies = 2U * wgnx::platform::HZ;
constexpr inline std::size_t ReceivePacketCapacity = 4096;

class DaemonRuntime {
public:
    DaemonRuntime();

    void Initialize();
    wgnx::DaemonStatus GetDaemonStatus();
    std::uint32_t CopyPeers(std::span<wgnx::PeerInfo> out);
    ams::Result SetActivePeer(std::int32_t peer_index);
    ams::Result SetAutoStartPeer(std::int32_t peer_index);
    ams::Result TriggerDebugPayload(wgnx::DebugTriggerAction action);
    ams::Result BumpUdpBinding();
    wgnx::PacketSubmissionResult SubmitInnerIpv4Packet(
        std::span<const std::uint8_t> packet,
        std::uint64_t process_id);
    wgnx::PacketReceiveResult ReceiveInnerIpv4Packet(
        std::span<std::uint8_t> packet,
        std::uint64_t process_id);

private:
    static void ResolverWorkCallback(wgnx::platform::work_struct *work);
    static void PayloadSubmissionWorkCallback(wgnx::platform::work_struct *work);
    static void InnerPacketSubmissionWorkCallback(wgnx::platform::work_struct *work);
    static void ReceiveWorkCallback(wgnx::platform::work_struct *work);
    static void ProtocolTimerCallback(
        wgnx::wireguard::TimerHook hook,
        const wgnx::wireguard::TimerToken &token);
    static void DebugProbeTimeoutCallback();
    static void NetworkPathObserverCallback();

    void SchedulePayloadProbeTimeout();
    void CancelPayloadProbeTimeout();
    void ClearInnerPacketStateLocked(const char *reason);
    runtime::EffectBatch SetPeerInactive(std::size_t peer_index);
    void QueueReceiveWork();
    void QueuePayloadSubmissionWork();
    void QueueInnerPacketSubmissionWork();
    bool QueuePayloadSubmissionRequestLocked(wgnx::DebugTriggerAction action);
    wgnx::PeerInfo BuildPeerInfo(std::size_t peer_index);
    bool HasRuntimeErrors();
    void InitializeState();
    bool IsValidPeerIndex(std::int32_t peer_index);
    bool DequeuePayloadSubmissionRequest(runtime::DebugProbeRequest *out_request);
    bool SnapshotReceiveRuntime(
        std::size_t *out_peer_index,
        std::uint32_t *out_activation_generation,
        std::uint32_t *out_socket_generation,
        wgnx::platform::socket_handle *out_socket);
    NOINLINE void ExecuteOpenUdpBindEffect(
        const runtime::OpenUdpBindEffect &effect,
        runtime::EffectBatch &generated);
    NOINLINE void ExecutePendingDatagramSendEffect(
        const runtime::SendPendingDatagramEffect &effect,
        runtime::EffectBatch &generated);
    NOINLINE void ExecutePublishDecryptedPacketEffect(
        const runtime::PublishDecryptedPacketEffect &effect);
    void ExecuteRuntimeEffects(const runtime::EffectBatch &effects);
    void PublishDecryptedPacketLocked(
        std::size_t peer_index,
        std::uint32_t activation_generation,
        std::span<const std::uint8_t> inner_packet);
    void CommitPayloadSubmission(const runtime::DebugProbeRequest &request);
    void ResolverWorkMain(wgnx::platform::work_struct *work);
    void ProcessPendingBindBump();
    NOINLINE void CommitReceivedPacket(
        std::size_t peer_index,
        std::uint32_t activation_generation,
        std::uint32_t socket_generation,
        wgnx::platform::socket_handle socket,
        std::span<const std::uint8_t> packet,
        const wgnx::platform::endpoint &source,
        runtime::EffectBatch &effects);
    void CommitReceiveFailure(
        std::size_t peer_index,
        std::uint32_t activation_generation,
        std::uint32_t socket_generation,
        wgnx::platform::socket_handle socket,
        wgnx::platform::socket_error error);
    void ReceiveWorkMain(wgnx::platform::work_struct *work);
    void PayloadSubmissionWorkMain(wgnx::platform::work_struct *work);
    void InnerPacketSubmissionWorkMain(wgnx::platform::work_struct *work);
    void CommitPayloadProbeTimeout();
    void RunTimerAction(
        wgnx::wireguard::TimerHook hook,
        const wgnx::wireguard::TimerToken &token);
    void NetworkPathObserverWorkMain(wgnx::platform::work_struct *work);
    void InitializeHorizonDispatcher();

    static DaemonRuntime *s_instance;
    DaemonState m_state{};
    ams::os::Mutex m_state_mutex;
    runtime::EndpointResolver m_endpoint_resolver{};
    runtime::UdpRebindQueue m_rebind_requests{};
    runtime::HorizonDispatcher m_horizon_dispatcher{};
    runtime::TimerScheduler m_timer_scheduler{};
    runtime::PacketChannel m_packet_channel{};
    runtime::RuntimeCoordinator m_runtime_coordinator;
    runtime::PacketDataPlane m_packet_data_plane;
    runtime::DebugProbeRunner m_debug_probe_runner{};
    runtime::NetworkPathObserver m_network_path_observer{};
    runtime::PeerConfigurationLoader m_peer_configuration_loader{};
    runtime::LoadedPeerConfiguration m_loaded_peer_configuration{};
    std::array<std::uint8_t, ReceivePacketCapacity> m_receive_packet_storage{};
    runtime::EffectBatch m_receive_effects{};
};

DaemonRuntime *DaemonRuntime::s_instance = nullptr;

DaemonRuntime::DaemonRuntime()
    : m_state_mutex(false),
      m_runtime_coordinator(m_state.peers),
      m_packet_data_plane(m_runtime_coordinator, m_packet_channel) {
    AMS_ABORT_UNLESS(s_instance == nullptr);
    s_instance = this;
}

template<std::size_t Size>
const char *CStr(const std::array<char, Size> &value) {
    return value.data();
}

void FormatEndpointText(
    const wgnx::platform::endpoint &endpoint,
    char *out_text,
    std::size_t out_text_size) {
    if (out_text == nullptr || out_text_size == 0) {
        return;
    }

    if (!wgnx::platform::endpoint_to_string(endpoint, std::span<char>(out_text, out_text_size))) {
        std::snprintf(out_text, out_text_size, "<invalid>");
    }
}

wgnx::platform::ktime_t GetRuntimeNowNs() {
    return wgnx::platform::ktime_get_coarse_boottime_ns();
}

 [[maybe_unused]] void DaemonRuntime::SchedulePayloadProbeTimeout() {
    m_timer_scheduler.ArmDebugProbeTimeout(
        wgnx::platform::get_jiffies_64() + DebugProbeTimeoutJiffies);
}

void DaemonRuntime::CancelPayloadProbeTimeout() {
    m_timer_scheduler.CancelDebugProbeTimeout();
}

void DaemonRuntime::ClearInnerPacketStateLocked(const char *reason) {
    const auto cleared = m_packet_data_plane.Clear();
    if (cleared.outbound_count != 0 || cleared.inbound_count != 0) {
        logger::Log(
            "Cleared inner packet state reason=%s tx=%zu rx=%zu",
            reason != nullptr ? reason : "unspecified",
            cleared.outbound_count,
            cleared.inbound_count);
    }
}

runtime::EffectBatch DaemonRuntime::SetPeerInactive(std::size_t peer_index) {
    CancelPayloadProbeTimeout();
    const auto *lifecycle = m_runtime_coordinator.Lifecycle(peer_index);
    AMS_ABORT_UNLESS(lifecycle != nullptr);
    const runtime::PeerIdentity peer{
        .peer_index = static_cast<std::uint32_t>(peer_index),
        .activation_generation = lifecycle->activation_generation,
    };
    m_debug_probe_runner.Cancel(&peer);
    ClearInnerPacketStateLocked("peer inactive");
    return m_runtime_coordinator.Dispatch(runtime::DeactivationRequestedEvent{
        .peer = peer,
        .occurred_at = GetRuntimeNowNs(),
    });
}

void DaemonRuntime::QueueReceiveWork() {
    m_horizon_dispatcher.QueueReceive();
}

[[maybe_unused]] void DaemonRuntime::QueuePayloadSubmissionWork() {
    m_horizon_dispatcher.QueueDebugPayloadSubmission();
}

void DaemonRuntime::QueueInnerPacketSubmissionWork() {
    m_horizon_dispatcher.QueueInnerPacketSubmission();
}

[[maybe_unused]] bool DaemonRuntime::QueuePayloadSubmissionRequestLocked(wgnx::DebugTriggerAction action) {
    runtime::DebugPeerSnapshot peer{};
    if (!m_runtime_coordinator.SnapshotDebugPeer(peer)) {
        return false;
    }
    return m_debug_probe_runner.Queue(
        peer.peer,
        peer.source_address.data(),
        action,
        GetRuntimeNowNs());
}

wgnx::PeerInfo DaemonRuntime::BuildPeerInfo(std::size_t peer_index) {
    const auto now = GetRuntimeNowNs();
    auto info = m_runtime_coordinator.BuildPeerInfo(peer_index, now);
    m_debug_probe_runner.Project(static_cast<std::uint32_t>(peer_index), now, info);
    return info;
}

bool DaemonRuntime::HasRuntimeErrors() {
    return m_runtime_coordinator.HasRuntimeErrors();
}

void DaemonRuntime::InitializeState() {
    if (m_state.initialized) {
        return;
    }

    auto &config = m_loaded_peer_configuration;
    if (m_peer_configuration_loader.Load(config)) {
        const bool assigned = m_runtime_coordinator.Configure(
            std::span<const wgnx::PeerConfigEntry>(config.peers).first(config.peer_count),
            std::span<runtime::PeerConfigDerivedInfo>(config.derived).first(config.peer_count),
            config.auto_start_peer_index,
            GetRuntimeNowNs());
        AMS_ABORT_UNLESS(assigned);
    } else {
        m_runtime_coordinator.ClearConfiguration(GetRuntimeNowNs());
    }
    config.~LoadedPeerConfiguration();
    std::construct_at(std::addressof(config));

    m_state.initialized = true;
    logger::Log(
        "Initialized peer state with %u configured peer(s)",
        m_runtime_coordinator.PeerCount());
}

bool DaemonRuntime::IsValidPeerIndex(std::int32_t peer_index) {
    return m_runtime_coordinator.IsValidSelection(peer_index);
}

[[maybe_unused]] bool DaemonRuntime::DequeuePayloadSubmissionRequest(runtime::DebugProbeRequest *out_request) {
    std::scoped_lock lock(m_state_mutex);
    if (out_request == nullptr) {
        return false;
    }
    return m_debug_probe_runner.TakePending(*out_request);
}

bool DaemonRuntime::SnapshotReceiveRuntime(
    std::size_t *out_peer_index,
    std::uint32_t *out_activation_generation,
    std::uint32_t *out_socket_generation,
    wgnx::platform::socket_handle *out_socket) {
    if (out_peer_index == nullptr || out_activation_generation == nullptr ||
        out_socket_generation == nullptr || out_socket == nullptr) {
        return false;
    }

    std::scoped_lock lock(m_state_mutex);
    runtime::ReceiveRuntimeSnapshot snapshot{};
    if (!m_runtime_coordinator.SnapshotReceiveRuntime(snapshot)) {
        return false;
    }

    *out_peer_index = snapshot.peer.peer_index;
    *out_activation_generation = snapshot.peer.activation_generation;
    *out_socket_generation = snapshot.socket_generation;
    *out_socket = snapshot.socket;
    return true;
}

NOINLINE void DaemonRuntime::ExecuteOpenUdpBindEffect(
    const runtime::OpenUdpBindEffect &effect,
    runtime::EffectBatch &generated) {
    wgnx::platform::socket_handle socket = wgnx::platform::InvalidSocket;
    const auto error = wgnx::platform::udp_open(
        std::addressof(socket),
        effect.endpoint.family);
    logger::Log(
        "UDP bind open completion peer=%u activation=%u socket_generation=%u socket=%d endpoint=%s error=%u",
        effect.peer.peer_index,
        effect.peer.activation_generation,
        effect.socket_generation,
        static_cast<int>(socket),
        effect.endpoint_text.data(),
        static_cast<unsigned int>(error));
    const auto retry_deadline =
        wgnx::wireguard::TimerDeadlineFromJiffies(
            wgnx::platform::get_jiffies_64()) +
        wgnx::wireguard::GetHandshakeRetryDelay(
            wgnx::platform::get_random_u32_below(
                wgnx::wireguard::RekeyTimeoutJitterMaxMs));
    runtime::EffectBatch completion{};
    {
        std::scoped_lock lock(m_state_mutex);
        completion = m_runtime_coordinator.Dispatch(runtime::UdpBindOpenedEvent{
            .peer = effect.peer,
            .endpoint = effect.endpoint,
            .endpoint_text = effect.endpoint_text,
            .socket = socket,
            .error = error,
            .socket_generation = effect.socket_generation,
            .purpose = effect.purpose,
            .retry_deadline = retry_deadline,
            .occurred_at = GetRuntimeNowNs(),
        });
    }
    AMS_ABORT_UNLESS(generated.Append(completion));
}

NOINLINE void DaemonRuntime::ExecutePendingDatagramSendEffect(
    const runtime::SendPendingDatagramEffect &effect,
    runtime::EffectBatch &generated) {
    runtime::PendingDatagramSnapshot snapshot{};
    bool current = false;
    {
        std::scoped_lock lock(m_state_mutex);
        current = m_runtime_coordinator.SnapshotPendingDatagram(
            effect.peer,
            effect.datagram_generation,
            snapshot);
    }
    if (!current) {
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
        effect.peer.peer_index,
        effect.peer.activation_generation,
        effect.datagram_generation,
        runtime::GetPendingDatagramKindName(snapshot.kind),
        static_cast<unsigned long long>(snapshot.inner_packet_id),
        snapshot.size,
        sent,
        snapshot.binding.generation,
        static_cast<int>(snapshot.binding.socket),
        static_cast<unsigned int>(error));
    runtime::EffectBatch completion{};
    {
        std::scoped_lock lock(m_state_mutex);
        completion = m_runtime_coordinator.Dispatch(runtime::PendingDatagramSentEvent{
            .peer = effect.peer,
            .datagram_generation = effect.datagram_generation,
            .bytes_sent = sent,
            .error = error,
            .occurred_at = GetRuntimeNowNs(),
        });
    }
    AMS_ABORT_UNLESS(generated.Append(completion));
}

NOINLINE void DaemonRuntime::ExecutePublishDecryptedPacketEffect(
    const runtime::PublishDecryptedPacketEffect &effect) {
    std::scoped_lock lock(m_state_mutex);
    runtime::DecryptedPacketView view{};
    if (m_runtime_coordinator.ViewDecryptedPacket(
            effect.peer,
            effect.packet_generation,
            view)) {
        PublishDecryptedPacketLocked(
            effect.peer.peer_index,
            effect.peer.activation_generation,
            view.packet);
    }
}

void DaemonRuntime::ExecuteRuntimeEffects(const runtime::EffectBatch &effects) {
    runtime::EffectBatch current = effects;
    while (!current.Empty()) {
        runtime::EffectBatch generated{};
        for (const auto &effect : current) {
            std::visit(
                [this, &generated](const auto &value) {
                    using Effect = std::remove_cvref_t<decltype(value)>;
                    if constexpr (std::is_same_v<Effect, runtime::ResolveEndpointEffect>) {
                        bool current = false;
                        bool schedule = false;
                        {
                            std::scoped_lock lock(m_state_mutex);
                            current = m_runtime_coordinator.IsActiveIdentity(value.peer);
                            if (current) {
                                schedule = m_endpoint_resolver.Queue(value);
                            }
                        }
                        if (current) {
                            logger::Log(
                                "Queued endpoint resolution for peer %u activation=%u endpoint='%s' schedule=%u",
                                value.peer.peer_index,
                                value.peer.activation_generation,
                                value.endpoint.data(),
                                schedule ? 1U : 0U);
                        }
                        if (schedule) {
                            m_horizon_dispatcher.QueueResolve();
                        }
                    } else if constexpr (std::is_same_v<Effect, runtime::OpenUdpBindEffect>) {
                        ExecuteOpenUdpBindEffect(value, generated);
                    } else if constexpr (std::is_same_v<Effect, runtime::CloseUdpSocketEffect>) {
                        if (value.socket != wgnx::platform::InvalidSocket) {
                            wgnx::platform::udp_close(value.socket);
                        }
                    } else if constexpr (std::is_same_v<Effect, runtime::SendPendingDatagramEffect>) {
                        ExecutePendingDatagramSendEffect(value, generated);
                    } else if constexpr (std::is_same_v<Effect, runtime::QueueReceiveEffect>) {
                        bool current = false;
                        {
                            std::scoped_lock lock(m_state_mutex);
                            current =
                                m_runtime_coordinator.IsActiveTransportIdentity(value.peer);
                        }
                        if (current) {
                            QueueReceiveWork();
                        }
                    } else if constexpr (std::is_same_v<Effect, runtime::ArmProtocolTimerEffect>) {
                        bool current = false;
                        {
                            std::scoped_lock lock(m_state_mutex);
                            current = m_runtime_coordinator.IsCurrentTimerEffect(value);
                        }
                        if (current) {
                            m_timer_scheduler.ArmProtocolTimer(
                                value.token,
                                value.deadline);
                        }
                    } else if constexpr (std::is_same_v<Effect, runtime::CancelProtocolTimerEffect>) {
                        m_timer_scheduler.CancelProtocolTimer(value.token);
                    } else if constexpr (std::is_same_v<Effect, runtime::QueueInnerPacketSubmissionEffect>) {
                        bool current = false;
                        {
                            std::scoped_lock lock(m_state_mutex);
                            current =
                                m_runtime_coordinator.IsActiveEstablishedIdentity(value.peer);
                        }
                        if (current) {
                            QueueInnerPacketSubmissionWork();
                        }
                    } else if constexpr (std::is_same_v<Effect, runtime::PublishDecryptedPacketEffect>) {
                        ExecutePublishDecryptedPacketEffect(value);
                    }
                },
                effect);
        }
        current = generated;
    }
}

void DaemonRuntime::PublishDecryptedPacketLocked(
    std::size_t peer_index,
    std::uint32_t activation_generation,
    std::span<const std::uint8_t> inner_packet) {
    const auto probe = m_debug_probe_runner.HandleDecryptedPacket(
        {
            .peer_index = static_cast<std::uint32_t>(peer_index),
            .activation_generation = activation_generation,
        },
        inner_packet,
        GetRuntimeNowNs());
    if (probe.consumed) {
        CancelPayloadProbeTimeout();
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
            "Validated debug ICMP reply for peer %zu action=%s source=%s destination=%s seq=%u activation=%u",
            peer_index,
            wgnx::GetDebugTriggerActionName(probe.info.action),
            inner_source,
            inner_destination,
            static_cast<unsigned int>(probe.info.sequence),
            probe.info.activation_generation);
        return;
    }

    if (probe.consumed) {
        logger::Log(
            "Rejected debug ICMP reply metadata for peer %zu validation=%s payload=%zu",
            peer_index,
            wgnx::wireguard::GetDebugProbeReplyValidationName(probe.validation),
            inner_packet.size());
        return;
    }

    const auto delivery = m_packet_data_plane.DeliverDecryptedPacket(
        {
            .peer_index = static_cast<std::uint32_t>(peer_index),
            .activation_generation = activation_generation,
        },
        inner_packet);
    switch (delivery.status) {
        case runtime::PacketDeliveryStatus::Queued:
            logger::Log(
                "Queued decrypted inner packet id=%llu peer=%zu activation=%u bytes=%zu depth=%zu",
                static_cast<unsigned long long>(delivery.packet_id),
                peer_index,
                activation_generation,
                inner_packet.size(),
                delivery.queue_depth);
            break;
        case runtime::PacketDeliveryStatus::NoConsumer:
            logger::Log(
                "Dropped decrypted inner packet peer=%zu activation=%u bytes=%zu reason=no_consumer",
                peer_index,
                activation_generation,
                inner_packet.size());
            break;
        case runtime::PacketDeliveryStatus::MalformedPacket:
            logger::Log(
                "Dropped decrypted inner packet peer=%zu activation=%u bytes=%zu validation=%s",
                peer_index,
                activation_generation,
                inner_packet.size(),
                wgnx::wireguard::GetInnerIpValidationErrorName(delivery.validation));
            break;
        case runtime::PacketDeliveryStatus::UnsupportedPacket:
            logger::Log(
                "Dropped decrypted inner packet peer=%zu activation=%u bytes=%zu reason=unsupported_transport_ip_version version=%u",
                peer_index,
                activation_generation,
                inner_packet.size(),
                static_cast<unsigned int>(delivery.version));
            break;
        case runtime::PacketDeliveryStatus::QueueFull:
            logger::Log(
                "Dropped decrypted inner packet peer=%zu activation=%u bytes=%zu reason=rx_queue_full capacity=%zu",
                peer_index,
                activation_generation,
                inner_packet.size(),
                delivery.queue_capacity);
            break;
        case runtime::PacketDeliveryStatus::StalePeer:
            break;
    }
}

NOINLINE void DaemonRuntime::CommitReceivedPacket(
    std::size_t peer_index,
    std::uint32_t activation_generation,
    std::uint32_t socket_generation,
    wgnx::platform::socket_handle socket,
    std::span<const std::uint8_t> packet,
    const wgnx::platform::endpoint &source,
    runtime::EffectBatch &out_effects) {
    out_effects.Clear();
    std::scoped_lock lock(m_state_mutex);
    const runtime::PeerIdentity identity{
        .peer_index = static_cast<std::uint32_t>(peer_index),
        .activation_generation = activation_generation,
    };
    const auto binding = m_runtime_coordinator.BindingSnapshot(peer_index);
    if (!m_runtime_coordinator.IsActiveTransportIdentity(identity) ||
        !binding.Matches(socket_generation, socket)) {
        return;
    }

    std::array<char, sizeof(wgnx::PeerInfo::resolved_endpoint)> source_text{};
    FormatEndpointText(source, source_text.data(), source_text.size());
    const auto now_jiffies = wgnx::platform::get_jiffies_64();
    out_effects = m_runtime_coordinator.Dispatch(
        runtime::EncryptedDatagramReceivedEvent{
            .peer = {
                .peer_index = static_cast<std::uint32_t>(peer_index),
                .activation_generation = activation_generation,
            },
            .packet = packet,
            .source = source,
            .source_text = source_text,
            .keepalive_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(now_jiffies) +
                std::chrono::seconds{
                    m_runtime_coordinator.Lifecycle(peer_index)
                        ->persistent_keepalive_interval},
            .rekey_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(now_jiffies) +
                wgnx::wireguard::RekeyAfterTime,
            .zero_key_material_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(now_jiffies) +
                wgnx::wireguard::ZeroKeyMaterialAfterTime,
            .occurred_at = GetRuntimeNowNs(),
        });
}
void DaemonRuntime::CommitReceiveFailure(
    std::size_t peer_index,
    std::uint32_t activation_generation,
    std::uint32_t socket_generation,
    wgnx::platform::socket_handle socket,
    wgnx::platform::socket_error error) {
    runtime::EffectBatch effects{};
    std::unique_lock lock(m_state_mutex);
    const runtime::PeerIdentity identity{
        .peer_index = static_cast<std::uint32_t>(peer_index),
        .activation_generation = activation_generation,
    };
    const auto binding = m_runtime_coordinator.BindingSnapshot(peer_index);
    if (!m_runtime_coordinator.IsActiveTransportIdentity(identity) ||
        !binding.Matches(socket_generation, socket)) {
        return;
    }

    logger::Log(
        "UDP receive failed for peer %zu endpoint=%s err=%u",
        peer_index,
        binding.endpoint_text.data(),
        static_cast<unsigned int>(error));
    effects = m_runtime_coordinator.Dispatch(runtime::TransportFailureEvent{
        .peer = identity,
        .operation = runtime::TransportIoOperation::Receive,
        .socket = socket,
        .socket_generation = socket_generation,
        .error = error,
        .occurred_at = GetRuntimeNowNs(),
    });
    logger::Log(
        "WG receive worker stopped after transport failure peer=%zu activation=%u socket_generation=%u socket=%d",
        peer_index,
        activation_generation,
        socket_generation,
        static_cast<int>(socket));
    lock.unlock();
    ExecuteRuntimeEffects(effects);
}

[[maybe_unused]] void DaemonRuntime::CommitPayloadSubmission(const runtime::DebugProbeRequest &request) {
    runtime::EffectBatch effects{};
    std::unique_lock lock(m_state_mutex);
    if (!m_runtime_coordinator.IsActiveIdentity(request.peer)) {
        static_cast<void>(m_debug_probe_runner.MarkFailed(
            request,
            wgnx::DebugProbeStatus::StaleActivation,
            GetRuntimeNowNs()));
        logger::Log(
            "Discarded queued payload submission for stale peer %u activation=%u",
            request.peer.peer_index,
            request.peer.activation_generation);
        return;
    }

    const auto *lifecycle = m_runtime_coordinator.Lifecycle(request.peer.peer_index);
    const auto binding = m_runtime_coordinator.BindingSnapshot(request.peer.peer_index);
    AMS_ABORT_UNLESS(lifecycle != nullptr);
    if (!m_runtime_coordinator.IsActiveEstablishedIdentity(request.peer) ||
        !binding.IsOpen()) {
        static_cast<void>(m_debug_probe_runner.MarkFailed(
            request,
            lifecycle->activation_generation == request.peer.activation_generation
                ? wgnx::DebugProbeStatus::InvalidState
                : wgnx::DebugProbeStatus::StaleActivation,
            GetRuntimeNowNs()));
        logger::Log(
            "Discarded queued payload submission for peer %u state=%s activation=%u current_activation=%u",
            request.peer.peer_index,
            wgnx::GetPeerRuntimeStateName(lifecycle->state),
            request.peer.activation_generation,
            lifecycle->activation_generation);
        return;
    }

    std::array<std::uint8_t, wgnx::wireguard::DebugProbePacketSize> payload{};
    const std::size_t payload_size = m_debug_probe_runner.BuildPacket(
        request,
        payload,
        wgnx::platform::get_random_u32_below(std::numeric_limits<std::uint32_t>::max()));
    if (payload_size == 0) {
        char target_text[16] = {};
        std::array<std::uint8_t, 4> target_ipv4{};
        wgnx::wireguard::CopyDebugTargetIpv4(request.action, target_ipv4);
        wgnx::wireguard::FormatIpv4Text(target_ipv4, target_text, sizeof(target_text));
        static_cast<void>(m_debug_probe_runner.MarkFailed(
            request,
            wgnx::DebugProbeStatus::BuildFailed,
            GetRuntimeNowNs()));
        logger::Log(
            "Failed to build debug ICMP packet for peer %u activation=%u action=%s source=%s target=%s",
            request.peer.peer_index,
            request.peer.activation_generation,
            wgnx::GetDebugTriggerActionName(request.action),
            request.source_address.data(),
            target_text);
        return;
    }

    char target_text[16] = {};
    std::array<std::uint8_t, 4> target_ipv4{};
    wgnx::wireguard::CopyDebugTargetIpv4(request.action, target_ipv4);
    wgnx::wireguard::FormatIpv4Text(target_ipv4, target_text, sizeof(target_text));
    logger::Log(
        "Built debug ICMP packet for peer %u activation=%u action=%s source=%s target=%s bytes=%zu",
        request.peer.peer_index,
        request.peer.activation_generation,
        wgnx::GetDebugTriggerActionName(request.action),
        request.source_address.data(),
        target_text,
        payload_size);
    const auto submission = m_packet_data_plane.SubmitInternalIpPacket(
        std::span<const std::uint8_t>(payload.data(), payload_size),
        wgnx::wireguard::TimerDeadlineFromJiffies(wgnx::platform::get_jiffies_64()) +
            wgnx::wireguard::GetHandshakeRetryDelay(
                wgnx::platform::get_random_u32_below(
                    wgnx::wireguard::RekeyTimeoutJitterMaxMs)),
        GetRuntimeNowNs(),
        effects);
    if (submission.status != runtime::PacketSubmissionStatus::Queued) {
        static_cast<void>(m_debug_probe_runner.MarkFailed(
            request,
            wgnx::DebugProbeStatus::SendFailed,
            GetRuntimeNowNs()));
        logger::Log(
            "Failed to stage debug payload peer=%u activation=%u status=%u",
            request.peer.peer_index,
            request.peer.activation_generation,
            static_cast<unsigned int>(submission.status));
        return;
    }

    static_cast<void>(m_debug_probe_runner.MarkSent(request, GetRuntimeNowNs()));
    SchedulePayloadProbeTimeout();
    lock.unlock();
    ExecuteRuntimeEffects(effects);
}

void DaemonRuntime::ResolverWorkMain(wgnx::platform::work_struct *) {
    while (true) {
        std::optional<runtime::ResolveEndpointEffect> request{};
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
        const auto result = wgnx::platform::resolve_endpoint(request->endpoint.data());
        logger::Log(
            "Endpoint resolution completion peer=%u activation=%u endpoint='%s' success=%u stage=%s code=%s resolved=%s",
            request->peer.peer_index,
            request->peer.activation_generation,
            request->endpoint.data(),
            result.success ? 1U : 0U,
            wgnx::GetPeerErrorStageName(result.error_stage),
            wgnx::GetPeerErrorCodeName(result.error_code),
            result.text.data());
        runtime::EffectBatch effects{};
        {
            std::scoped_lock lock(m_state_mutex);
            effects = m_runtime_coordinator.Dispatch(runtime::EndpointResolvedEvent{
                .peer = request->peer,
                .result = result,
                .occurred_at = GetRuntimeNowNs(),
            });
        }
        ExecuteRuntimeEffects(effects);
    }
}

void DaemonRuntime::ProcessPendingBindBump() {
    std::unique_lock lock(m_state_mutex);
    runtime::UdpRebindRequest request{};
    if (!m_rebind_requests.Take(request)) {
        return;
    }
    const runtime::PeerIdentity identity{
        .peer_index = static_cast<std::uint32_t>(request.peer_index),
        .activation_generation = request.activation_generation,
    };
    logger::Log(
        "Dispatching UDP bind bump peer=%zu activation=%u",
        request.peer_index,
        request.activation_generation);

    const runtime::EffectBatch effects = m_runtime_coordinator.Dispatch(
        runtime::UdpRebindRequestedEvent{
            .peer = identity,
            .occurred_at = GetRuntimeNowNs(),
        });
    lock.unlock();
    ExecuteRuntimeEffects(effects);
}

void DaemonRuntime::ReceiveWorkMain(wgnx::platform::work_struct *) {
    // HorizonDispatcher serializes this callback on one ordered work queue, so
    // the process-lifetime receive storage has one exclusive user at a time.
    wgnx::platform::packet_buffer packet{
        .data = m_receive_packet_storage.data(),
        .len = 0,
        .capacity = m_receive_packet_storage.size(),
    };
    while (true) {
        ProcessPendingBindBump();

        std::size_t peer_index = 0;
        std::uint32_t activation_generation = 0;
        std::uint32_t socket_generation = 0;
        wgnx::platform::socket_handle socket = wgnx::platform::InvalidSocket;
        if (!SnapshotReceiveRuntime(
                std::addressof(peer_index),
                std::addressof(activation_generation),
                std::addressof(socket_generation),
                std::addressof(socket))) {
            return;
        }

        wgnx::platform::endpoint source{};
        std::size_t received = 0;
        logger::Log(
            "WG receive iteration begin peer=%zu activation=%u socket_generation=%u socket=%d",
            peer_index,
            activation_generation,
            socket_generation,
            static_cast<int>(socket));
        const auto receive_error = wgnx::platform::udp_receive(
            socket,
            packet.storage(),
            std::addressof(received),
            std::addressof(source));
        logger::Log(
            "WG receive iteration end peer=%zu activation=%u socket_generation=%u socket=%d error=%u bytes=%zu",
            peer_index,
            activation_generation,
            socket_generation,
            static_cast<int>(socket),
            static_cast<unsigned int>(receive_error),
            received);
        if (receive_error != wgnx::platform::socket_error::none) {
            CommitReceiveFailure(peer_index, activation_generation, socket_generation, socket, receive_error);
            return;
        }
        if (received == 0) {
            continue;
        }

        static_cast<void>(wgnx::platform::packet_set_len(std::addressof(packet), received));
        CommitReceivedPacket(
            peer_index,
            activation_generation,
            socket_generation,
            socket,
            packet.bytes(),
            source,
            m_receive_effects);
        ExecuteRuntimeEffects(m_receive_effects);
        m_receive_effects.Clear();
        wgnx::platform::packet_clear(std::addressof(packet));
    }
}

[[maybe_unused]] void DaemonRuntime::PayloadSubmissionWorkMain(wgnx::platform::work_struct *) {
    runtime::DebugProbeRequest request{};
    while (DequeuePayloadSubmissionRequest(std::addressof(request))) {
        CommitPayloadSubmission(request);
    }
}

[[maybe_unused]] void DaemonRuntime::InnerPacketSubmissionWorkMain(wgnx::platform::work_struct *) {
    runtime::EffectBatch effects{};
    {
        std::scoped_lock lock(m_state_mutex);
        runtime::PeerPacketStateSnapshot peer{};
        if (!m_runtime_coordinator.SnapshotPacketState(peer)) {
            return;
        }
        effects = m_runtime_coordinator.Dispatch(runtime::ProcessOutboundQueueEvent{
            .peer = peer.identity,
            .retry_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(
                    wgnx::platform::get_jiffies_64()) +
                wgnx::wireguard::GetHandshakeRetryDelay(
                    wgnx::platform::get_random_u32_below(
                        wgnx::wireguard::RekeyTimeoutJitterMaxMs)),
            .occurred_at = GetRuntimeNowNs(),
        });
    }
    ExecuteRuntimeEffects(effects);
}

[[maybe_unused]] void DaemonRuntime::CommitPayloadProbeTimeout() {
    std::scoped_lock lock(m_state_mutex);
    const auto peer = m_debug_probe_runner.Peer();
    const auto action = m_debug_probe_runner.Action();
    if (!m_debug_probe_runner.HandleTimeout(GetRuntimeNowNs())) {
        return;
    }
    logger::Log(
        "Debug payload probe timed out for peer %u action=%s activation=%u",
        peer.peer_index,
        wgnx::GetDebugTriggerActionName(action),
        peer.activation_generation);
}

void DaemonRuntime::RunTimerAction(
    wgnx::wireguard::TimerHook hook,
    const wgnx::wireguard::TimerToken &token) {
    std::unique_lock lock(m_state_mutex);
    if (!token.IsValid() || token.hook != hook ||
        token.owner.peer_index >= m_runtime_coordinator.PeerCount()) {
        return;
    }

    const std::size_t peer_index = token.owner.peer_index;
    const auto now_jiffies = wgnx::platform::get_jiffies_64();
    const runtime::EffectBatch effects = m_runtime_coordinator.Dispatch(
        runtime::ProtocolTimerExpiredEvent{
            .peer = {
                .peer_index = token.owner.peer_index,
                .activation_generation = token.owner.activation_generation,
            },
            .hook = hook,
            .token = token,
            .retry_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(now_jiffies) +
                wgnx::wireguard::GetHandshakeRetryDelay(
                    wgnx::platform::get_random_u32_below(
                        wgnx::wireguard::RekeyTimeoutJitterMaxMs)),
            .keepalive_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(now_jiffies) +
                std::chrono::seconds{
                    m_runtime_coordinator.Configuration(peer_index)
                        ->persistent_keepalive},
            .zero_key_material_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(now_jiffies) +
                wgnx::wireguard::ZeroKeyMaterialAfterTime,
            .occurred_at = GetRuntimeNowNs(),
        });
    lock.unlock();
    ExecuteRuntimeEffects(effects);
}

void DaemonRuntime::NetworkPathObserverWorkMain(wgnx::platform::work_struct *) {
    bool has_active_transport = false;
    {
        std::scoped_lock lock(m_state_mutex);
        has_active_transport = m_runtime_coordinator.ActivePeerIndex() >= 0;
    }

    if (has_active_transport) {
        const auto sequence = m_network_path_observer.BeginObservation();
        const auto snapshot = wgnx::platform::sample_network_path(sequence);
        static_cast<void>(m_network_path_observer.Commit({
            .sequence = sequence,
            .snapshot = snapshot,
        }));
    }
}

void DaemonRuntime::ResolverWorkCallback(wgnx::platform::work_struct *work) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    s_instance->ResolverWorkMain(work);
}

void DaemonRuntime::PayloadSubmissionWorkCallback(wgnx::platform::work_struct *work) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    s_instance->PayloadSubmissionWorkMain(work);
}

void DaemonRuntime::InnerPacketSubmissionWorkCallback(wgnx::platform::work_struct *work) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    s_instance->InnerPacketSubmissionWorkMain(work);
}

void DaemonRuntime::ReceiveWorkCallback(wgnx::platform::work_struct *work) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    s_instance->ReceiveWorkMain(work);
}

void DaemonRuntime::ProtocolTimerCallback(
    wgnx::wireguard::TimerHook hook,
    const wgnx::wireguard::TimerToken &token) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    s_instance->RunTimerAction(hook, token);
}

void DaemonRuntime::DebugProbeTimeoutCallback() {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    s_instance->CommitPayloadProbeTimeout();
}

void DaemonRuntime::NetworkPathObserverCallback() {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    s_instance->NetworkPathObserverWorkMain(nullptr);
}

void DaemonRuntime::InitializeHorizonDispatcher() {
    m_horizon_dispatcher.Initialize(
        {
            .resolve = ResolverWorkCallback,
            .submit_debug_payload = PayloadSubmissionWorkCallback,
            .submit_inner_packet = InnerPacketSubmissionWorkCallback,
            .receive = ReceiveWorkCallback,
        });
    m_timer_scheduler.Initialize(
        m_horizon_dispatcher,
        {
            .protocol_timer = ProtocolTimerCallback,
            .debug_probe_timeout = DebugProbeTimeoutCallback,
            .network_path_observer = NetworkPathObserverCallback,
        },
        development_config::NifmPathObserverEnabled,
        NetworkPathObservationJiffies);

    logger::Log("Started endpoint resolver worker");
    logger::Log("Started shared payload and inner packet submission worker");
    logger::Log("Started UDP receive worker");
    if constexpr (development_config::NifmPathObserverEnabled) {
        logger::Log("NIFM network-path observer enabled mode=%s interval_jiffies=%llu",
            development_config::GetNifmPathObserverModeName(),
            static_cast<unsigned long long>(NetworkPathObservationJiffies));
    } else {
        logger::Log("NIFM network-path observer disabled mode=%s",
            development_config::GetNifmPathObserverModeName());
    }
    logger::Log("Started transport timer executor");
}

wgnx::DaemonStatus DaemonRuntime::GetDaemonStatus() {
    std::scoped_lock lock(m_state_mutex);
    InitializeState();

    return {
        .abi_version = wgnx::IpcApiVersion,
        .peer_count = m_runtime_coordinator.PeerCount(),
        .active_peer_index = m_runtime_coordinator.ActivePeerIndex(),
        .auto_start_peer_index = m_runtime_coordinator.AutoStartPeerIndex(),
        .flags = runtime::BuildDaemonFlags(
            m_runtime_coordinator.ActivePeerIndex() >= 0,
            HasRuntimeErrors()),
        .reserved = 0,
    };
}

std::uint32_t DaemonRuntime::CopyPeers(std::span<wgnx::PeerInfo> out) {
    std::scoped_lock lock(m_state_mutex);
    InitializeState();

    const std::size_t copy_count =
        std::min<std::size_t>(out.size(), m_runtime_coordinator.PeerCount());
    for (std::size_t i = 0; i < copy_count; ++i) {
        out[i] = BuildPeerInfo(i);
    }

    return m_runtime_coordinator.PeerCount();
}

ams::Result DaemonRuntime::SetActivePeer(std::int32_t peer_index) {
    std::unique_lock lock(m_state_mutex);
    InitializeState();

    if (!IsValidPeerIndex(peer_index)) {
        logger::Log("Rejected SetActivePeer(%d): invalid index", peer_index);
        R_THROW(ams::fs::ResultInvalidArgument());
    }

    if (peer_index == m_runtime_coordinator.ActivePeerIndex()) {
        logger::Log("SetActivePeer(%d): no change", peer_index);
        R_SUCCEED();
    }

    runtime::EffectBatch effects{};
    if (m_runtime_coordinator.ActivePeerIndex() >= 0 &&
        m_runtime_coordinator.ActivePeerIndex() != peer_index) {
        const std::size_t old_index =
            static_cast<std::size_t>(m_runtime_coordinator.ActivePeerIndex());
        effects = SetPeerInactive(old_index);
    }

    AMS_ABORT_UNLESS(m_runtime_coordinator.SetActivePeerIndex(peer_index));
    if (peer_index >= 0) {
        const auto activation_effects = m_runtime_coordinator.Dispatch(runtime::ActivationRequestedEvent{
            .peer_index = static_cast<std::uint32_t>(peer_index),
            .occurred_at = GetRuntimeNowNs(),
        });
        AMS_ABORT_UNLESS(effects.Append(activation_effects));
    }
    logger::Log("SetActivePeer(%d)", peer_index);
    lock.unlock();
    ExecuteRuntimeEffects(effects);
    R_SUCCEED();
}

ams::Result DaemonRuntime::SetAutoStartPeer(std::int32_t peer_index) {
    std::scoped_lock lock(m_state_mutex);
    InitializeState();

    if (!IsValidPeerIndex(peer_index)) {
        logger::Log("Rejected SetAutoStartPeer(%d): invalid index", peer_index);
        R_THROW(ams::fs::ResultInvalidArgument());
    }

    const char *peer_name = nullptr;
    if (peer_index >= 0) {
        peer_name = m_runtime_coordinator
                        .Configuration(static_cast<std::size_t>(peer_index))
                        ->name.data();
    }

    const ams::Result store_rc = StoreAutoStartPeerName(peer_name);
    if (R_FAILED(store_rc)) {
        logger::Log("Rejected SetAutoStartPeer(%d): persist failed rc=0x%08x", peer_index, static_cast<u32>(store_rc.GetValue()));
        R_THROW(store_rc);
    }

    AMS_ABORT_UNLESS(m_runtime_coordinator.SetAutoStartPeerIndex(peer_index));
    logger::Log("SetAutoStartPeer(%d)", peer_index);
    R_SUCCEED();
}

ams::Result DaemonRuntime::TriggerDebugPayload(wgnx::DebugTriggerAction action) {
    std::scoped_lock lock(m_state_mutex);
    InitializeState();

    if (!QueuePayloadSubmissionRequestLocked(action)) {
        logger::Log(
            "Rejected TriggerDebugPayload(action=%u): no active session, invalid action, or queue busy",
            static_cast<unsigned int>(action));
        R_THROW(ams::fs::ResultInvalidArgument());
    }

    QueuePayloadSubmissionWork();
    logger::Log("Queued debug payload trigger action=%s", wgnx::GetDebugTriggerActionName(action));
    R_SUCCEED();
}

ams::Result DaemonRuntime::BumpUdpBinding() {
    {
        std::scoped_lock lock(m_state_mutex);
        InitializeState();
        runtime::PeerPacketStateSnapshot peer{};
        if (!m_runtime_coordinator.SnapshotPacketState(peer)) {
            logger::Log("Rejected BumpUdpBinding: no active peer");
            R_THROW(ams::fs::ResultInvalidArgument());
        }

        const std::size_t peer_index = peer.identity.peer_index;
        const auto binding = m_runtime_coordinator.BindingSnapshot(peer_index);
        if ((peer.state != wgnx::PeerRuntimeState::Handshaking &&
             peer.state != wgnx::PeerRuntimeState::Active) ||
            !binding.has_endpoint) {
            logger::Log(
                "Rejected BumpUdpBinding: peer=%zu state=%s resolved=%u",
                peer_index,
                wgnx::GetPeerRuntimeStateName(peer.state),
                binding.has_endpoint ? 1U : 0U);
            R_THROW(ams::fs::ResultInvalidArgument());
        }

        const runtime::UdpRebindRequest request{
            .peer_index = peer_index,
            .activation_generation = peer.identity.activation_generation,
        };
        if (m_rebind_requests.IsPending(request)) {
            logger::Log(
                "Coalesced UDP bind bump peer=%zu activation=%u",
                peer_index,
                peer.identity.activation_generation);
        } else {
            static_cast<void>(m_rebind_requests.Queue(request));
            logger::Log(
                "Queued UDP bind bump peer=%zu activation=%u socket_generation=%u socket=%d",
                peer_index,
                peer.identity.activation_generation,
                binding.generation,
                static_cast<int>(binding.socket));
        }
    }

    QueueReceiveWork();
    R_SUCCEED();
}

wgnx::PacketSubmissionResult DaemonRuntime::SubmitInnerIpv4Packet(
    std::span<const std::uint8_t> packet_bytes,
    std::uint64_t process_id) {
    wgnx::PacketSubmissionResult result = {
        .packet_id = 0,
        .status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::InternalError),
        .packet_size = static_cast<std::uint32_t>(packet_bytes.size()),
        .activation_generation = 0,
        .peer_index = -1,
    };

    runtime::EffectBatch effects{};
    runtime::PacketSubmissionOutcome outcome{};
    {
        std::scoped_lock lock(m_state_mutex);
        InitializeState();
        outcome = m_packet_data_plane.SubmitIpv4Packet(
            packet_bytes,
            process_id,
            wgnx::wireguard::TimerDeadlineFromJiffies(
                wgnx::platform::get_jiffies_64()) +
                wgnx::wireguard::GetHandshakeRetryDelay(
                    wgnx::platform::get_random_u32_below(
                        wgnx::wireguard::RekeyTimeoutJitterMaxMs)),
            GetRuntimeNowNs(),
            effects);
        if (outcome.ownership_transferred) {
            logger::Log(
                "Transferred packet API ownership pid=%llu discarded_tx=%zu discarded_rx=%zu",
                static_cast<unsigned long long>(process_id),
                outcome.discarded_outbound,
                outcome.discarded_inbound);
        }
    }

    result.packet_id = outcome.packet_id;
    result.activation_generation = outcome.has_peer
        ? outcome.peer.activation_generation
        : 0;
    result.peer_index = outcome.has_peer
        ? static_cast<std::int32_t>(outcome.peer.peer_index)
        : -1;
    switch (outcome.status) {
        case runtime::PacketSubmissionStatus::Queued:
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::Queued);
            logger::Log(
                "Queued packet API submission id=%llu pid=%llu peer=%u activation=%u bytes=%zu depth=%zu state=%s",
                static_cast<unsigned long long>(outcome.packet_id),
                static_cast<unsigned long long>(process_id),
                outcome.peer.peer_index,
                outcome.peer.activation_generation,
                packet_bytes.size(),
                outcome.queue_depth,
                wgnx::GetPeerRuntimeStateName(outcome.peer_state));
            break;
        case runtime::PacketSubmissionStatus::MalformedPacket:
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::MalformedPacket);
            logger::Log(
                "Rejected packet API submission pid=%llu bytes=%zu validation=%s",
                static_cast<unsigned long long>(process_id),
                packet_bytes.size(),
                wgnx::wireguard::GetInnerIpValidationErrorName(outcome.validation));
            break;
        case runtime::PacketSubmissionStatus::TunnelUnavailable:
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::TunnelUnavailable);
            break;
        case runtime::PacketSubmissionStatus::QueueFull:
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::QueueFull);
            logger::Log(
                "Rejected packet API submission pid=%llu reason=tx_queue_full",
                static_cast<unsigned long long>(process_id));
            break;
        case runtime::PacketSubmissionStatus::InternalError:
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::InternalError);
            break;
    }

    ExecuteRuntimeEffects(effects);
    return result;
}

wgnx::PacketReceiveResult DaemonRuntime::ReceiveInnerIpv4Packet(
    std::span<std::uint8_t> packet,
    std::uint64_t process_id) {
    wgnx::PacketReceiveResult result = {
        .packet_id = 0,
        .status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::QueueEmpty),
        .packet_size = 0,
        .activation_generation = 0,
        .peer_index = -1,
    };

    runtime::PacketReceiveOutcome outcome{};
    {
        std::scoped_lock lock(m_state_mutex);
        InitializeState();
        outcome = m_packet_data_plane.ReceivePacket(packet, process_id);
    }
    result.packet_id = outcome.packet_id;
    result.packet_size = static_cast<std::uint32_t>(outcome.packet_size);
    result.activation_generation = outcome.peer.activation_generation;
    result.peer_index = outcome.packet_id != 0
        ? static_cast<std::int32_t>(outcome.peer.peer_index)
        : -1;
    switch (outcome.status) {
        case runtime::PacketReceiveStatus::Success:
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::Success);
            logger::Log(
                "Delivered packet API receive id=%llu pid=%llu peer=%u activation=%u bytes=%zu remaining=%zu",
                static_cast<unsigned long long>(outcome.packet_id),
                static_cast<unsigned long long>(process_id),
                outcome.peer.peer_index,
                outcome.peer.activation_generation,
                outcome.packet_size,
                outcome.queue_depth);
            break;
        case runtime::PacketReceiveStatus::QueueEmpty:
            break;
        case runtime::PacketReceiveStatus::AccessDenied:
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::AccessDenied);
            break;
        case runtime::PacketReceiveStatus::OutputBufferTooSmall:
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::OutputBufferTooSmall);
            break;
        case runtime::PacketReceiveStatus::StaleActivation:
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::StaleActivation);
            logger::Log(
                "Discarded packet API receive id=%llu reason=stale_activation",
                static_cast<unsigned long long>(outcome.packet_id));
            break;
    }
    return result;
}

void DaemonRuntime::Initialize() {
    {
        std::scoped_lock lock(m_state_mutex);
        InitializeState();
    }
    InitializeHorizonDispatcher();
}

DaemonRuntime g_daemon_runtime{};

} // namespace

namespace runtime {

void Initialize() {
    g_daemon_runtime.Initialize();
}

wgnx::DaemonStatus GetDaemonStatus() {
    return g_daemon_runtime.GetDaemonStatus();
}

std::uint32_t CopyPeers(std::span<wgnx::PeerInfo> out) {
    return g_daemon_runtime.CopyPeers(out);
}

ams::Result SetActivePeer(std::int32_t peer_index) {
    R_RETURN(g_daemon_runtime.SetActivePeer(peer_index));
}

ams::Result SetAutoStartPeer(std::int32_t peer_index) {
    R_RETURN(g_daemon_runtime.SetAutoStartPeer(peer_index));
}

ams::Result TriggerDebugPayload(wgnx::DebugTriggerAction action) {
    R_RETURN(g_daemon_runtime.TriggerDebugPayload(action));
}

ams::Result BumpUdpBinding() {
    R_RETURN(g_daemon_runtime.BumpUdpBinding());
}

wgnx::PacketSubmissionResult SubmitInnerIpv4Packet(
    std::span<const std::uint8_t> packet,
    std::uint64_t process_id) {
    return g_daemon_runtime.SubmitInnerIpv4Packet(packet, process_id);
}

wgnx::PacketReceiveResult ReceiveInnerIpv4Packet(
    std::span<std::uint8_t> packet,
    std::uint64_t process_id) {
    return g_daemon_runtime.ReceiveInnerIpv4Packet(packet, process_id);
}

} // namespace runtime

} // namespace wgnx::sysmodule
