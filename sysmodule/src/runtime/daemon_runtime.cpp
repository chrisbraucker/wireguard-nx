#include "runtime/daemon_runtime.hpp"
#include "runtime/debug_probe_runner.hpp"
#include "runtime/encrypted_receive_pump.hpp"
#include "runtime/endpoint_resolver.hpp"
#include "runtime/horizon_dispatcher.hpp"
#include "runtime/network_path_observer.hpp"
#include "runtime/packet_channel.hpp"
#include "runtime/packet_data_plane.hpp"
#include "runtime/peer_configuration.hpp"
#include "runtime/peer_runtime.hpp"
#include "runtime/runtime_coordinator.hpp"
#include "runtime/runtime_contracts.hpp"
#include "runtime/runtime_effect_executor.hpp"
#include "runtime/timer_scheduler.hpp"

#include "config_loader.hpp"
#include "development_config.hpp"
#include "logger.hpp"
#include "wgnx/platform/clock.hpp"
#include "wgnx/platform/random.hpp"
#include "wgnx/platform/work.hpp"
#include "wgnx/resource_budget.hpp"
#include "wireguard/peer_controller.hpp"
#include "wireguard/timers.hpp"

#include <algorithm>
#include <mutex>
#include <span>

namespace wgnx::sysmodule {

namespace {

struct DaemonState {
    runtime::PeerRegistry peers{};
    bool initialized{false};
};

constexpr inline wgnx::platform::jiffies_t NetworkPathObservationJiffies = 2U * wgnx::platform::HZ;

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
        runtime::ProcessId process_id);
    wgnx::PacketReceiveResult ReceiveInnerIpv4Packet(
        std::span<std::uint8_t> packet,
        runtime::ProcessId process_id);

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

    void ClearInnerPacketStateLocked(const char *reason);
    runtime::EffectBatch SetPeerInactive(std::size_t peer_index);
    void QueuePayloadSubmissionWork();
    runtime::DebugProbeQueueResult QueuePayloadSubmissionRequestLocked(
        wgnx::DebugTriggerAction action);
    wgnx::PeerInfo BuildPeerInfo(std::size_t peer_index);
    bool HasRuntimeErrors();
    void InitializeState();
    bool IsValidPeerIndex(std::int32_t peer_index);
    void ExecuteRuntimeEffects(const runtime::EffectBatch &effects);
    void InitializeHorizonDispatcher();

    static DaemonRuntime *s_instance;
    DaemonState m_state{};
    ams::os::Mutex m_state_mutex;
    runtime::EndpointResolver m_endpoint_resolver{};
    runtime::HorizonDispatcher m_horizon_dispatcher{};
    runtime::TimerScheduler m_timer_scheduler{};
    runtime::PacketChannel m_packet_channel{};
    runtime::RuntimeCoordinator m_runtime_coordinator;
    runtime::PacketDataPlane m_packet_data_plane;
    runtime::DebugProbeRunner m_debug_probe_runner{};
    runtime::NetworkPathObserver m_network_path_observer{};
    runtime::PeerConfigurationLoader m_peer_configuration_loader{};
    runtime::LoadedPeerConfiguration m_loaded_peer_configuration{};
    runtime::EncryptedReceivePump m_receive_pump;
    runtime::RuntimeEffectExecutor m_effect_executor;
};

static_assert(
    sizeof(DaemonRuntime) <=
    wgnx::resource_budget::MaximumDaemonRuntimeBytes);

DaemonRuntime *DaemonRuntime::s_instance = nullptr;

DaemonRuntime::DaemonRuntime()
    : m_state_mutex(false),
      m_runtime_coordinator(m_state.peers),
      m_packet_data_plane(m_runtime_coordinator, m_packet_channel),
      m_receive_pump(
          m_state_mutex,
          m_runtime_coordinator,
          m_horizon_dispatcher),
      m_effect_executor(
          m_state_mutex,
          m_runtime_coordinator,
          m_endpoint_resolver,
          m_horizon_dispatcher,
          m_timer_scheduler,
          m_packet_data_plane,
          m_debug_probe_runner,
          m_network_path_observer,
          m_receive_pump) {
    AMS_ABORT_UNLESS(s_instance == nullptr);
    s_instance = this;
}

wgnx::platform::ktime_t GetRuntimeNowNs() {
    return wgnx::platform::ktime_get_coarse_boottime_ns();
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
    m_effect_executor.CancelDebugProbeTimeout();
    const auto *lifecycle = m_runtime_coordinator.Lifecycle(peer_index);
    AMS_ABORT_UNLESS(lifecycle != nullptr);
    const runtime::PeerIdentity peer{
        .peer_index = runtime::PeerIndex{
            static_cast<std::uint32_t>(peer_index)},
        .activation_generation = lifecycle->activation_generation,
    };
    m_debug_probe_runner.Cancel(&peer);
    ClearInnerPacketStateLocked("peer inactive");
    return m_runtime_coordinator.Dispatch(runtime::DeactivationRequestedEvent{
        .peer = peer,
        .occurred_at = GetRuntimeNowNs(),
    });
}

[[maybe_unused]] void DaemonRuntime::QueuePayloadSubmissionWork() {
    m_horizon_dispatcher.QueueDebugPayloadSubmission();
}

[[maybe_unused]] runtime::DebugProbeQueueResult
DaemonRuntime::QueuePayloadSubmissionRequestLocked(
    wgnx::DebugTriggerAction action) {
    runtime::DebugPeerSnapshot peer{};
    if (!m_runtime_coordinator.SnapshotDebugPeer(peer)) {
        return runtime::DebugProbeQueueResult::NoActivePeer;
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

void DaemonRuntime::ExecuteRuntimeEffects(const runtime::EffectBatch &effects) {
    m_effect_executor.Execute(effects);
}

void DaemonRuntime::ResolverWorkCallback(wgnx::platform::work_struct *work) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    static_cast<void>(work);
    s_instance->m_effect_executor.RunEndpointResolver();
}

void DaemonRuntime::PayloadSubmissionWorkCallback(wgnx::platform::work_struct *work) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    static_cast<void>(work);
    s_instance->m_effect_executor.RunDebugPayloadSubmission();
}

void DaemonRuntime::InnerPacketSubmissionWorkCallback(wgnx::platform::work_struct *work) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    static_cast<void>(work);
    s_instance->m_effect_executor.RunInnerPacketSubmission();
}

void DaemonRuntime::ReceiveWorkCallback(wgnx::platform::work_struct *work) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    static_cast<void>(work);
    s_instance->m_receive_pump.Run(s_instance->m_effect_executor);
}

void DaemonRuntime::ProtocolTimerCallback(
    wgnx::wireguard::TimerHook hook,
    const wgnx::wireguard::TimerToken &token) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    s_instance->m_effect_executor.RunProtocolTimer(hook, token);
}

void DaemonRuntime::DebugProbeTimeoutCallback() {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    s_instance->m_effect_executor.RunDebugProbeTimeout();
}

void DaemonRuntime::NetworkPathObserverCallback() {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    s_instance->m_effect_executor.RunNetworkPathObservation();
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
            .peer_index = runtime::PeerIndex{
                static_cast<std::uint32_t>(peer_index)},
            .occurred_at = GetRuntimeNowNs(),
        });
        effects.Append(activation_effects);
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

    const auto queue_result = QueuePayloadSubmissionRequestLocked(action);
    if (queue_result != runtime::DebugProbeQueueResult::Queued) {
        logger::Log(
            "Rejected TriggerDebugPayload(action=%u): reason=%u",
            static_cast<unsigned int>(action),
            static_cast<unsigned int>(queue_result));
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

        const auto peer_index = peer.identity.peer_index;
        const auto binding =
            m_runtime_coordinator.BindingSnapshot(peer_index.Value());
        if ((peer.state != wgnx::PeerRuntimeState::Handshaking &&
             peer.state != wgnx::PeerRuntimeState::Active) ||
            !binding.has_endpoint) {
            logger::Log(
                "Rejected BumpUdpBinding: peer=%zu state=%s resolved=%u",
                static_cast<std::size_t>(peer_index.Value()),
                wgnx::GetPeerRuntimeStateName(peer.state),
                binding.has_endpoint ? 1U : 0U);
            R_THROW(ams::fs::ResultInvalidArgument());
        }

        const runtime::UdpRebindRequest request{
            .peer_index = peer_index,
            .activation_generation = peer.identity.activation_generation,
        };
        const auto queue_result = m_receive_pump.QueueRebindLocked(request);
        if (queue_result == runtime::UdpRebindQueueResult::Replaced) {
            logger::Log(
                "Coalesced UDP bind bump peer=%zu activation=%u",
                static_cast<std::size_t>(peer_index.Value()),
                peer.identity.activation_generation.Value());
        } else {
            logger::Log(
                "Queued UDP bind bump peer=%zu activation=%u socket_generation=%u socket=%d",
                static_cast<std::size_t>(peer_index.Value()),
                peer.identity.activation_generation.Value(),
                binding.generation.Value(),
                static_cast<int>(binding.socket));
        }
    }

    m_receive_pump.Queue();
    R_SUCCEED();
}

wgnx::PacketSubmissionResult DaemonRuntime::SubmitInnerIpv4Packet(
    std::span<const std::uint8_t> packet_bytes,
    runtime::ProcessId process_id) {
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
                static_cast<unsigned long long>(process_id.Value()),
                outcome.discarded_outbound,
                outcome.discarded_inbound);
        }
    }

    result.packet_id = outcome.packet_id.Value();
    result.activation_generation = outcome.has_peer
        ? outcome.peer.activation_generation.Value()
        : 0;
    result.peer_index = outcome.has_peer
        ? static_cast<std::int32_t>(outcome.peer.peer_index.Value())
        : -1;
    switch (outcome.status) {
        case runtime::PacketSubmissionStatus::Queued:
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::Queued);
            logger::Log(
                "Queued packet API submission id=%llu pid=%llu peer=%u activation=%u bytes=%zu depth=%zu state=%s",
                static_cast<unsigned long long>(outcome.packet_id.Value()),
                static_cast<unsigned long long>(process_id.Value()),
                outcome.peer.peer_index.Value(),
                outcome.peer.activation_generation.Value(),
                packet_bytes.size(),
                outcome.queue_depth,
                wgnx::GetPeerRuntimeStateName(outcome.peer_state));
            break;
        case runtime::PacketSubmissionStatus::MalformedPacket:
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::MalformedPacket);
            logger::Log(
                "Rejected packet API submission pid=%llu bytes=%zu validation=%s",
                static_cast<unsigned long long>(process_id.Value()),
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
                static_cast<unsigned long long>(process_id.Value()));
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
    runtime::ProcessId process_id) {
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
    result.packet_id = outcome.packet_id.Value();
    result.packet_size = static_cast<std::uint32_t>(outcome.packet_size);
    result.activation_generation = outcome.peer.activation_generation.Value();
    result.peer_index = !outcome.packet_id.IsZero()
        ? static_cast<std::int32_t>(outcome.peer.peer_index.Value())
        : -1;
    switch (outcome.status) {
        case runtime::PacketReceiveStatus::Success:
            result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::Success);
            logger::Log(
                "Delivered packet API receive id=%llu pid=%llu peer=%u activation=%u bytes=%zu remaining=%zu",
                static_cast<unsigned long long>(outcome.packet_id.Value()),
                static_cast<unsigned long long>(process_id.Value()),
                outcome.peer.peer_index.Value(),
                outcome.peer.activation_generation.Value(),
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
                static_cast<unsigned long long>(outcome.packet_id.Value()));
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
    return g_daemon_runtime.SubmitInnerIpv4Packet(
        packet,
        runtime::ProcessId{process_id});
}

wgnx::PacketReceiveResult ReceiveInnerIpv4Packet(
    std::span<std::uint8_t> packet,
    std::uint64_t process_id) {
    return g_daemon_runtime.ReceiveInnerIpv4Packet(
        packet,
        runtime::ProcessId{process_id});
}

} // namespace runtime

} // namespace wgnx::sysmodule
