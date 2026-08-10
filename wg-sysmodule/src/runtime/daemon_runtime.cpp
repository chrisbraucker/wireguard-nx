#include "runtime/daemon_runtime.hpp"
#include "runtime/autostart_persistence.hpp"
#include "runtime/debug_probe_runner.hpp"
#include "runtime/encrypted_receive_pump.hpp"
#include "runtime/endpoint_resolver.hpp"
#include "runtime/horizon_dispatcher.hpp"
#include "runtime/packet_channel.hpp"
#include "runtime/packet_data_plane.hpp"
#include "runtime/tunnel_flow_plane.hpp"
#include "runtime/userspace_ip_adapter_owner.hpp"
#include "runtime/peer_configuration.hpp"
#include "runtime/peer/peer_runtime.hpp"
#include "runtime/runtime_coordinator.hpp"
#include "runtime/runtime_contracts.hpp"
#include "runtime/runtime_effect_executor.hpp"
#include "runtime/timer_scheduler.hpp"
#include "platform/horizon/network_path_service.hpp"

#include "config_loader.hpp"
#include "logger.hpp"
#include "wgnx/platform/clock.hpp"
#include "wgnx/platform/random.hpp"
#include "wgnx/platform/work.hpp"
#include "wgnx/resource_budget.hpp"
#include "wireguard/peer_controller.hpp"
#include "wireguard/timers.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <mutex>
#include <optional>
#include <span>

namespace wgnx::sysmodule {

namespace {

struct DaemonState {
    runtime::PeerRegistry peers{};
    bool initialized{false};
};

class DaemonRuntime {
  public:
    DaemonRuntime();

    void Initialize();
    void Shutdown();
    wgnx::DaemonStatus GetDaemonStatus();
    std::uint32_t CopyPeers(std::span<wgnx::PeerInfo> out);
    ams::Result SetActivePeer(std::int32_t peer_index);
    ams::Result SetAutoStartPeer(std::int32_t peer_index);
    ams::Result TriggerDebugPayload(wgnx::DebugTriggerAction action);
    ams::Result BumpUdpBinding();
    wgnx::PacketSubmissionResult SubmitInnerIpv4Packet(std::span<const std::uint8_t> packet, runtime::ProcessId process_id);
    wgnx::PacketReceiveResult ReceiveInnerIpv4Packet(std::span<std::uint8_t> packet, runtime::ProcessId process_id);
    runtime::TunnelClientId CreateTunnelClient(runtime::TunnelFlowPlane::CompletionNotifier notifier, void* notifier_context);
    void DestroyTunnelClient(runtime::TunnelClientId client);
    std::uint32_t SignalTunnelClientShutdown();
    wgnx::tunnel::Capabilities GetTunnelCapabilities();
    wgnx::tunnel::RoutingPolicySnapshot CopyTunnelRoutingPolicy(std::span<wgnx::tunnel::RouteRecord> out);
    wgnx::tunnel::OpenConnectedFlowResult OpenTunnelConnectedUdpFlow(
        runtime::TunnelClientId client, const wgnx::tunnel::OpenConnectedFlowRequest& request
    );
    wgnx::tunnel::ProtocolStatus SendTunnelUdpDatagram(
        runtime::TunnelClientId client, const wgnx::tunnel::PayloadRange& descriptor, std::span<const std::uint8_t> payload
    );
    runtime::TunnelCompletionDrainOutcome ReceiveTunnelCompletions(
        runtime::TunnelClientId client,
        std::span<wgnx::tunnel::CompletionRecord> records,
        std::span<std::uint8_t> payload,
        runtime::TunnelFlowPlane::CompletionNotifier clear_notifier,
        void* clear_context
    );
    wgnx::tunnel::FlowStateResult GetTunnelFlowState(runtime::TunnelClientId client, wgnx::tunnel::FlowHandle flow);
    wgnx::tunnel::ProtocolStatus CloseTunnelFlow(runtime::TunnelClientId client, wgnx::tunnel::FlowHandle flow);

  private:
    static void ResolverWorkCallback(wgnx::platform::work_struct* work);
    static void PayloadSubmissionWorkCallback(wgnx::platform::work_struct* work);
    static void InnerPacketSubmissionWorkCallback(wgnx::platform::work_struct* work);
    static void UserspaceIpAdapterWorkCallback(wgnx::platform::work_struct* work);
    static void PendingDatagramTransmitWorkCallback(wgnx::platform::work_struct* work);
    static void ReceiveWorkCallback(wgnx::platform::work_struct* work);
    static void ProtocolTimerCallback(wgnx::wireguard::TimerHook hook, const wgnx::wireguard::TimerToken& token);
    static void DebugProbeTimeoutCallback();
    static void UserspaceIpTimeoutCallback();

    void ClearInnerPacketStateLocked(const char* reason);
    runtime::EffectBatch SetPeerInactive(std::size_t peer_index);
    runtime::DebugProbeQueueResult QueuePayloadSubmissionRequestLocked(wgnx::DebugTriggerAction action);
    wgnx::PeerInfo BuildPeerInfo(std::size_t peer_index);
    bool HasRuntimeErrors();
    void EnsureInitialized();
    void InitializeStateLocked();
    bool CaptureAutoStartPersistenceRequestLocked(std::int32_t peer_index, runtime::AutoStartPersistenceRequest& out_request);
    bool IsCurrentAutoStartPersistenceRequestLocked(const runtime::AutoStartPersistenceRequest& request) const;
    bool IsValidPeerIndex(std::int32_t peer_index) const;
    void ExecuteRuntimeEffects(const runtime::EffectBatch& effects);
    void InitializeHorizonDispatcher();
    void RefreshTunnelPolicyLocked();
    void DeliverUserspaceIpInputLocked(const runtime::UserspaceIpAdapterOwner::Operation& operation);

    static DaemonRuntime* s_instance;
    DaemonState m_state{};
    ams::os::Mutex m_state_mutex;
    ams::os::Mutex m_initialization_mutex;
    ams::os::Mutex m_auto_start_persistence_mutex;
    runtime::EndpointResolver m_endpoint_resolver{};
    runtime::HorizonDispatcher m_horizon_dispatcher{};
    runtime::TimerScheduler m_timer_scheduler{};
    runtime::PacketChannel m_packet_channel{};
    runtime::RuntimeCoordinator m_runtime_coordinator;
    runtime::PacketDataPlane m_packet_data_plane;
    runtime::TunnelFlowPlane m_tunnel_flow_plane{};
    runtime::UserspaceIpAdapterOwner m_userspace_ip_adapter_owner{};
    runtime::DebugProbeRunner m_debug_probe_runner{};
    platform::horizon::NetworkPathService m_network_path_service{};
    runtime::PeerConfigurationLoader m_peer_configuration_loader{};
    runtime::LoadedPeerConfiguration m_loaded_peer_configuration{};
    runtime::AutoStartPersistenceState m_auto_start_persistence{};
    runtime::EncryptedReceivePump m_receive_pump;
    runtime::RuntimeEffectExecutor m_effect_executor;
};

static_assert(sizeof(runtime::TunnelFlowPlane) <= wgnx::resource_budget::MaximumTunnelFlowPlaneBytes);
static_assert(sizeof(DaemonRuntime) <= wgnx::resource_budget::MaximumDaemonRuntimeBytes);

DaemonRuntime* DaemonRuntime::s_instance = nullptr;

DaemonRuntime::DaemonRuntime()
    : m_state_mutex(false), m_initialization_mutex(false), m_auto_start_persistence_mutex(false), m_runtime_coordinator(m_state.peers),
      m_packet_data_plane(m_runtime_coordinator, m_packet_channel),
      m_receive_pump(m_state_mutex, m_runtime_coordinator, m_horizon_dispatcher), m_effect_executor(
                                                                                      m_state_mutex,
                                                                                      m_runtime_coordinator,
                                                                                      m_endpoint_resolver,
                                                                                      m_horizon_dispatcher,
                                                                                      m_timer_scheduler,
                                                                                      m_packet_data_plane,
                                                                                      m_tunnel_flow_plane,
                                                                                      m_userspace_ip_adapter_owner,
                                                                                      m_debug_probe_runner,
                                                                                      m_network_path_service,
                                                                                      m_receive_pump
                                                                                  ) {
    AMS_ABORT_UNLESS(s_instance == nullptr);
    s_instance = this;
}

wgnx::platform::ktime_t GetRuntimeNowNs() {
    return wgnx::platform::ktime_get_coarse_boottime_ns();
}

void DaemonRuntime::ClearInnerPacketStateLocked(const char* reason) {
    const auto cleared = m_packet_data_plane.Clear();
    if (cleared.outbound_count != 0 || cleared.inbound_count != 0) {
        logger::Log(
            "Cleared inner packet state reason=%s tx=%zu rx=%zu",
            reason != nullptr ? reason : "unspecified",
            cleared.outbound_count,
            cleared.inbound_count
        );
    }
}

runtime::EffectBatch DaemonRuntime::SetPeerInactive(std::size_t peer_index) {
    const auto* lifecycle = m_runtime_coordinator.Lifecycle(peer_index);
    AMS_ABORT_UNLESS(lifecycle != nullptr);
    const runtime::PeerIdentity peer{
        .peer_index = runtime::PeerIndex{static_cast<std::uint32_t>(peer_index)},
        .activation_generation = lifecycle->activation_generation,
    };
    m_tunnel_flow_plane.InvalidatePeerActivation(peer, wgnx::tunnel::FlowTerminalReason::PeerDeactivated, GetRuntimeNowNs());
    m_userspace_ip_adapter_owner.QueueResetLocked();
    m_debug_probe_runner.Cancel(&peer);
    ClearInnerPacketStateLocked("peer inactive");
    auto effects = m_runtime_coordinator.Dispatch(
        runtime::DeactivationRequestedEvent{
            .peer = peer,
            .occurred_at = GetRuntimeNowNs(),
        }
    );
    effects.Add(runtime::CancelDebugProbeTimeoutEffect{});
    return effects;
}

[[maybe_unused]] runtime::DebugProbeQueueResult DaemonRuntime::QueuePayloadSubmissionRequestLocked(wgnx::DebugTriggerAction action) {
    runtime::DebugPeerSnapshot peer{};
    if (!m_runtime_coordinator.SnapshotDebugPeer(peer)) {
        return runtime::DebugProbeQueueResult::NoActivePeer;
    }
    return m_debug_probe_runner.Queue(peer.peer, peer.source_address.data(), action, GetRuntimeNowNs());
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

void DaemonRuntime::InitializeStateLocked() {
    if (m_state.initialized) {
        return;
    }

    auto& config = m_loaded_peer_configuration;
    if (config.peer_count != 0) {
        const bool assigned = m_runtime_coordinator.Configure(
            std::span<const wgnx::PeerConfigEntry>(config.peers).first(config.peer_count),
            std::span<runtime::PeerConfigDerivedInfo>(config.derived).first(config.peer_count),
            config.auto_start_peer_index,
            GetRuntimeNowNs()
        );
        AMS_ABORT_UNLESS(assigned);
    } else {
        const auto cleanup_effects = m_runtime_coordinator.ClearConfiguration(GetRuntimeNowNs());
        AMS_ABORT_UNLESS(cleanup_effects.Empty());
    }
    config.~LoadedPeerConfiguration();
    std::construct_at(std::addressof(config));

    m_state.initialized = true;
    logger::Log("Initialized peer state with %u configured peer(s)", m_runtime_coordinator.PeerCount());
}

void DaemonRuntime::EnsureInitialized() {
    std::scoped_lock initialization_lock(m_initialization_mutex);
    {
        std::scoped_lock state_lock(m_state_mutex);
        if (m_state.initialized) {
            return;
        }
    }

    auto& config = m_loaded_peer_configuration;
    if (!m_peer_configuration_loader.Load(config)) {
        config.peer_count = 0;
    }

    std::scoped_lock state_lock(m_state_mutex);
    InitializeStateLocked();
}

bool DaemonRuntime::CaptureAutoStartPersistenceRequestLocked(std::int32_t peer_index, runtime::AutoStartPersistenceRequest& out_request) {
    if (!IsValidPeerIndex(peer_index)) {
        return false;
    }

    const char* peer_name = nullptr;
    if (peer_index >= 0) {
        const auto* configuration = m_runtime_coordinator.Configuration(static_cast<std::size_t>(peer_index));
        if (configuration == nullptr) {
            return false;
        }
        peer_name = configuration->name.data();
    }
    out_request = m_auto_start_persistence.Begin(peer_index, peer_name);
    return true;
}

bool DaemonRuntime::IsCurrentAutoStartPersistenceRequestLocked(const runtime::AutoStartPersistenceRequest& request) const {
    if (!m_auto_start_persistence.IsCurrent(request) || !IsValidPeerIndex(request.peer_index)) {
        return false;
    }
    if (request.peer_index < 0) {
        return true;
    }
    const auto* configuration = m_runtime_coordinator.Configuration(static_cast<std::size_t>(request.peer_index));
    return configuration != nullptr && std::strncmp(configuration->name.data(), request.peer_name.data(), request.peer_name.size()) == 0;
}

bool DaemonRuntime::IsValidPeerIndex(std::int32_t peer_index) const {
    return m_runtime_coordinator.IsValidSelection(peer_index);
}

void DaemonRuntime::RefreshTunnelPolicyLocked() {
    const std::int32_t active_peer_index = m_runtime_coordinator.ActivePeerIndex();
    if (active_peer_index < 0) {
        m_tunnel_flow_plane.RefreshPolicy({}, GetRuntimeNowNs());
        return;
    }
    const auto* configuration = m_runtime_coordinator.Configuration(static_cast<std::size_t>(active_peer_index));
    const auto* lifecycle = m_runtime_coordinator.Lifecycle(static_cast<std::size_t>(active_peer_index));
    if (configuration == nullptr || lifecycle == nullptr || lifecycle->activation_generation.IsZero()) {
        m_tunnel_flow_plane.RefreshPolicy({}, GetRuntimeNowNs());
        return;
    }
    m_tunnel_flow_plane.RefreshPolicy(
        {
            .configuration = configuration,
            .peer =
                {
                    .peer_index = runtime::PeerIndex{static_cast<std::uint32_t>(active_peer_index)},
                    .activation_generation = lifecycle->activation_generation,
                },
            .selected = true,
        },
        GetRuntimeNowNs()
    );
}

void DaemonRuntime::ExecuteRuntimeEffects(const runtime::EffectBatch& effects) {
    m_effect_executor.Execute(effects);
}

void DaemonRuntime::ResolverWorkCallback(wgnx::platform::work_struct* work) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    static_cast<void>(work);
    s_instance->m_effect_executor.RunEndpointResolver();
}

void DaemonRuntime::PayloadSubmissionWorkCallback(wgnx::platform::work_struct* work) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    static_cast<void>(work);
    s_instance->m_effect_executor.RunDebugPayloadSubmission();
}

void DaemonRuntime::InnerPacketSubmissionWorkCallback(wgnx::platform::work_struct* work) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    static_cast<void>(work);
    s_instance->m_effect_executor.RunInnerPacketSubmission();
}

void DaemonRuntime::UserspaceIpAdapterWorkCallback(wgnx::platform::work_struct* work) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    static_cast<void>(work);
    while (true) {
        std::optional<runtime::UserspaceIpAdapterOwner::Operation> operation{};
        {
            std::scoped_lock lock(s_instance->m_state_mutex);
            operation = s_instance->m_userspace_ip_adapter_owner.TakeNextLocked();
        }
        if (!operation.has_value()) {
            return;
        }
        ip::UserspaceIpResult result = ip::UserspaceIpResult::TransportError;
        bool execute = true;
        if (operation->kind == runtime::UserspaceIpAdapterOwner::OperationKind::InputPacket) {
            std::scoped_lock lock(s_instance->m_state_mutex);
            execute = s_instance->m_runtime_coordinator.IsActiveIdentity(operation->peer) &&
                      s_instance->m_tunnel_flow_plane.PolicyGeneration() == operation->policy_generation &&
                      s_instance->m_userspace_ip_adapter_owner.AdapterEpochLocked() == operation->adapter_epoch;
        }
        if (execute) {
            result = s_instance->m_userspace_ip_adapter_owner.Execute(*operation);
        } else {
            result = ip::UserspaceIpResult::Stale;
        }
        if (operation->kind == runtime::UserspaceIpAdapterOwner::OperationKind::Reset) {
            const auto& statistics = s_instance->m_userspace_ip_adapter_owner.Statistics();
            logger::Log(
                "lwip adapter reset summary resets=%llu collateral_fragments=%llu inputs=%llu rejected=%llu "
                "reassemblies=%llu callbacks=%llu callback_rejected=%llu pbuf_rejected=%llu",
                static_cast<unsigned long long>(statistics.resets),
                static_cast<unsigned long long>(statistics.collateral_fragment_resets),
                static_cast<unsigned long long>(statistics.input_packets),
                static_cast<unsigned long long>(statistics.input_rejections),
                static_cast<unsigned long long>(statistics.reassembly_successes),
                static_cast<unsigned long long>(statistics.callback_deliveries),
                static_cast<unsigned long long>(statistics.callback_rejections),
                static_cast<unsigned long long>(statistics.pbuf_rejections)
            );
        }
        const std::uint32_t timeout_delay_ms = s_instance->m_userspace_ip_adapter_owner.NextTimeoutDelayMs();
        if (timeout_delay_ms == std::numeric_limits<std::uint32_t>::max()) {
            s_instance->m_timer_scheduler.CancelUserspaceIpTimeout();
        } else {
            s_instance->m_timer_scheduler.ArmUserspaceIpTimeout(timeout_delay_ms);
        }
        {
            std::scoped_lock lock(s_instance->m_state_mutex);
            s_instance->m_userspace_ip_adapter_owner.CompleteLocked(*operation, result);
            if (operation->kind == runtime::UserspaceIpAdapterOwner::OperationKind::InputPacket) {
                if (result == ip::UserspaceIpResult::Success) {
                    s_instance->DeliverUserspaceIpInputLocked(*operation);
                } else if (result == ip::UserspaceIpResult::Stale) {
                    logger::Log(
                        "Dropped decrypted inner packet peer=%u activation=%u reason=stale_adapter_input",
                        operation->peer.peer_index.Value(),
                        operation->peer.activation_generation.Value()
                    );
                }
                static_cast<void>(s_instance->m_userspace_ip_adapter_owner.TakeResultLocked(operation->ticket));
            }
        }
    }
}

void DaemonRuntime::DeliverUserspaceIpInputLocked(const runtime::UserspaceIpAdapterOwner::Operation& operation) {
    const auto packet = m_userspace_ip_adapter_owner.InputPacketLocked(operation.ticket);
    AMS_ABORT_UNLESS(!packet.empty());
    const auto datagrams = m_userspace_ip_adapter_owner.InboundDatagramsLocked(operation.ticket);
    if (datagrams.empty() && (m_userspace_ip_adapter_owner.HadInboundDatagramRejectionLocked(operation.ticket) ||
                              m_userspace_ip_adapter_owner.HadInputRejectionLocked(operation.ticket) ||
                              m_userspace_ip_adapter_owner.HasPendingInboundFragmentLocked(operation.ticket))) {
        logger::LogPacket(
            "Dropped decrypted inner packet peer=%u activation=%u reason=lwip_input_unclaimed",
            operation.peer.peer_index.Value(),
            operation.peer.activation_generation.Value()
        );
        return;
    }
    if (datagrams.empty()) {
        const auto delivery = m_packet_data_plane.DeliverDecryptedPacket(operation.peer, packet);
        if (delivery.status == runtime::PacketDeliveryStatus::Queued) {
            logger::Log(
                "Queued decrypted inner packet id=%llu peer=%u activation=%u bytes=%zu depth=%zu",
                static_cast<unsigned long long>(delivery.packet_id.Value()),
                operation.peer.peer_index.Value(),
                operation.peer.activation_generation.Value(),
                packet.size(),
                delivery.queue_depth
            );
        }
        return;
    }
    AMS_ABORT_UNLESS(datagrams.size() == 1);
    const auto& datagram = datagrams.front();
    const auto tunnel_delivery = m_tunnel_flow_plane.DeliverInboundUdpDatagram(
        operation.peer,
        operation.policy_generation,
        datagram.token,
        datagram.remote,
        std::span<const std::uint8_t>(datagram.payload).first(datagram.size),
        GetRuntimeNowNs()
    );
    switch (tunnel_delivery.disposition) {
    case runtime::TunnelInboundDisposition::Delivered:
        logger::LogPacket(
            "Queued tunnel UDP delivery flow=%llu peer=%u activation=%u bytes=%zu",
            static_cast<unsigned long long>(tunnel_delivery.flow.value),
            operation.peer.peer_index.Value(),
            operation.peer.activation_generation.Value(),
            tunnel_delivery.payload_size
        );
        return;
    case runtime::TunnelInboundDisposition::DroppedMalformed:
        logger::LogPacket(
            "Dropped tunnel UDP delivery peer=%u activation=%u reason=malformed",
            operation.peer.peer_index.Value(),
            operation.peer.activation_generation.Value()
        );
        return;
    case runtime::TunnelInboundDisposition::DroppedStale:
        logger::LogPacket(
            "Dropped tunnel UDP delivery peer=%u activation=%u reason=reverse_tuple_quarantine",
            operation.peer.peer_index.Value(),
            operation.peer.activation_generation.Value()
        );
        return;
    case runtime::TunnelInboundDisposition::DroppedQueueFull:
        logger::LogPacket(
            "Dropped tunnel UDP delivery flow=%llu peer=%u activation=%u reason=queue_full",
            static_cast<unsigned long long>(tunnel_delivery.flow.value),
            operation.peer.peer_index.Value(),
            operation.peer.activation_generation.Value()
        );
        return;
    case runtime::TunnelInboundDisposition::NotClaimed:
    case runtime::TunnelInboundDisposition::DroppedUnknown:
        logger::LogPacket(
            "Dropped tunnel UDP delivery peer=%u activation=%u reason=unknown_adapter_flow",
            operation.peer.peer_index.Value(),
            operation.peer.activation_generation.Value()
        );
        return;
    }
}

void DaemonRuntime::PendingDatagramTransmitWorkCallback(wgnx::platform::work_struct* work) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    static_cast<void>(work);
    s_instance->m_effect_executor.RunPendingDatagramTransmit();
}

void DaemonRuntime::ReceiveWorkCallback(wgnx::platform::work_struct* work) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    static_cast<void>(work);
    s_instance->m_receive_pump.Run(s_instance->m_effect_executor);
}

void DaemonRuntime::ProtocolTimerCallback(wgnx::wireguard::TimerHook hook, const wgnx::wireguard::TimerToken& token) {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    s_instance->m_effect_executor.RunProtocolTimer(hook, token);
}

void DaemonRuntime::DebugProbeTimeoutCallback() {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    s_instance->m_effect_executor.RunDebugProbeTimeout();
}

void DaemonRuntime::UserspaceIpTimeoutCallback() {
    AMS_ABORT_UNLESS(s_instance != nullptr);
    {
        std::scoped_lock lock(s_instance->m_state_mutex);
        s_instance->m_userspace_ip_adapter_owner.QueueRunTimeoutsLocked();
    }
    static_cast<void>(s_instance->m_horizon_dispatcher.QueueUserspaceIpAdapter());
}

void DaemonRuntime::InitializeHorizonDispatcher() {
    m_horizon_dispatcher.Initialize({
        .resolve = ResolverWorkCallback,
        .submit_debug_payload = PayloadSubmissionWorkCallback,
        .submit_inner_packet = InnerPacketSubmissionWorkCallback,
        .run_userspace_ip_adapter = UserspaceIpAdapterWorkCallback,
        .transmit_datagram = PendingDatagramTransmitWorkCallback,
        .receive = ReceiveWorkCallback,
    });
    m_timer_scheduler.Initialize(
        m_horizon_dispatcher,
        {
            .protocol_timer = ProtocolTimerCallback,
            .debug_probe_timeout = DebugProbeTimeoutCallback,
            .userspace_ip_timeout = UserspaceIpTimeoutCallback,
        }
    );

    logger::Log("Started endpoint resolver worker");
    logger::Log("Started shared payload, inner packet, and userspace IP submission worker");
    logger::Log("Started serialized encrypted datagram transmit worker");
    logger::Log("Started UDP receive worker");
    logger::Log("NIFM network-path requests are event-driven and activation-owned");
    logger::Log("Started transport timer executor");
}

wgnx::DaemonStatus DaemonRuntime::GetDaemonStatus() {
    ON_SCOPE_EXIT {
        logger::Flush();
    };
    EnsureInitialized();
    std::scoped_lock lock(m_state_mutex);

    return {
        .abi_version = wgnx::IpcApiVersion,
        .peer_count = m_runtime_coordinator.PeerCount(),
        .active_peer_index = m_runtime_coordinator.ActivePeerIndex(),
        .auto_start_peer_index = m_runtime_coordinator.AutoStartPeerIndex(),
        .flags = runtime::BuildDaemonFlags(m_runtime_coordinator.ActivePeerIndex() >= 0, HasRuntimeErrors()),
        .reserved = 0,
    };
}

std::uint32_t DaemonRuntime::CopyPeers(std::span<wgnx::PeerInfo> out) {
    ON_SCOPE_EXIT {
        logger::Flush();
    };
    EnsureInitialized();
    std::scoped_lock lock(m_state_mutex);

    const std::size_t copy_count = std::min<std::size_t>(out.size(), m_runtime_coordinator.PeerCount());
    for (std::size_t i = 0; i < copy_count; ++i) {
        out[i] = BuildPeerInfo(i);
    }

    return m_runtime_coordinator.PeerCount();
}

ams::Result DaemonRuntime::SetActivePeer(std::int32_t peer_index) {
    ON_SCOPE_EXIT {
        logger::Flush();
    };
    EnsureInitialized();
    std::unique_lock lock(m_state_mutex);

    if (!IsValidPeerIndex(peer_index)) {
        logger::Log("Rejected SetActivePeer(%d): invalid index", peer_index);
        R_THROW(ams::fs::ResultInvalidArgument());
    }

    if (peer_index == m_runtime_coordinator.ActivePeerIndex()) {
        logger::Log("SetActivePeer(%d): no change", peer_index);
        R_SUCCEED();
    }

    runtime::EffectBatch effects{};
    bool adapter_work_pending = false;
    if (m_runtime_coordinator.ActivePeerIndex() >= 0 && m_runtime_coordinator.ActivePeerIndex() != peer_index) {
        const std::size_t old_index = static_cast<std::size_t>(m_runtime_coordinator.ActivePeerIndex());
        effects = SetPeerInactive(old_index);
    }

    AMS_ABORT_UNLESS(m_runtime_coordinator.SetActivePeerIndex(peer_index));
    if (peer_index >= 0) {
        const auto activation_effects = m_runtime_coordinator.Dispatch(
            runtime::ActivationRequestedEvent{
                .peer_index = runtime::PeerIndex{static_cast<std::uint32_t>(peer_index)},
                .occurred_at = GetRuntimeNowNs(),
            }
        );
        effects.Append(activation_effects);
    }
    RefreshTunnelPolicyLocked();
    adapter_work_pending = m_userspace_ip_adapter_owner.HasPendingWork();
    logger::Log("SetActivePeer(%d)", peer_index);
    lock.unlock();
    if (adapter_work_pending) {
        static_cast<void>(m_horizon_dispatcher.QueueUserspaceIpAdapter());
    }
    ExecuteRuntimeEffects(effects);
    R_SUCCEED();
}

ams::Result DaemonRuntime::SetAutoStartPeer(std::int32_t peer_index) {
    ON_SCOPE_EXIT {
        logger::Flush();
    };
    EnsureInitialized();
    runtime::AutoStartPersistenceRequest request{};
    {
        std::scoped_lock lock(m_state_mutex);
        if (!CaptureAutoStartPersistenceRequestLocked(peer_index, request)) {
            logger::Log("Rejected SetAutoStartPeer(%d): invalid index", peer_index);
            R_THROW(ams::fs::ResultInvalidArgument());
        }
    }

    std::scoped_lock persistence_lock(m_auto_start_persistence_mutex);
    {
        std::scoped_lock state_lock(m_state_mutex);
        if (!IsCurrentAutoStartPersistenceRequestLocked(request)) {
            logger::Log("Discarded stale SetAutoStartPeer(%d) before persistence generation=%u", peer_index, request.generation.Value());
            R_SUCCEED();
        }
    }

    const char* peer_name = peer_index >= 0 ? request.peer_name.data() : nullptr;
    const ams::Result store_rc = StoreAutoStartPeerName(peer_name);
    if (R_FAILED(store_rc)) {
        logger::Log("Rejected SetAutoStartPeer(%d): persist failed rc=0x%08x", peer_index, static_cast<u32>(store_rc.GetValue()));
        R_THROW(store_rc);
    }

    {
        std::scoped_lock state_lock(m_state_mutex);
        if (!IsCurrentAutoStartPersistenceRequestLocked(request)) {
            logger::Log("Discarded stale SetAutoStartPeer(%d) after persistence generation=%u", peer_index, request.generation.Value());
            R_SUCCEED();
        }
        AMS_ABORT_UNLESS(m_runtime_coordinator.SetAutoStartPeerIndex(peer_index));
    }
    logger::Log("SetAutoStartPeer(%d)", peer_index);
    R_SUCCEED();
}

ams::Result DaemonRuntime::TriggerDebugPayload(wgnx::DebugTriggerAction action) {
    ON_SCOPE_EXIT {
        logger::Flush();
    };
    EnsureInitialized();
    runtime::DebugProbeQueueResult queue_result{};
    {
        std::scoped_lock lock(m_state_mutex);
        queue_result = QueuePayloadSubmissionRequestLocked(action);
    }
    if (queue_result != runtime::DebugProbeQueueResult::Queued) {
        logger::Log(
            "Rejected TriggerDebugPayload(action=%u): reason=%u",
            static_cast<unsigned int>(action),
            static_cast<unsigned int>(queue_result)
        );
        R_THROW(ams::fs::ResultInvalidArgument());
    }
    m_horizon_dispatcher.QueueDebugPayloadSubmission();
    logger::Log("Queued debug payload trigger action=%s", wgnx::GetDebugTriggerActionName(action));
    R_SUCCEED();
}

ams::Result DaemonRuntime::BumpUdpBinding() {
    ON_SCOPE_EXIT {
        logger::Flush();
    };
    EnsureInitialized();
    {
        std::scoped_lock lock(m_state_mutex);
        runtime::PeerPacketStateSnapshot peer{};
        if (!m_runtime_coordinator.SnapshotPacketState(peer)) {
            logger::Log("Rejected BumpUdpBinding: no active peer");
            R_THROW(ams::fs::ResultInvalidArgument());
        }

        const auto peer_index = peer.identity.peer_index;
        const auto binding = m_runtime_coordinator.BindingSnapshot(peer_index.Value());
        if ((peer.state != wgnx::PeerRuntimeState::Handshaking && peer.state != wgnx::PeerRuntimeState::Active) || !binding.has_endpoint) {
            logger::Log(
                "Rejected BumpUdpBinding: peer=%zu state=%s resolved=%u",
                static_cast<std::size_t>(peer_index.Value()),
                wgnx::GetPeerRuntimeStateName(peer.state),
                binding.has_endpoint ? 1U : 0U
            );
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
                peer.identity.activation_generation.Value()
            );
        } else {
            logger::Log(
                "Queued UDP bind bump peer=%zu activation=%u socket_generation=%u socket=%d",
                static_cast<std::size_t>(peer_index.Value()),
                peer.identity.activation_generation.Value(),
                binding.generation.Value(),
                static_cast<int>(binding.socket)
            );
        }
    }

    m_receive_pump.Queue();
    R_SUCCEED();
}

wgnx::PacketSubmissionResult DaemonRuntime::SubmitInnerIpv4Packet(
    std::span<const std::uint8_t> packet_bytes, runtime::ProcessId process_id
) {
    wgnx::PacketSubmissionResult result = {
        .packet_id = 0,
        .status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::InternalError),
        .packet_size = static_cast<std::uint32_t>(packet_bytes.size()),
        .activation_generation = 0,
        .peer_index = -1,
    };

    ON_SCOPE_EXIT {
        logger::Flush();
    };
    EnsureInitialized();
    runtime::EffectBatch effects{};
    runtime::PacketSubmissionOutcome outcome{};
    const auto timer_facts = runtime::CaptureTimerFacts();
    {
        std::scoped_lock lock(m_state_mutex);
        outcome = m_packet_data_plane.SubmitIpv4Packet(packet_bytes, process_id, timer_facts, GetRuntimeNowNs(), effects);
        if (outcome.ownership_transferred) {
            logger::Log(
                "Transferred packet API ownership pid=%llu discarded_tx=%zu discarded_rx=%zu",
                static_cast<unsigned long long>(process_id.Value()),
                outcome.discarded_outbound,
                outcome.discarded_inbound
            );
        }
    }

    result.packet_id = outcome.packet_id.Value();
    result.activation_generation = outcome.has_peer ? outcome.peer.activation_generation.Value() : 0;
    result.peer_index = outcome.has_peer ? static_cast<std::int32_t>(outcome.peer.peer_index.Value()) : -1;
    switch (outcome.status) {
    case runtime::PacketSubmissionStatus::Queued:
        result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::Queued);
        logger::LogPacket(
            "Queued packet API submission id=%llu pid=%llu peer=%u activation=%u bytes=%zu depth=%zu state=%s",
            static_cast<unsigned long long>(outcome.packet_id.Value()),
            static_cast<unsigned long long>(process_id.Value()),
            outcome.peer.peer_index.Value(),
            outcome.peer.activation_generation.Value(),
            packet_bytes.size(),
            outcome.queue_depth,
            wgnx::GetPeerRuntimeStateName(outcome.peer_state)
        );
        break;
    case runtime::PacketSubmissionStatus::MalformedPacket:
        result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::MalformedPacket);
        logger::LogPacket(
            "Rejected packet API submission pid=%llu bytes=%zu validation=%s",
            static_cast<unsigned long long>(process_id.Value()),
            packet_bytes.size(),
            wgnx::wireguard::GetInnerIpValidationErrorName(outcome.validation)
        );
        break;
    case runtime::PacketSubmissionStatus::TunnelUnavailable:
        result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::TunnelUnavailable);
        break;
    case runtime::PacketSubmissionStatus::QueueFull:
        result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::QueueFull);
        logger::LogPacket(
            "Rejected packet API submission pid=%llu reason=tx_queue_full",
            static_cast<unsigned long long>(process_id.Value())
        );
        break;
    case runtime::PacketSubmissionStatus::InternalError:
        result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::InternalError);
        break;
    }

    ExecuteRuntimeEffects(effects);
    return result;
}

wgnx::PacketReceiveResult DaemonRuntime::ReceiveInnerIpv4Packet(std::span<std::uint8_t> packet, runtime::ProcessId process_id) {
    wgnx::PacketReceiveResult result = {
        .packet_id = 0,
        .status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::QueueEmpty),
        .packet_size = 0,
        .activation_generation = 0,
        .peer_index = -1,
    };

    ON_SCOPE_EXIT {
        logger::Flush();
    };
    EnsureInitialized();
    runtime::PacketReceiveOutcome outcome{};
    {
        std::scoped_lock lock(m_state_mutex);
        outcome = m_packet_data_plane.ReceivePacket(packet, process_id);
    }
    result.packet_id = outcome.packet_id.Value();
    result.packet_size = static_cast<std::uint32_t>(outcome.packet_size);
    result.activation_generation = outcome.peer.activation_generation.Value();
    result.peer_index = !outcome.packet_id.IsZero() ? static_cast<std::int32_t>(outcome.peer.peer_index.Value()) : -1;
    switch (outcome.status) {
    case runtime::PacketReceiveStatus::Success:
        result.status = static_cast<std::uint32_t>(wgnx::PacketApiStatus::Success);
        logger::LogPacket(
            "Delivered packet API receive id=%llu pid=%llu peer=%u activation=%u bytes=%zu remaining=%zu",
            static_cast<unsigned long long>(outcome.packet_id.Value()),
            static_cast<unsigned long long>(process_id.Value()),
            outcome.peer.peer_index.Value(),
            outcome.peer.activation_generation.Value(),
            outcome.packet_size,
            outcome.queue_depth
        );
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
        logger::LogPacket(
            "Discarded packet API receive id=%llu reason=stale_activation",
            static_cast<unsigned long long>(outcome.packet_id.Value())
        );
        break;
    }
    return result;
}

runtime::TunnelClientId DaemonRuntime::CreateTunnelClient(runtime::TunnelFlowPlane::CompletionNotifier notifier, void* notifier_context) {
    EnsureInitialized();
    std::scoped_lock lock(m_state_mutex);
    RefreshTunnelPolicyLocked();
    return m_tunnel_flow_plane.CreateClient(notifier, notifier_context);
}

void DaemonRuntime::DestroyTunnelClient(runtime::TunnelClientId client) {
    if (!client.IsValid()) {
        return;
    }
    EnsureInitialized();
    std::array<std::uint64_t, wgnx::tunnel::MaximumFlowsPerClient> adapter_tokens{};
    std::uint32_t token_count = 0;
    {
        std::scoped_lock lock(m_state_mutex);
        token_count = m_tunnel_flow_plane.CopyClientAdapterTokens(client, adapter_tokens);
        m_tunnel_flow_plane.DestroyClient(client, GetRuntimeNowNs());
    }
    for (std::uint32_t index = 0; index < token_count && index < adapter_tokens.size(); ++index) {
        runtime::UserspaceIpAdapterOwner::OperationTicket ticket{};
        {
            std::scoped_lock lock(m_state_mutex);
            if (m_userspace_ip_adapter_owner.QueueCloseFlowLocked(adapter_tokens[index], &ticket) !=
                runtime::UserspaceIpAdapterOwner::QueueResult::Queued) {
                continue;
            }
        }
        const auto queue_result = m_horizon_dispatcher.QueueUserspaceIpAdapter();
        if (queue_result == wgnx::platform::queue_work_result::capacity_exhausted ||
            queue_result == wgnx::platform::queue_work_result::unavailable) {
            std::scoped_lock lock(m_state_mutex);
            m_userspace_ip_adapter_owner.CancelLocked(ticket);
            continue;
        }
        m_horizon_dispatcher.FlushSubmissionWork();
        std::scoped_lock lock(m_state_mutex);
        static_cast<void>(m_userspace_ip_adapter_owner.TakeResultLocked(ticket));
    }
}

std::uint32_t DaemonRuntime::SignalTunnelClientShutdown() {
    EnsureInitialized();
    std::scoped_lock lock(m_state_mutex);
    return m_tunnel_flow_plane.SignalAllClientCompletionEvents();
}

wgnx::tunnel::Capabilities DaemonRuntime::GetTunnelCapabilities() {
    EnsureInitialized();
    std::scoped_lock lock(m_state_mutex);
    RefreshTunnelPolicyLocked();
    return m_tunnel_flow_plane.GetCapabilities();
}

wgnx::tunnel::RoutingPolicySnapshot DaemonRuntime::CopyTunnelRoutingPolicy(std::span<wgnx::tunnel::RouteRecord> out) {
    EnsureInitialized();
    std::scoped_lock lock(m_state_mutex);
    RefreshTunnelPolicyLocked();
    return m_tunnel_flow_plane.CopyRoutingPolicy(out);
}

wgnx::tunnel::OpenConnectedFlowResult DaemonRuntime::OpenTunnelConnectedUdpFlow(
    runtime::TunnelClientId client, const wgnx::tunnel::OpenConnectedFlowRequest& request
) {
    EnsureInitialized();
    runtime::TunnelFlowReservation reservation{};
    runtime::UserspaceIpAdapterOwner::OperationTicket ticket{};
    {
        std::scoped_lock lock(m_state_mutex);
        RefreshTunnelPolicyLocked();
        runtime::PeerPacketStateSnapshot peer{};
        const bool packet_state_available = m_runtime_coordinator.SnapshotPacketState(peer);
        reservation = m_tunnel_flow_plane.ReserveConnectedUdpFlow(
            client,
            request,
            GetRuntimeNowNs(),
            {
                .protocol_available = packet_state_available && peer.protocol_instantiated,
                .staging_available = packet_state_available && peer.protocol_instantiated && peer.can_stage_packet,
            }
        );
        if (!reservation.IsReserved()) {
            return reservation.result;
        }
        m_userspace_ip_adapter_owner.QueueConfigureLocked(
            {reservation.local.address[0], reservation.local.address[1], reservation.local.address[2], reservation.local.address[3]},
            m_tunnel_flow_plane.GetCapabilities().effective_inner_mtu
        );
        if (m_userspace_ip_adapter_owner.QueueOpenFlowLocked(
                {
                    .token = reservation.adapter_token,
                    .local = reservation.local,
                    .remote = reservation.remote,
                },
                &ticket
            ) != runtime::UserspaceIpAdapterOwner::QueueResult::Queued) {
            m_tunnel_flow_plane.CancelFlowReservation(reservation);
            reservation.result.status = wgnx::tunnel::ProtocolStatus::QueueFull;
            reservation.result.flow = {};
            return reservation.result;
        }
    }

    const auto queue_result = m_horizon_dispatcher.QueueUserspaceIpAdapter();
    if (queue_result == wgnx::platform::queue_work_result::capacity_exhausted ||
        queue_result == wgnx::platform::queue_work_result::unavailable) {
        std::scoped_lock lock(m_state_mutex);
        m_userspace_ip_adapter_owner.CancelLocked(ticket);
        m_tunnel_flow_plane.CancelFlowReservation(reservation);
        reservation.result.status = wgnx::tunnel::ProtocolStatus::QueueFull;
        reservation.result.flow = {};
        return reservation.result;
    }
    m_horizon_dispatcher.FlushSubmissionWork();

    bool close_stale_pcb = false;
    {
        std::scoped_lock lock(m_state_mutex);
        const auto adapter_result = m_userspace_ip_adapter_owner.TakeResultLocked(ticket);
        if (!adapter_result.has_value() || *adapter_result != ip::UserspaceIpResult::Success) {
            m_tunnel_flow_plane.CancelFlowReservation(reservation);
            reservation.result.status = adapter_result.has_value() && *adapter_result == ip::UserspaceIpResult::FlowQuotaExhausted
                                            ? wgnx::tunnel::ProtocolStatus::FlowQuotaExhausted
                                        : adapter_result.has_value() && *adapter_result == ip::UserspaceIpResult::QueueFull
                                            ? wgnx::tunnel::ProtocolStatus::QueueFull
                                            : wgnx::tunnel::ProtocolStatus::TransportUnavailable;
            reservation.result.flow = {};
            return reservation.result;
        }
        if (m_tunnel_flow_plane.CommitFlowReservation(reservation)) {
            return reservation.result;
        }
        m_tunnel_flow_plane.CancelFlowReservation(reservation);
        close_stale_pcb = true;
    }
    if (close_stale_pcb) {
        runtime::UserspaceIpAdapterOwner::OperationTicket close_ticket{};
        bool close_queued = false;
        {
            std::scoped_lock lock(m_state_mutex);
            close_queued = m_userspace_ip_adapter_owner.QueueCloseFlowLocked(reservation.adapter_token, &close_ticket) ==
                           runtime::UserspaceIpAdapterOwner::QueueResult::Queued;
        }
        if (close_queued) {
            static_cast<void>(m_horizon_dispatcher.QueueUserspaceIpAdapter());
            m_horizon_dispatcher.FlushSubmissionWork();
            std::scoped_lock lock(m_state_mutex);
            static_cast<void>(m_userspace_ip_adapter_owner.TakeResultLocked(close_ticket));
        }
    }
    reservation.result.status = wgnx::tunnel::ProtocolStatus::PeerUnavailable;
    reservation.result.flow = {};
    return reservation.result;
}

wgnx::tunnel::ProtocolStatus DaemonRuntime::SendTunnelUdpDatagram(
    runtime::TunnelClientId client, const wgnx::tunnel::PayloadRange& descriptor, std::span<const std::uint8_t> payload
) {
    EnsureInitialized();
    runtime::EffectBatch effects{};
    runtime::PreparedTunnelDatagram prepared{};
    wgnx::tunnel::ProtocolStatus status = wgnx::tunnel::ProtocolStatus::TransportUnavailable;
    runtime::UserspaceIpAdapterOwner::OperationTicket ticket{};
    bool queued = false;
    {
        std::scoped_lock lock(m_state_mutex);
        RefreshTunnelPolicyLocked();
        runtime::PeerPacketStateSnapshot peer{};
        const bool packet_state_available = m_runtime_coordinator.SnapshotPacketState(peer);
        prepared = m_tunnel_flow_plane.PrepareSend(
            client,
            descriptor,
            payload,
            {
                .protocol_available = packet_state_available && peer.protocol_instantiated,
                .staging_available = true,
            },
            GetRuntimeNowNs()
        );
        status = prepared.status;
        if (prepared.IsPrepared()) {
            queued = m_userspace_ip_adapter_owner.QueueSendDatagramLocked(prepared.adapter_token, payload, &ticket) ==
                     runtime::UserspaceIpAdapterOwner::QueueResult::Queued;
            if (!queued) {
                status = wgnx::tunnel::ProtocolStatus::QueueFull;
                m_tunnel_flow_plane.CompleteSend(prepared, status);
            }
        }
    }
    if (!queued) {
        return status;
    }
    static_cast<void>(m_horizon_dispatcher.QueueUserspaceIpAdapter());
    m_horizon_dispatcher.FlushSubmissionWork();
    {
        std::scoped_lock lock(m_state_mutex);
        const auto adapter_result = m_userspace_ip_adapter_owner.PeekResultLocked(ticket);
        if (!adapter_result) {
            status = wgnx::tunnel::ProtocolStatus::TransportUnavailable;
        } else if (*adapter_result == ip::UserspaceIpResult::Success) {
            const auto packets = m_userspace_ip_adapter_owner.OutboundPacketsLocked(ticket);
            std::array<runtime::SynchronousPacketView, runtime::MaximumInnerPacketBatchSize> packet_views{
                runtime::SynchronousPacketView{std::span<const std::uint8_t>{}},
                runtime::SynchronousPacketView{std::span<const std::uint8_t>{}},
                runtime::SynchronousPacketView{std::span<const std::uint8_t>{}},
            };
            if (packets.empty() || packets.size() > packet_views.size()) {
                status = wgnx::tunnel::ProtocolStatus::QueueFull;
            } else {
                for (std::size_t index = 0; index < packets.size(); ++index) {
                    packet_views[index] =
                        runtime::SynchronousPacketView{std::span<const std::uint8_t>(packets[index].bytes).first(packets[index].size)};
                }
                const auto submission = m_packet_data_plane.SubmitInternalIpPacketBatch(
                    std::span<const runtime::SynchronousPacketView>(packet_views).first(packets.size()),
                    runtime::CaptureTimerFacts(),
                    GetRuntimeNowNs(),
                    effects
                );
                switch (submission.status) {
                case runtime::PacketSubmissionStatus::Queued:
                    status = wgnx::tunnel::ProtocolStatus::Success;
                    break;
                case runtime::PacketSubmissionStatus::QueueFull:
                    status = wgnx::tunnel::ProtocolStatus::QueueFull;
                    break;
                case runtime::PacketSubmissionStatus::TunnelUnavailable:
                    status = wgnx::tunnel::ProtocolStatus::TransportUnavailable;
                    break;
                case runtime::PacketSubmissionStatus::MalformedPacket:
                case runtime::PacketSubmissionStatus::InternalError:
                    status = wgnx::tunnel::ProtocolStatus::TransportUnavailable;
                    break;
                }
            }
        } else if (*adapter_result == ip::UserspaceIpResult::QueueFull) {
            status = wgnx::tunnel::ProtocolStatus::QueueFull;
        } else {
            status = wgnx::tunnel::ProtocolStatus::TransportUnavailable;
        }
        static_cast<void>(m_userspace_ip_adapter_owner.TakeResultLocked(ticket));
        m_tunnel_flow_plane.CompleteSend(prepared, status);
    }
    ExecuteRuntimeEffects(effects);
    return status;
}

runtime::TunnelCompletionDrainOutcome DaemonRuntime::ReceiveTunnelCompletions(
    runtime::TunnelClientId client,
    std::span<wgnx::tunnel::CompletionRecord> records,
    std::span<std::uint8_t> payload,
    runtime::TunnelFlowPlane::CompletionNotifier clear_notifier,
    void* clear_context
) {
    EnsureInitialized();
    std::scoped_lock lock(m_state_mutex);
    const auto outcome = m_tunnel_flow_plane.ReceiveCompletions(client, records, payload);
    if (!m_tunnel_flow_plane.HasCompletions(client) && clear_notifier != nullptr) {
        clear_notifier(clear_context);
    }
    return outcome;
}

wgnx::tunnel::FlowStateResult DaemonRuntime::GetTunnelFlowState(runtime::TunnelClientId client, wgnx::tunnel::FlowHandle flow) {
    EnsureInitialized();
    std::scoped_lock lock(m_state_mutex);
    RefreshTunnelPolicyLocked();
    return m_tunnel_flow_plane.GetFlowState(client, flow);
}

wgnx::tunnel::ProtocolStatus DaemonRuntime::CloseTunnelFlow(runtime::TunnelClientId client, wgnx::tunnel::FlowHandle flow) {
    EnsureInitialized();
    runtime::UserspaceIpAdapterOwner::OperationTicket ticket{};
    std::uint64_t adapter_token = 0;
    {
        std::scoped_lock lock(m_state_mutex);
        if (!m_tunnel_flow_plane.GetFlowAdapterToken(client, flow, &adapter_token)) {
            return m_tunnel_flow_plane.CloseFlow(client, flow, GetRuntimeNowNs());
        }
        if (m_userspace_ip_adapter_owner.QueueCloseFlowLocked(adapter_token, &ticket) !=
            runtime::UserspaceIpAdapterOwner::QueueResult::Queued) {
            return wgnx::tunnel::ProtocolStatus::QueueFull;
        }
    }
    const auto queue_result = m_horizon_dispatcher.QueueUserspaceIpAdapter();
    if (queue_result == wgnx::platform::queue_work_result::capacity_exhausted ||
        queue_result == wgnx::platform::queue_work_result::unavailable) {
        std::scoped_lock lock(m_state_mutex);
        m_userspace_ip_adapter_owner.CancelLocked(ticket);
        return wgnx::tunnel::ProtocolStatus::QueueFull;
    }
    {
        std::scoped_lock lock(m_state_mutex);
        static_cast<void>(m_tunnel_flow_plane.CloseFlow(client, flow, GetRuntimeNowNs()));
    }
    m_horizon_dispatcher.FlushSubmissionWork();
    {
        std::scoped_lock lock(m_state_mutex);
        const auto result = m_userspace_ip_adapter_owner.TakeResultLocked(ticket);
        if (!result.has_value() || *result != ip::UserspaceIpResult::Success) {
            return wgnx::tunnel::ProtocolStatus::TransportUnavailable;
        }
    }
    // Flow closure is a measurement boundary, so persist its aggregate summary
    // after releasing the daemon mutex without flushing packet-path traffic.
    logger::Flush();
    return wgnx::tunnel::ProtocolStatus::Success;
}

void DaemonRuntime::Initialize() {
    EnsureInitialized();
    InitializeHorizonDispatcher();
    logger::Flush();
}

void DaemonRuntime::Shutdown() {
    if (!m_state.initialized) {
        return;
    }

    logger::Log("Runtime graceful shutdown deactivating active peer");
    const ams::Result deactivate_result = SetActivePeer(-1);
    if (R_FAILED(deactivate_result)) {
        logger::Log("Runtime graceful shutdown deactivation failed rc=0x%08X", deactivate_result.GetValue());
    }
    m_timer_scheduler.CancelAllProtocolTimers();
    m_timer_scheduler.CancelDebugProbeTimeout();
    m_timer_scheduler.CancelUserspaceIpTimeout();
    {
        std::scoped_lock lock(m_state_mutex);
        m_userspace_ip_adapter_owner.QueueResetLocked();
    }
    static_cast<void>(m_horizon_dispatcher.QueueUserspaceIpAdapter());
    logger::Flush();
}

DaemonRuntime g_daemon_runtime{};

} // namespace

namespace runtime {

void Initialize() {
    g_daemon_runtime.Initialize();
}

void Shutdown() {
    g_daemon_runtime.Shutdown();
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

wgnx::PacketSubmissionResult SubmitInnerIpv4Packet(std::span<const std::uint8_t> packet, std::uint64_t process_id) {
    return g_daemon_runtime.SubmitInnerIpv4Packet(packet, runtime::ProcessId{process_id});
}

wgnx::PacketReceiveResult ReceiveInnerIpv4Packet(std::span<std::uint8_t> packet, std::uint64_t process_id) {
    return g_daemon_runtime.ReceiveInnerIpv4Packet(packet, runtime::ProcessId{process_id});
}

TunnelClientId CreateTunnelClient(TunnelFlowPlane::CompletionNotifier notifier, void* notifier_context) {
    return g_daemon_runtime.CreateTunnelClient(notifier, notifier_context);
}

void DestroyTunnelClient(TunnelClientId client) {
    g_daemon_runtime.DestroyTunnelClient(client);
}

std::uint32_t SignalTunnelClientShutdown() {
    return g_daemon_runtime.SignalTunnelClientShutdown();
}

wgnx::tunnel::Capabilities GetTunnelCapabilities() {
    return g_daemon_runtime.GetTunnelCapabilities();
}

wgnx::tunnel::RoutingPolicySnapshot CopyTunnelRoutingPolicy(std::span<wgnx::tunnel::RouteRecord> out) {
    return g_daemon_runtime.CopyTunnelRoutingPolicy(out);
}

wgnx::tunnel::OpenConnectedFlowResult OpenTunnelConnectedUdpFlow(
    TunnelClientId client, const wgnx::tunnel::OpenConnectedFlowRequest& request
) {
    return g_daemon_runtime.OpenTunnelConnectedUdpFlow(client, request);
}

wgnx::tunnel::ProtocolStatus SendTunnelUdpDatagram(
    TunnelClientId client, const wgnx::tunnel::PayloadRange& descriptor, std::span<const std::uint8_t> payload
) {
    return g_daemon_runtime.SendTunnelUdpDatagram(client, descriptor, payload);
}

TunnelCompletionDrainOutcome ReceiveTunnelCompletions(
    TunnelClientId client,
    std::span<wgnx::tunnel::CompletionRecord> records,
    std::span<std::uint8_t> payload,
    TunnelFlowPlane::CompletionNotifier clear_notifier,
    void* clear_context
) {
    return g_daemon_runtime.ReceiveTunnelCompletions(client, records, payload, clear_notifier, clear_context);
}

wgnx::tunnel::FlowStateResult GetTunnelFlowState(TunnelClientId client, wgnx::tunnel::FlowHandle flow) {
    return g_daemon_runtime.GetTunnelFlowState(client, flow);
}

wgnx::tunnel::ProtocolStatus CloseTunnelFlow(TunnelClientId client, wgnx::tunnel::FlowHandle flow) {
    return g_daemon_runtime.CloseTunnelFlow(client, flow);
}

} // namespace runtime

} // namespace wgnx::sysmodule
