#pragma once

#include "runtime/runtime_events.hpp"
#include "wireguard/timers.hpp"

#include <stratosphere.hpp>

#include <optional>

namespace wgnx::sysmodule::platform::horizon {
class NetworkPathService;
}

namespace wgnx::sysmodule::runtime {

class DebugProbeRunner;
struct DebugProbeRequest;
class EncryptedReceivePump;
class EndpointResolver;
class HorizonDispatcher;
class PacketDataPlane;
class TunnelFlowPlane;
class RuntimeCoordinator;
class TimerScheduler;

class RuntimeEffectExecutor {
  public:
    RuntimeEffectExecutor(
        ams::os::Mutex& state_mutex,
        RuntimeCoordinator& coordinator,
        EndpointResolver& endpoint_resolver,
        HorizonDispatcher& dispatcher,
        TimerScheduler& timer_scheduler,
        PacketDataPlane& packet_data_plane,
        TunnelFlowPlane& tunnel_flow_plane,
        DebugProbeRunner& debug_probe_runner,
        wgnx::sysmodule::platform::horizon::NetworkPathService& network_path_service,
        EncryptedReceivePump& receive_pump
    )
        : m_state_mutex(state_mutex), m_coordinator(coordinator), m_endpoint_resolver(endpoint_resolver), m_dispatcher(dispatcher),
          m_timer_scheduler(timer_scheduler), m_packet_data_plane(packet_data_plane), m_tunnel_flow_plane(tunnel_flow_plane),
          m_debug_probe_runner(debug_probe_runner), m_network_path_service(network_path_service), m_receive_pump(receive_pump) {}

    void Execute(const EffectBatch& effects);
    void RunEndpointResolver();
    void RunPendingDatagramTransmit();
    void RunDebugPayloadSubmission();
    void RunInnerPacketSubmission();
    void RunProtocolTimer(wgnx::wireguard::TimerHook hook, const wgnx::wireguard::TimerToken& token);
    void RunDebugProbeTimeout();
    void HandleNetworkPathObservation(const wgnx::platform::network_path_observation& observation);

  private:
    bool TakeDebugPayloadSubmission(DebugProbeRequest& out_request);
    NOINLINE void ExecuteOpenUdpBind(const OpenUdpBindEffect& effect, EffectBatch& generated);
    NOINLINE void ExecutePendingDatagramSend(const SendPendingDatagramEffect& effect, EffectBatch& generated);
    NOINLINE void ExecuteCookieReplySend(const SendCookieReplyEffect& effect);
    void QueuePendingDatagramTransmit(const SendPendingDatagramEffect& effect);
    NOINLINE void ExecutePublishDecryptedPacket(const PublishDecryptedPacketEffect& effect);
    [[nodiscard]] bool PublishDecryptedPacketLocked(const PeerIdentity& peer, std::span<const std::uint8_t> inner_packet);
    void CommitDebugPayloadSubmission(const DebugProbeRequest& request);
    static void NetworkPathObservationCallback(void* context, const wgnx::platform::network_path_observation& observation);

    ams::os::Mutex& m_state_mutex;
    RuntimeCoordinator& m_coordinator;
    EndpointResolver& m_endpoint_resolver;
    HorizonDispatcher& m_dispatcher;
    TimerScheduler& m_timer_scheduler;
    PacketDataPlane& m_packet_data_plane;
    TunnelFlowPlane& m_tunnel_flow_plane;
    DebugProbeRunner& m_debug_probe_runner;
    wgnx::sysmodule::platform::horizon::NetworkPathService& m_network_path_service;
    EncryptedReceivePump& m_receive_pump;
    // A peer owns at most one pending datagram. Its concrete send completion
    // remains in the dedicated transmit worker rather than any producer stack.
    std::optional<SendPendingDatagramEffect> m_pending_datagram_transmit{};
    EffectBatch m_pending_datagram_transmit_effects{};
};

} // namespace wgnx::sysmodule::runtime
