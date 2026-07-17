#pragma once

#include "runtime/runtime_events.hpp"
#include "wireguard/timers.hpp"

#include <stratosphere.hpp>

namespace wgnx::sysmodule::runtime {

class DebugProbeRunner;
struct DebugProbeRequest;
class EncryptedReceivePump;
class EndpointResolver;
class HorizonDispatcher;
class NetworkPathObserver;
class PacketDataPlane;
class RuntimeCoordinator;
class TimerScheduler;

class RuntimeEffectExecutor {
public:
    RuntimeEffectExecutor(
        ams::os::Mutex &state_mutex,
        RuntimeCoordinator &coordinator,
        EndpointResolver &endpoint_resolver,
        HorizonDispatcher &dispatcher,
        TimerScheduler &timer_scheduler,
        PacketDataPlane &packet_data_plane,
        DebugProbeRunner &debug_probe_runner,
        NetworkPathObserver &network_path_observer,
        EncryptedReceivePump &receive_pump)
        : m_state_mutex(state_mutex),
          m_coordinator(coordinator),
          m_endpoint_resolver(endpoint_resolver),
          m_dispatcher(dispatcher),
          m_timer_scheduler(timer_scheduler),
          m_packet_data_plane(packet_data_plane),
          m_debug_probe_runner(debug_probe_runner),
          m_network_path_observer(network_path_observer),
          m_receive_pump(receive_pump) {}

    void Execute(const EffectBatch &effects);
    void RunEndpointResolver();
    void RunDebugPayloadSubmission();
    void RunInnerPacketSubmission();
    void RunProtocolTimer(
        wgnx::wireguard::TimerHook hook,
        const wgnx::wireguard::TimerToken &token);
    void RunDebugProbeTimeout();
    void RunNetworkPathObservation();
    void CancelDebugProbeTimeout();

private:
    bool TakeDebugPayloadSubmission(DebugProbeRequest &out_request);
    NOINLINE void ExecuteOpenUdpBind(
        const OpenUdpBindEffect &effect,
        EffectBatch &generated);
    NOINLINE void ExecutePendingDatagramSend(
        const SendPendingDatagramEffect &effect,
        EffectBatch &generated);
    NOINLINE void ExecutePublishDecryptedPacket(
        const PublishDecryptedPacketEffect &effect);
    void PublishDecryptedPacketLocked(
        const PeerIdentity &peer,
        std::span<const std::uint8_t> inner_packet);
    void CommitDebugPayloadSubmission(const DebugProbeRequest &request);

    ams::os::Mutex &m_state_mutex;
    RuntimeCoordinator &m_coordinator;
    EndpointResolver &m_endpoint_resolver;
    HorizonDispatcher &m_dispatcher;
    TimerScheduler &m_timer_scheduler;
    PacketDataPlane &m_packet_data_plane;
    DebugProbeRunner &m_debug_probe_runner;
    NetworkPathObserver &m_network_path_observer;
    EncryptedReceivePump &m_receive_pump;
};

} // namespace wgnx::sysmodule::runtime
