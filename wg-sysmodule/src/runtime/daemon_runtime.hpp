#pragma once

#include <stratosphere.hpp>

#include "runtime/tunnel_flow_plane.hpp"
#include "wgnx/protocol.hpp"
#include "wgnx/tunnel_protocol.hpp"

#include <cstdint>
#include <span>

namespace wgnx::sysmodule::runtime {

void Initialize();
void Shutdown();
wgnx::DaemonStatus GetDaemonStatus();
std::uint32_t CopyPeers(std::span<wgnx::PeerInfo> out);
ams::Result SetActivePeer(std::int32_t peer_index);
ams::Result SetAutoStartPeer(std::int32_t peer_index);
ams::Result TriggerDebugPayload(wgnx::DebugTriggerAction action);
ams::Result BumpUdpBinding();
wgnx::PacketSubmissionResult SubmitInnerIpv4Packet(std::span<const std::uint8_t> packet, std::uint64_t process_id);
wgnx::PacketReceiveResult ReceiveInnerIpv4Packet(std::span<std::uint8_t> packet, std::uint64_t process_id);

TunnelClientId CreateTunnelClient(TunnelFlowPlane::CompletionNotifier notifier, void* notifier_context);
void DestroyTunnelClient(TunnelClientId client);
std::uint32_t SignalTunnelClientShutdown();
wgnx::tunnel::Capabilities GetTunnelCapabilities();
wgnx::tunnel::RoutingPolicySnapshot CopyTunnelRoutingPolicy(std::span<wgnx::tunnel::RouteRecord> out);
wgnx::tunnel::OpenConnectedUdpFlowResult OpenTunnelConnectedUdpFlow(TunnelClientId client,
                                                                    const wgnx::tunnel::OpenConnectedUdpFlowRequest& request);
wgnx::tunnel::ProtocolStatus SendTunnelUdpDatagram(TunnelClientId client, const wgnx::tunnel::DatagramDescriptor& descriptor,
                                                   std::span<const std::uint8_t> payload);
TunnelCompletionDrainOutcome ReceiveTunnelCompletions(TunnelClientId client, std::span<wgnx::tunnel::CompletionRecord> records,
                                                      std::span<std::uint8_t> payload, TunnelFlowPlane::CompletionNotifier clear_notifier,
                                                      void* clear_context);
wgnx::tunnel::FlowStateResult GetTunnelFlowState(TunnelClientId client, wgnx::tunnel::FlowHandle flow);
wgnx::tunnel::ProtocolStatus CloseTunnelFlow(TunnelClientId client, wgnx::tunnel::FlowHandle flow);

} // namespace wgnx::sysmodule::runtime
