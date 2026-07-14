#pragma once

#include <stratosphere.hpp>

#include "wgnx/protocol.hpp"

#define WGNX_I_CONTROL_SERVICE_INTERFACE_DEBUG_INFO(C, H) \
    AMS_SF_METHOD_INFO(C, H, static_cast<u32>(wgnx::CommandId::TriggerDebugPayload),   ams::Result, TriggerDebugPayload,   (const wgnx::DebugTriggerRequest &request),                                                                                              (request),                    ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, static_cast<u32>(wgnx::CommandId::SubmitInnerIpv4Packet), ams::Result, SubmitInnerIpv4Packet, (ams::sf::Out<wgnx::PacketSubmissionResult> out, const ams::sf::InBuffer &packet, const ams::sf::ClientProcessId &client_pid), (out, packet, client_pid),    ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, static_cast<u32>(wgnx::CommandId::ReceiveInnerIpv4Packet),ams::Result, ReceiveInnerIpv4Packet,(ams::sf::Out<wgnx::PacketReceiveResult> out, const ams::sf::OutBuffer &packet, const ams::sf::ClientProcessId &client_pid),    (out, packet, client_pid),    ams::hos::Version_Min, ams::hos::Version_Max)

#define WGNX_I_CONTROL_SERVICE_INTERFACE_INFO(C, H) \
    AMS_SF_METHOD_INFO(C, H, static_cast<u32>(wgnx::CommandId::GetApiVersion),    ams::Result, GetApiVersion,    (ams::sf::Out<u32> out),                                                     (out), ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, static_cast<u32>(wgnx::CommandId::GetDaemonStatus),  ams::Result, GetDaemonStatus,  (ams::sf::Out<wgnx::DaemonStatus> out),                                      (out), ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, static_cast<u32>(wgnx::CommandId::ListPeers),        ams::Result, ListPeers,        (ams::sf::Out<u32> out_count, const ams::sf::OutArray<wgnx::PeerInfo> &out), (out_count, out), ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, static_cast<u32>(wgnx::CommandId::GetBuildInfo),     ams::Result, GetBuildInfo,     (ams::sf::Out<wgnx::BuildInfo> out),                                         (out), ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, static_cast<u32>(wgnx::CommandId::SetActivePeer),    ams::Result, SetActivePeer,    (const wgnx::PeerSelectionRequest &request),                                 (request), ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, static_cast<u32>(wgnx::CommandId::SetAutoStartPeer), ams::Result, SetAutoStartPeer, (const wgnx::PeerSelectionRequest &request),                                 (request), ams::hos::Version_Min, ams::hos::Version_Max) \
    WGNX_I_CONTROL_SERVICE_INTERFACE_DEBUG_INFO(C, H)

// Interface ID for Stratosphere's service framework.
// 0x57474E58 is ASCII "WGNX", chosen as a stable, human-readable identifier
// for this custom interface. It is distinct from the SM service name "wgnx:ctl".
AMS_SF_DEFINE_INTERFACE(wgnx::sysmodule, IControlService, WGNX_I_CONTROL_SERVICE_INTERFACE_INFO, 0x57474E58);

namespace wgnx::sysmodule {

class ControlService {
public:
    ams::Result GetApiVersion(ams::sf::Out<u32> out);
    ams::Result GetDaemonStatus(ams::sf::Out<wgnx::DaemonStatus> out);
    ams::Result GetBuildInfo(ams::sf::Out<wgnx::BuildInfo> out);
    ams::Result ListPeers(ams::sf::Out<u32> out_count, const ams::sf::OutArray<wgnx::PeerInfo> &out);
    ams::Result SetActivePeer(const wgnx::PeerSelectionRequest &request);
    ams::Result SetAutoStartPeer(const wgnx::PeerSelectionRequest &request);
    ams::Result TriggerDebugPayload(const wgnx::DebugTriggerRequest &request);
    ams::Result SubmitInnerIpv4Packet(
        ams::sf::Out<wgnx::PacketSubmissionResult> out,
        const ams::sf::InBuffer &packet,
        const ams::sf::ClientProcessId &client_pid);
    ams::Result ReceiveInnerIpv4Packet(
        ams::sf::Out<wgnx::PacketReceiveResult> out,
        const ams::sf::OutBuffer &packet,
        const ams::sf::ClientProcessId &client_pid);
};
static_assert(IsIControlService<ControlService>);

void RunIpcServer();

} // namespace wgnx::sysmodule
