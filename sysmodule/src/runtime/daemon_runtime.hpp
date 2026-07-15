#pragma once

#include <stratosphere.hpp>

#include "wgnx/protocol.hpp"

#include <cstdint>
#include <span>

namespace wgnx::sysmodule::runtime {

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

} // namespace wgnx::sysmodule::runtime
