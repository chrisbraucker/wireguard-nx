#pragma once

#include "wgnx/platform/udp.hpp"

#include <sys/socket.h>

#include <stratosphere.hpp>

namespace wgnx::sysmodule::platform::horizon::internal {

ams::Result EnsureUdpRuntimeInitialized();
int ToNativeAddressFamily(wgnx::platform::address_family family);
wgnx::platform::address_family FromNativeAddressFamily(int family);
bool EncodeEndpointFromSockaddr(wgnx::platform::endpoint* out, const sockaddr* address);
bool DecodeEndpointToSockaddr(sockaddr_storage* out_address, socklen_t* out_length, const wgnx::platform::endpoint& endpoint);

} // namespace wgnx::sysmodule::platform::horizon::internal
