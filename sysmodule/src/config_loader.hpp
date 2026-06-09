#pragma once

#include <stratosphere.hpp>
#include <string_view>

#include "wgnx/config.hpp"

namespace wgnx::sysmodule {

bool LoadPeerConfig(wgnx::PeerConfigSet *out);
bool LoadAutoStartPeerName(char *out_name, std::size_t out_name_size);
ams::Result StoreAutoStartPeerName(std::string_view name);

} // namespace wgnx::sysmodule
