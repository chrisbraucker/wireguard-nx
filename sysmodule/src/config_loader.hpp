#pragma once

#include "wgnx/config.hpp"

namespace wgnx::sysmodule {

bool LoadPeerConfig(wgnx::PeerConfigSet *out);
bool LoadAutoStartPeerName(char *out_name, std::size_t out_name_size);

} // namespace wgnx::sysmodule
