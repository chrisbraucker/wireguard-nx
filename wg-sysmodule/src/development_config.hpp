#pragma once

namespace wgnx::sysmodule::development_config {

// Emit every receive-loop iteration. Path transitions are always recorded;
// this remains disabled in normal operation to protect the bounded logger.
constexpr inline bool VerboseHeartbeatLogging = false;

} // namespace wgnx::sysmodule::development_config
