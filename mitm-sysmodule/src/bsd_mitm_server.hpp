#pragma once

namespace wgnx::mitm {

// Registers the narrow Toolbox-only bsd:s MITM and starts its server loop.
bool StartBsdMitmServer();
void StopBsdMitmServer();

[[nodiscard]] bool IsBsdMitmServerRunning();

} // namespace wgnx::mitm
