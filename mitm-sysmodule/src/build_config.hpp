#pragma once

namespace wgnx::mitm::build_config {

#ifndef WGNX_MITM_TOOLBOX_FORWARDER_PROGRAM_ID
#if defined(__SWITCH__)
#error "WGNX_MITM_TOOLBOX_FORWARDER_PROGRAM_ID must be set by the MITM build"
#else
#define WGNX_MITM_TOOLBOX_FORWARDER_PROGRAM_ID 0
#endif
#endif

inline constexpr unsigned long long ToolboxForwarderProgramId = WGNX_MITM_TOOLBOX_FORWARDER_PROGRAM_ID;

} // namespace wgnx::mitm::build_config
