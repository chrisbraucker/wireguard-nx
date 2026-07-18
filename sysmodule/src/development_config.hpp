#pragma once

namespace wgnx::sysmodule::development_config {

enum class NifmPathObserverMode {
    Disabled,
    InitializeOnly,
    InternetStatusOnly,
    IpConfigOnly,
    Full,
};

// Retain a nifm:s general-service session without issuing observer queries.
constexpr inline NifmPathObserverMode NifmPathObserver = NifmPathObserverMode::InitializeOnly;

constexpr inline bool NifmPathObserverEnabled =
    NifmPathObserver != NifmPathObserverMode::Disabled;
constexpr inline bool QueryNifmInternetStatus =
    NifmPathObserver == NifmPathObserverMode::InternetStatusOnly ||
    NifmPathObserver == NifmPathObserverMode::Full;
constexpr inline bool QueryNifmIpConfig =
    NifmPathObserver == NifmPathObserverMode::IpConfigOnly ||
    NifmPathObserver == NifmPathObserverMode::Full;

// Emit every receive-loop and NIFM-observation iteration. Keep this disabled
// for normal operation: lifecycle and path-change records remain unconditional,
// while steady-state heartbeats otherwise overwhelm the bounded logger queue.
constexpr inline bool VerboseHeartbeatLogging = false;

// Diagnostic mode: isolate stale BSD socket state after an uplink loss while
// preserving the active peer, WireGuard protocol state, and NIFM session.
constexpr inline bool SuspendUdpTransportOnFirstSendFailure = true;

constexpr inline const char *GetNifmPathObserverModeName() {
    switch (NifmPathObserver) {
        case NifmPathObserverMode::Disabled:
            return "Disabled";
        case NifmPathObserverMode::InitializeOnly:
            return "InitializeOnly";
        case NifmPathObserverMode::InternetStatusOnly:
            return "InternetStatusOnly";
        case NifmPathObserverMode::IpConfigOnly:
            return "IpConfigOnly";
        case NifmPathObserverMode::Full:
            return "Full";
    }

    return "Unknown";
}

} // namespace wgnx::sysmodule::development_config
