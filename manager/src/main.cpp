/*
  run this example from nxlink

  nxlink <-a switch_ip> nxlink_stdio.nro -s <arguments>

  -s or --server tells nxlink to open a socket nxlink can connect to.

*/

#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/errno.h>
#include <unistd.h>
#include <array>

#include <switch.h>

#include "wgnx/client.hpp"

#define VERSION_WITH_BUILD VERSION "-" BUILD_ID

int main(int argc, char **argv)
{
    consoleInit(NULL);

    // Configure our supported input layout: a single player with standard controller styles
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);

    // Initialize the default gamepad (which reads handheld mode inputs as well as the first connected controller)
    PadState pad;
    padInitializeDefault(&pad);
    
    Result rc;

    printf("Initializing socket\n");
    if (R_FAILED(rc = socketInitializeDefault()))
        diagAbortWithResult(rc);

    printf("Initializing nifm\n");
    if (R_FAILED(rc = nifmInitialize(NifmServiceType_User)))
        diagAbortWithResult(rc);

    printf("Exit by pressing + or -\n");
    printf("Press ZL to send a debug ping to 10.13.13.1 through the tunnel\n");
    printf("Press ZR to send a debug ping to 1.1.1.1 through the tunnel\n");

    // Display arguments sent from nxlink
    printf("%d arguments\n", argc);
    printf("Manager Version: %s\n", VERSION_WITH_BUILD);

    for (int i=0; i<argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }

    if (__nxlink_host.s_addr != 0) {
    // the host ip where nxlink was launched
        printf("nxlink host is %s\n", inet_ntoa(__nxlink_host));

        fprintf(stdout, "stdout output will continue on client\n");

        nxlinkConnectToHost(false, true);

        fprintf(stderr, "stderr output now shows on host\n");
        printf("see?\n");
    }

    u32 ip;
    nifmGetCurrentIpAddress(&ip);
    printf("Current IP: %u.%u.%u.%u\n", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);

    if (wgnx::client::IsServiceRunning()) {
        u32 api_version = 0;
        if (R_SUCCEEDED(wgnx::client::GetApiVersion(&api_version))) {
            printf("WireGuard IPC API: v%u\n", api_version);
        }

        wgnx::BuildInfo sysmodule_build = {};
        if (R_SUCCEEDED(wgnx::client::GetBuildInfo(&sysmodule_build))) {
            printf(
                "Sysmodule Version: %s-%s\n",
                sysmodule_build.version[0] != '\0' ? sysmodule_build.version : "unknown",
                sysmodule_build.build_id[0] != '\0' ? sysmodule_build.build_id : "unknown");
        }

        wgnx::DaemonStatus status{};
        if (R_SUCCEEDED(wgnx::client::GetDaemonStatus(&status))) {
            printf("WireGuard peers: %u | active=%d | autostart=%d | flags=0x%08X\n",
                status.peer_count, status.active_peer_index, status.auto_start_peer_index, status.flags);
        }

        std::array<wgnx::PeerInfo, wgnx::MaxPeers> peers{};
        u32 peer_count = 0;
        if (R_SUCCEEDED(wgnx::client::ListPeers(peers.data(), peers.size(), &peer_count))) {
            for (u32 i = 0; i < peer_count && i < peers.size(); ++i) {
                const auto& peer = peers[i];
                const char *endpoint = ((peer.flags & wgnx::PeerFlag_Active) != 0 &&
                                        (peer.flags & wgnx::PeerFlag_HasResolvedEndpoint) != 0)
                    ? peer.resolved_endpoint
                    : peer.endpoint;
                printf("[%u] %s | %s | endpoint=%s | local_pub=%s | state=%s stage=%s flags=0x%02X | hs=%d rx_age=%d tx_age=%d",
                    i, peer.name, peer.address, endpoint,
                    peer.derived_public_key[0] != '\0' ? peer.derived_public_key : "<unavailable>",
                    wgnx::GetPeerRuntimeStateName(static_cast<wgnx::PeerRuntimeState>(peer.runtime_state)),
                    wgnx::GetPeerErrorStageName(static_cast<wgnx::PeerErrorStage>(peer.error_stage)),
                    peer.flags,
                    peer.last_handshake_seconds, peer.last_rx_seconds, peer.last_tx_seconds);
                printf(
                    " | probe=%s/%s/%ds",
                    wgnx::GetDebugTriggerActionName(static_cast<wgnx::DebugTriggerAction>(peer.debug_probe_action)),
                    wgnx::GetDebugProbeStatusName(static_cast<wgnx::DebugProbeStatus>(peer.debug_probe_status)),
                    peer.last_debug_probe_seconds);
                printf(
                    " | ka=%us err=%s (0x%08X)\n",
                    peer.persistent_keepalive_interval,
                    wgnx::GetPeerErrorCodeName(static_cast<wgnx::PeerErrorCode>(peer.last_error_code)),
                    peer.last_error_code);
            }
        }
    } else {
        printf("WireGuard IPC service '%s' is not running.\n", wgnx::ServiceName);
    }

    u32 hosversion = hosversionGet();
    bool is_atmos = hosversionIsAtmosphere();
    printf("HOS Version: %u.%u.%u", (hosversion >> 16) & 0xFF, (hosversion >> 8) & 0xFF, hosversion & 0xFF);
    if (is_atmos) {
        printf("|AMS");
    }
    printf("\n");

    // Main loop
    while(appletMainLoop())
    {
        padUpdate(&pad);

        // padGetButtonsDown returns the set of buttons that have been newly pressed in this frame compared to the previous one
        u32 kDown = padGetButtonsDown(&pad);
        if (kDown & HidNpadButton_Plus) break;
        if (kDown & HidNpadButton_Minus) break;

        if (kDown & (HidNpadButton_ZL | HidNpadButton_ZR)) {
            const wgnx::DebugTriggerAction action = (kDown & HidNpadButton_ZL) != 0
                ? wgnx::DebugTriggerAction::PingTunnelPeer
                : wgnx::DebugTriggerAction::PingPublicDns;

            if (!wgnx::client::IsServiceRunning()) {
                printf("TriggerDebugPayload: IPC service is not running.\n");
            } else {
                const Result trigger_rc = wgnx::client::TriggerDebugPayload(action);
                printf(
                    "TriggerDebugPayload(%s): %s (0x%08X)\n",
                    wgnx::GetDebugTriggerActionName(action),
                    R_SUCCEEDED(trigger_rc) ? "queued" : "failed",
                    trigger_rc);
            }
        }

        consoleUpdate(NULL);
    }

    socketExit();
    consoleExit(NULL);
    return 0;
}
