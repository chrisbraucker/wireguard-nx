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

#include <switch.h>

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

    // Display arguments sent from nxlink
    printf("%d arguments\n", argc);

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

        // Your code goes here

        consoleUpdate(NULL);
    }

    socketExit();
    consoleExit(NULL);
    return 0;
}