#pragma once

#include <tesla.hpp>

#define WGNX_PROGRAM_ID 0x000000000000EAD0

struct WireGuardPeer {
    tsl::elm::ListItem *listItem;
    std::string name;
    std::string address;
    std::string endpoint;
    std::int32_t lastHandshake;
    std::int32_t rxBytes;
    std::int32_t txBytes;
    bool isActive;
    bool isAutoStartEnabled;
};

class GuiMain : public tsl::Gui {
private:
    std::vector<WireGuardPeer> m_peers;
    tsl::elm::CustomDrawer *m_peerInfoDrawer;
    WireGuardPeer* m_activePeer;

public:
    GuiMain();
    ~GuiMain();

    virtual tsl::elm::Element* createUI();
    virtual void update() override;
    virtual bool handleInput(u64 keysDown, u64 keysHeld, const HidTouchState &touchPos, HidAnalogStickState leftJoyStick, HidAnalogStickState rightJoyStick) override;

private:
    bool smIsRunning();
    bool getPeers(std::vector<WireGuardPeer>& peers);
    bool isActive(WireGuardPeer& peer);
    bool updatePeer(WireGuardPeer& peer);
};

std::string formatBytes(std::int32_t bytes);
std::string moment(std::int32_t seconds);