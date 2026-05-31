#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <tesla.hpp>

struct WireGuardPeer {
    std::int32_t index;
    tsl::elm::ListItem *listItem;
    std::string name;
    std::string address;
    std::string endpoint;
    std::int32_t lastHandshake;
    std::uint64_t rxBytes;
    std::uint64_t txBytes;
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
    bool refreshPeers();
};

std::string formatBytes(std::uint64_t bytes);
std::string moment(std::int32_t seconds);
