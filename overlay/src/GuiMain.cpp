#include "GuiMain.hpp"

#define VERSION_WITH_BUILD VERSION "-" BUILD_ID

constexpr const char* const descriptions[2][2] = {
    [0] = {
        [0] = "\uE098\uE031Off",
        [1] = "\uE0F4\uE031Off",
    },
    [1] = {
        [0] = "\uE098\uE031On",
        [1] = "\uE0F4\uE031On",
    },
};

GuiMain::GuiMain() {
    m_peers.reserve(5);
    if (!this->smIsRunning())
        return;
    if (!this->getPeers(this->m_peers))
        return;

    std::sort(m_peers.begin(), m_peers.end(), [](const WireGuardPeer& a, const WireGuardPeer& b) {
        return a.name < b.name;
    });

    for (auto& peer : this->m_peers) {
        peer.listItem = new tsl::elm::ListItem(peer.name);
        peer.listItem->setClickListener([this, &peer](u64 keys) {
            if (keys & KEY_Y) {
                // Toggle auto-start
                if (!peer.isAutoStartEnabled && std::any_of(m_peers.begin(), m_peers.end(), [](const WireGuardPeer& p) { return p.isAutoStartEnabled; })) {
                    // Only allow one auto-start peer at a time
                    return true;
                }
                peer.isAutoStartEnabled = !peer.isAutoStartEnabled;
                peer.listItem->setValue(descriptions[peer.isActive][peer.isAutoStartEnabled], !peer.isActive);
                this->updatePeer(peer);
                return true;
            } else if (keys & KEY_A) {
                // Toggle active state
                if (!peer.isActive && std::any_of(m_peers.begin(), m_peers.end(), [](const WireGuardPeer& p) { return p.isActive; })) {
                    // Only allow one active peer at a time
                    return true;
                }
                peer.isActive = !peer.isActive;
                peer.listItem->setValue(descriptions[peer.isActive][peer.isAutoStartEnabled], !peer.isActive);
                this->updatePeer(peer);
                m_peerInfoDrawer->invalidate();
                return true;
            }
            return false;
        });
    }
}

GuiMain::~GuiMain() {
}

tsl::elm::Element* GuiMain::createUI() {
    tsl::elm::OverlayFrame *rootFrame = new tsl::elm::OverlayFrame(APP_TITLE, VERSION_WITH_BUILD);

    if (!this->smIsRunning()) {
        const char *desc = "WireGuard-NX SysModule\n          is not running!";

        auto *warning = new tsl::elm::CustomDrawer([desc](tsl::gfx::Renderer *renderer, s32 x, s32 y, s32 w, s32 h) {
            renderer->drawString("\uE150", false, 180, 250, 90, renderer->a(0xFFFF));
            renderer->drawString(desc, false, 60, 340, 25, tsl::warningTextColor);
        });

        rootFrame->setContent(warning);
    } else if (this->m_peers.empty()) {
        const char *desc = "No servers configured!";

        auto *warning = new tsl::elm::CustomDrawer([desc](tsl::gfx::Renderer *renderer, s32 x, s32 y, s32 w, s32 h) {
            renderer->drawString("\uE150", false, 180, 250, 90, renderer->a(0xFFFF));
            renderer->drawString(desc, false, 90, 340, 25, tsl::warningTextColor);
        });

        rootFrame->setContent(warning);
    } else {
        tsl::elm::List* peerList = new tsl::elm::List();

        peerList->addItem(new tsl::elm::CategoryHeader("Servers  |  \uE0E3 Auto Start  |  \uE0E0 Toggle", true));
        peerList->addItem(new tsl::elm::CustomDrawer([](tsl::gfx::Renderer *renderer, s32 x, s32 y, s32 w, s32 h) {
            renderer->drawString("\uE016 Only one peer can be running! Stop others first.", false, x + 5, y + 10, 15, tsl::warningTextColor);
            renderer->drawString("\uE016 Only one peer can be enabled for auto-start.", false, x + 5, y + 30, 15, tsl::warningTextColor);
        }), 45);

        for (const auto& peer : this->m_peers) {
            peer.listItem->enableShortHoldKey();
            peerList->addItem(peer.listItem);
        }
        peerList->addItem(new tsl::elm::CategoryHeader("Connection Info", true));
        m_activePeer = &m_peers[0];
        m_peerInfoDrawer = new tsl::elm::CustomDrawer([this](tsl::gfx::Renderer *renderer, s32 x, s32 y, s32 w, s32 h) {
            if (this->m_activePeer == nullptr) {
                renderer->drawString("No active peer", false, x + 15, y + 10, 15, tsl::infoTextColor);
                return;
            }
            const auto& peer = *this->m_activePeer;
            renderer->drawString("Address: " + peer.address, false, x + 15, y + 10, 15, tsl::infoTextColor);
            renderer->drawString("Endpoint: " + peer.endpoint, false, x + 15, y + 30, 15, tsl::infoTextColor);
            renderer->drawString("Last Handshake: " + moment(peer.lastHandshake) + " ago", false, x + 15, y + 50, 15, tsl::infoTextColor);
            renderer->drawString("RX: " + formatBytes(peer.rxBytes) + ",   TX: " + formatBytes(peer.txBytes), false, x + 15, y + 70, 15, tsl::infoTextColor);
        });
        peerList->addItem(m_peerInfoDrawer);
        rootFrame->setContent(peerList);
    }

    return rootFrame;
}

void GuiMain::update() {
    if (!this->smIsRunning())
        return;

    static u32 counter = 0;
    if (counter++ % 60 != 0) // Update every 60 frames (~1 second)
        return;

    m_activePeer = nullptr;
    for (auto& peer : this->m_peers) {
        updatePeer(peer);
        peer.listItem->setValue(descriptions[peer.isActive][peer.isAutoStartEnabled], !peer.isActive);
        if (peer.isActive)
            m_activePeer = &peer;
    }
    m_peerInfoDrawer->invalidate();
}

bool GuiMain::handleInput(u64 keysDown, u64 keysHeld, const HidTouchState &touchPos, HidAnalogStickState leftJoyStick, HidAnalogStickState rightJoyStick) {
    // Side-note: Not sure why it is needed, but for some reason the Overlay handleInput is being cannibalized. Added to ensure behavior.
    // Navigational boundary cases for handling wrapping
    static bool lastDirectionPressed = true;
    const bool directionPressed = ((keysHeld & KEY_UP) || (keysHeld & KEY_DOWN) || (keysHeld & KEY_LEFT) || (keysHeld & KEY_RIGHT));

    if (!directionPressed && lastDirectionPressed)
        tsl::elm::s_directionalKeyReleased.store(true, std::memory_order_release);
    else if (directionPressed && lastDirectionPressed)
        tsl::elm::s_directionalKeyReleased.store(false, std::memory_order_release);

    lastDirectionPressed = directionPressed;

    return false;
}

bool GuiMain::smIsRunning() {
    // TODO: remove
    return true;
    u64 pid = 0;
    return R_SUCCEEDED(pmdmntGetProcessId(&pid, WGNX_PROGRAM_ID)) && pid > 0;
}

// TODO: un-dummy
// Returns the list of currently configured peers accessible to the sysmodule
bool GuiMain::getPeers(std::vector<WireGuardPeer>& peers) {
    WireGuardPeer peer;
    peer = {
        .name = "Test",
        .address = "192.168.1.1/24",
        .endpoint = "example.com:51820",
        .lastHandshake = 0,
        .rxBytes = 0,
        .txBytes = 0,
        .isActive = false,
        .isAutoStartEnabled = false,
    };
    peers.push_back(peer);
    peer = {
        .name = "Example",
        .address = "192.168.1.2/26",
        .endpoint = "vpn.test.com:51821",
        .lastHandshake = 0,
        .rxBytes = 0,
        .txBytes = 0,
        .isActive = false,
        .isAutoStartEnabled = false,
    };
    peers.push_back(peer);
    return true;
}

// TODO: un-dummy
bool GuiMain::isActive(WireGuardPeer& peer) {
    return true;
}

// TODO: un-dummy
// Update the peer's state from the sysmodule.
// returns whether the update was successful.
bool GuiMain::updatePeer(WireGuardPeer& peer) {
    if (peer.isActive) {
        peer.lastHandshake = rand() % 3600;
        peer.rxBytes += rand() % 10000;
        peer.txBytes += rand() % 10000;
    } else {
        peer.lastHandshake = 0;
        peer.rxBytes = 0;
        peer.txBytes = 0;
    }
    return true;
}

std::string formatBytes(std::int32_t bytes) {
    const char* suffixes[] = {"B", "K", "M", "G"};
    int suffixIndex = 0;
    double count = static_cast<double>(bytes);

    while (count >= 1024 && suffixIndex < 3) {
        count /= 1024;
        suffixIndex++;
    }

    char buffer[8];
    snprintf(buffer, sizeof(buffer), "%.1f%s", count, suffixes[suffixIndex]);
    return std::string(buffer);
}

std::string moment(std::int32_t seconds) {
    if (seconds < 60)
        return std::to_string(seconds) + "s";
    else if (seconds < 3600)
        return std::to_string(seconds / 60) + "m";
    else
        return std::to_string(seconds / 3600) + "h";
}
