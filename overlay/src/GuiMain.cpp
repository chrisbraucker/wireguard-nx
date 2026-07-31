#include "GuiMain.hpp"

#include "wgnx/client.hpp"
#include "wgnx/build_info.hpp"
#include "wgnx/mitm_client.hpp"

#include <algorithm>
#include <array>

constexpr const char* const descriptions[2][2] = {
    [0] =
        {
            [0] = "\uE098\uE031Off",
            [1] = "\uE0F4\uE031Off",
        },
    [1] = {
        [0] = "\uE098\uE031On",
        [1] = "\uE0F4\uE031On",
    },
};

std::string formatHex32(std::uint32_t value);
std::string displayEndpoint(const WireGuardPeer& peer);

GuiMain::GuiMain() {
    m_peers.reserve(5);
    if (!this->smIsRunning())
        return;
    if (!this->getPeers(this->m_peers))
        return;

    for (auto& peer : this->m_peers) {
        const std::int32_t peer_index = peer.index;
        peer.listItem = new tsl::elm::ListItem(peer.name);
        peer.listItem->setValue(descriptions[peer.isActive][peer.isAutoStartEnabled], !peer.isActive);
        peer.listItem->setClickListener([this, peer_index](u64 keys) {
            WireGuardPeer* peer = this->findPeerByIndex(peer_index);
            if (peer == nullptr)
                return true;

            if (keys & KEY_Y) {
                const std::int32_t next_index = peer->isAutoStartEnabled ? -1 : peer->index;
                if (R_FAILED(wgnx::client::SetAutoStartPeer(next_index)))
                    return true;

                this->refreshPeers();
                if (m_peerInfoDrawer != nullptr)
                    m_peerInfoDrawer->invalidate();
                return true;
            } else if (keys & KEY_A) {
                const std::int32_t next_index = peer->isActive ? -1 : peer->index;
                if (R_FAILED(wgnx::client::SetActivePeer(next_index)))
                    return true;

                this->refreshPeers();
                if (m_peerInfoDrawer != nullptr)
                    m_peerInfoDrawer->invalidate();
                return true;
            }
            return false;
        });
    }
}

GuiMain::~GuiMain() {}

tsl::elm::Element* GuiMain::createUI() {
    tsl::elm::OverlayFrame* rootFrame = new tsl::elm::OverlayFrame(APP_TITLE, wgnx::build_info::VersionWithBuild);

    if (!this->smIsRunning()) {
        const char* desc = "WireGuard-NX SysModule\n          is not running!";

        auto* warning = new tsl::elm::CustomDrawer([desc](tsl::gfx::Renderer* renderer, s32 x, s32 y, s32 w, s32 h) {
            renderer->drawString("\uE150", false, 180, 250, 90, renderer->a(0xFFFF));
            renderer->drawString(desc, false, 60, 340, 25, tsl::warningTextColor);
        });

        rootFrame->setContent(warning);
    } else if (this->m_peers.empty()) {
        const char* desc = "No servers configured!";

        auto* warning = new tsl::elm::CustomDrawer([desc](tsl::gfx::Renderer* renderer, s32 x, s32 y, s32 w, s32 h) {
            renderer->drawString("\uE150", false, 180, 250, 90, renderer->a(0xFFFF));
            renderer->drawString(desc, false, 90, 340, 25, tsl::warningTextColor);
        });

        rootFrame->setContent(warning);
    } else {
        tsl::elm::List* peerList = new tsl::elm::List();

        peerList->addItem(new tsl::elm::CategoryHeader("Servers  |  \uE0E3 Auto Start  |  \uE0E0 Toggle", true));
        peerList->addItem(
            new tsl::elm::CustomDrawer([](tsl::gfx::Renderer* renderer, s32 x, s32 y, s32 w, s32 h) {
                renderer->drawString(
                    "\uE016 Only one peer can be running! Stop others first.",
                    false,
                    x + 5,
                    y + 10,
                    15,
                    tsl::warningTextColor
                );
                renderer
                    ->drawString("\uE016 Only one peer can be enabled for auto-start.", false, x + 5, y + 30, 15, tsl::warningTextColor);
            }),
            45
        );

        for (const auto& peer : this->m_peers) {
            peer.listItem->enableShortHoldKey();
            peerList->addItem(peer.listItem);
        }
        if (wgnx::mitm::client::IsServiceRunning()) {
            peerList->addItem(new tsl::elm::CategoryHeader("MITM", true));
            auto* stopMitm = new tsl::elm::ListItem("Stop MITM");
            stopMitm->setValue("A", false);
            stopMitm->setClickListener([](u64 keys) {
                if ((keys & KEY_A) == 0) {
                    return false;
                }

                static_cast<void>(wgnx::mitm::client::Shutdown());
                return true;
            });
            peerList->addItem(stopMitm);
        }
        peerList->addItem(new tsl::elm::CategoryHeader("Connection Info", true));
        m_activePeer = nullptr;
        for (auto& peer : this->m_peers) {
            if (peer.isActive) {
                m_activePeer = &peer;
                break;
            }
        }
        m_peerInfoDrawer = new tsl::elm::CustomDrawer([this](tsl::gfx::Renderer* renderer, s32 x, s32 y, s32 w, s32 h) {
            if (this->m_activePeer == nullptr) {
                renderer->drawString("No active peer", false, x + 15, y + 10, 15, tsl::infoTextColor);
                return;
            }
            const auto& peer = *this->m_activePeer;
            renderer->drawString("State: " + peerStateSummary(peer), false, x + 15, y + 10, 15, tsl::infoTextColor);
            renderer->drawString("Detail: " + peerStateDetail(peer), false, x + 15, y + 30, 15, tsl::infoTextColor);
            renderer->drawString("Address: " + peer.address, false, x + 15, y + 50, 15, tsl::infoTextColor);
            renderer->drawString("Endpoint: " + displayEndpoint(peer), false, x + 15, y + 70, 15, tsl::infoTextColor);
            renderer->drawString("Last Handshake: " + moment(peer.lastHandshake), false, x + 15, y + 90, 15, tsl::infoTextColor);
            renderer->drawString(
                "Last RX: " + moment(peer.lastRx) + ",   Last TX: " + moment(peer.lastTx),
                false,
                x + 15,
                y + 110,
                15,
                tsl::infoTextColor
            );
            renderer->drawString(
                "RX: " + formatBytes(peer.rxBytes) + ",   TX: " + formatBytes(peer.txBytes),
                false,
                x + 15,
                y + 130,
                15,
                tsl::infoTextColor
            );
            renderer->drawString(
                "Keepalive: " + (peer.persistentKeepaliveInterval > 0 ? (std::to_string(peer.persistentKeepaliveInterval) + "s")
                                                                      : std::string("false")),
                false,
                x + 15,
                y + 150,
                15,
                tsl::infoTextColor
            );
            if (peer.debugProbeStatus != static_cast<std::uint32_t>(wgnx::DebugProbeStatus::None)) {
                renderer->drawString(
                    "Probe: " + std::string(wgnx::GetDebugTriggerActionName(static_cast<wgnx::DebugTriggerAction>(peer.debugProbeAction))) +
                        " / " + std::string(wgnx::GetDebugProbeStatusName(static_cast<wgnx::DebugProbeStatus>(peer.debugProbeStatus))) +
                        " / " + moment(peer.lastDebugProbe),
                    false,
                    x + 15,
                    y + 170,
                    15,
                    peer.debugProbeStatus == static_cast<std::uint32_t>(wgnx::DebugProbeStatus::ReplyValidated) ? tsl::infoTextColor
                                                                                                                : tsl::warningTextColor
                );
            }
            if (peer.hasError) {
                renderer->drawString(
                    "Error: " + peerErrorStage(peer.errorStage) + " / " + peerErrorCode(peer.lastErrorCode),
                    false,
                    x + 15,
                    y + (peer.debugProbeStatus != static_cast<std::uint32_t>(wgnx::DebugProbeStatus::None) ? 190 : 170),
                    15,
                    tsl::warningTextColor
                );
            }
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

    this->refreshPeers();
    if (m_peerInfoDrawer != nullptr)
        m_peerInfoDrawer->invalidate();
}

bool GuiMain::handleInput(
    u64 keysDown, u64 keysHeld, const HidTouchState& touchPos, HidAnalogStickState leftJoyStick, HidAnalogStickState rightJoyStick
) {
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
    return wgnx::client::IsServiceRunning();
}

bool GuiMain::getPeers(std::vector<WireGuardPeer>& peers) {
    std::array<wgnx::PeerInfo, wgnx::MaxPeers> remote_peers{};
    std::uint32_t count = 0;
    if (R_FAILED(wgnx::client::ListPeers(remote_peers.data(), remote_peers.size(), &count)))
        return false;

    peers.clear();
    for (std::uint32_t i = 0; i < count && i < remote_peers.size(); ++i) {
        const auto& remote = remote_peers[i];
        peers.push_back({
            .index = static_cast<std::int32_t>(i),
            .listItem = nullptr,
            .name = remote.name,
            .address = remote.address,
            .endpoint = remote.endpoint,
            .resolvedEndpoint = remote.resolved_endpoint,
            .lastHandshake = remote.last_handshake_seconds,
            .lastRx = remote.last_rx_seconds,
            .lastTx = remote.last_tx_seconds,
            .lastDebugProbe = remote.last_debug_probe_seconds,
            .lastErrorCode = remote.last_error_code,
            .debugProbeAction = remote.debug_probe_action,
            .debugProbeStatus = remote.debug_probe_status,
            .persistentKeepaliveInterval = remote.persistent_keepalive_interval,
            .runtimeState = remote.runtime_state,
            .errorStage = remote.error_stage,
            .resolvedFamily = remote.resolved_family,
            .rxBytes = remote.rx_bytes,
            .txBytes = remote.tx_bytes,
            .isActive = (remote.flags & wgnx::PeerFlag_Active) != 0,
            .isAutoStartEnabled = (remote.flags & wgnx::PeerFlag_AutoStart) != 0,
            .isEstablished = (remote.flags & wgnx::PeerFlag_Established) != 0,
            .hasError = (remote.flags & wgnx::PeerFlag_HasError) != 0,
            .hasResolvedEndpoint = (remote.flags & wgnx::PeerFlag_HasResolvedEndpoint) != 0,
        });
    }

    return true;
}

bool GuiMain::refreshPeers() {
    std::vector<WireGuardPeer> remote_peers;
    if (!this->getPeers(remote_peers))
        return false;

    m_activePeer = nullptr;
    for (auto& peer : this->m_peers) {
        const auto remote_peer = std::find_if(remote_peers.begin(), remote_peers.end(), [&peer](const WireGuardPeer& candidate) {
            return candidate.index == peer.index;
        });
        if (remote_peer == remote_peers.end())
            continue;

        peer.address = remote_peer->address;
        peer.endpoint = remote_peer->endpoint;
        peer.resolvedEndpoint = remote_peer->resolvedEndpoint;
        peer.lastHandshake = remote_peer->lastHandshake;
        peer.lastRx = remote_peer->lastRx;
        peer.lastTx = remote_peer->lastTx;
        peer.lastDebugProbe = remote_peer->lastDebugProbe;
        peer.lastErrorCode = remote_peer->lastErrorCode;
        peer.debugProbeAction = remote_peer->debugProbeAction;
        peer.debugProbeStatus = remote_peer->debugProbeStatus;
        peer.persistentKeepaliveInterval = remote_peer->persistentKeepaliveInterval;
        peer.runtimeState = remote_peer->runtimeState;
        peer.errorStage = remote_peer->errorStage;
        peer.resolvedFamily = remote_peer->resolvedFamily;
        peer.rxBytes = remote_peer->rxBytes;
        peer.txBytes = remote_peer->txBytes;
        peer.isActive = remote_peer->isActive;
        peer.isAutoStartEnabled = remote_peer->isAutoStartEnabled;
        peer.isEstablished = remote_peer->isEstablished;
        peer.hasError = remote_peer->hasError;
        peer.hasResolvedEndpoint = remote_peer->hasResolvedEndpoint;

        peer.listItem->setValue(descriptions[peer.isActive][peer.isAutoStartEnabled], !peer.isActive);
        if (peer.isActive)
            m_activePeer = &peer;
    }

    return true;
}

WireGuardPeer* GuiMain::findPeerByIndex(std::int32_t peerIndex) {
    const auto it =
        std::find_if(m_peers.begin(), m_peers.end(), [peerIndex](const WireGuardPeer& peer) { return peer.index == peerIndex; });
    return it != m_peers.end() ? std::addressof(*it) : nullptr;
}

std::string formatBytes(std::uint64_t bytes) {
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

std::string formatHex32(std::uint32_t value) {
    char buffer[9];
    std::snprintf(buffer, sizeof(buffer), "%08X", value);
    return std::string(buffer);
}

std::string displayEndpoint(const WireGuardPeer& peer) {
    if (peer.isActive && peer.hasResolvedEndpoint) {
        return peer.resolvedEndpoint;
    }

    return peer.endpoint;
}

std::string moment(std::int32_t seconds) {
    if (seconds < 0)
        return "Never";
    if (seconds < 60)
        return std::to_string(seconds) + "s ago";
    else if (seconds < 3600)
        return std::to_string(seconds / 60) + "m ago";
    else
        return std::to_string(seconds / 3600) + "h ago";
}

std::string peerStateSummary(const WireGuardPeer& peer) {
    if (peer.hasError)
        return "error";

    const auto state = static_cast<wgnx::PeerRuntimeState>(peer.runtimeState);
    if (state == wgnx::PeerRuntimeState::Inactive) {
        return "inactive";
    }

    return "active";
}

std::string peerStateDetail(const WireGuardPeer& peer) {
    switch (static_cast<wgnx::PeerRuntimeState>(peer.runtimeState)) {
    case wgnx::PeerRuntimeState::Inactive:
        return "configured but stopped";
    case wgnx::PeerRuntimeState::ResolvingEndpoint:
        return "resolving endpoint";
    case wgnx::PeerRuntimeState::Handshaking:
        return "handshaking";
    case wgnx::PeerRuntimeState::Active:
        return peer.isEstablished ? "established" : "active";
    case wgnx::PeerRuntimeState::Error:
        return "local failure";
    }

    return "configured but stopped";
}

std::string peerErrorStage(std::uint8_t stage) {
    return wgnx::GetPeerErrorStageName(static_cast<wgnx::PeerErrorStage>(stage));
}

std::string peerErrorCode(std::uint32_t code) {
    return wgnx::GetPeerErrorCodeName(static_cast<wgnx::PeerErrorCode>(code));
}
