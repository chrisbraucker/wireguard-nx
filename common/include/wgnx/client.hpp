#pragma once

#include <switch.h>

#include "wgnx/protocol.hpp"

namespace wgnx::client {

class ScopedService {
public:
    ScopedService() = default;
    ~ScopedService() {
        if (m_active) {
            serviceClose(&m_service);
        }
    }

    ScopedService(const ScopedService&) = delete;
    ScopedService& operator=(const ScopedService&) = delete;

    Result open() {
        const Result rc = smGetService(&m_service, ServiceName);
        m_active = R_SUCCEEDED(rc);
        return rc;
    }

    Service* get() {
        return &m_service;
    }

private:
    Service m_service{};
    bool m_active{false};
};

inline bool IsServiceRunning() {
    ScopedService service;
    return R_SUCCEEDED(service.open());
}

inline Result GetApiVersion(std::uint32_t* out_version) {
    ScopedService service;
    Result rc = service.open();
    if (R_FAILED(rc)) {
        return rc;
    }

    return serviceDispatchOut(service.get(), static_cast<std::uint32_t>(CommandId::GetApiVersion), *out_version);
}

inline Result GetDaemonStatus(DaemonStatus* out_status) {
    ScopedService service;
    Result rc = service.open();
    if (R_FAILED(rc)) {
        return rc;
    }

    return serviceDispatchOut(service.get(), static_cast<std::uint32_t>(CommandId::GetDaemonStatus), *out_status);
}

inline Result ListPeers(PeerInfo* out_peers, std::uint32_t max_peers, std::uint32_t* out_count) {
    ScopedService service;
    Result rc = service.open();
    if (R_FAILED(rc)) {
        return rc;
    }

    return serviceDispatchOut(service.get(), static_cast<std::uint32_t>(CommandId::ListPeers), *out_count,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
        .buffers = { { out_peers, max_peers * sizeof(PeerInfo) } },
    );
}

inline Result SetActivePeer(std::int32_t peer_index) {
    ScopedService service;
    Result rc = service.open();
    if (R_FAILED(rc)) {
        return rc;
    }

    const PeerSelectionRequest request = {
        .peer_index = peer_index,
        .reserved = 0,
    };

    return serviceDispatchIn(service.get(), static_cast<std::uint32_t>(CommandId::SetActivePeer), request);
}

inline Result SetAutoStartPeer(std::int32_t peer_index) {
    ScopedService service;
    Result rc = service.open();
    if (R_FAILED(rc)) {
        return rc;
    }

    const PeerSelectionRequest request = {
        .peer_index = peer_index,
        .reserved = 0,
    };

    return serviceDispatchIn(service.get(), static_cast<std::uint32_t>(CommandId::SetAutoStartPeer), request);
}

} // namespace wgnx::client
