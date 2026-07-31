#pragma once

#include <switch.h>

#include "wgnx/protocol.hpp"

namespace wgnx::client {

class ScopedService {
  public:
    ScopedService() = default;
    ~ScopedService() {
        close();
    }

    ScopedService(const ScopedService&) = delete;
    ScopedService& operator=(const ScopedService&) = delete;

    Result open() {
        if (m_active) {
            return 0;
        }

        const Result rc = smGetService(&m_service, ServiceName);
        m_active = R_SUCCEEDED(rc);
        return rc;
    }

    void close() {
        if (!m_active) {
            return;
        }

        serviceClose(&m_service);
        m_service = {};
        m_active = false;
    }

    bool isOpen() const {
        return m_active;
    }

    Service* get() {
        return &m_service;
    }

  private:
    Service m_service{};
    bool m_active{false};
};

inline bool IsServiceRunning() {
    Handle handle = INVALID_HANDLE;
    const Result rc = smRegisterService(&handle, smEncodeName(ServiceName), false, 1);

    // smGetService blocks until the service appears, which is not appropriate for
    // UI/client liveness checks. Probe by attempting to register the same name:
    // failure means another process is already hosting it.
    if (R_FAILED(rc)) {
        return true;
    }

    smUnregisterService(smEncodeName(ServiceName));
    svcCloseHandle(handle);
    return false;
}

inline Result GetApiVersion(ScopedService& service, std::uint32_t* out_version) {
    if (!service.isOpen()) {
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    }

    return serviceDispatchOut(service.get(), static_cast<std::uint32_t>(CommandId::GetApiVersion), *out_version);
}

inline Result GetApiVersion(std::uint32_t* out_version) {
    ScopedService service;
    Result rc = service.open();
    if (R_FAILED(rc)) {
        return rc;
    }

    return GetApiVersion(service, out_version);
}

inline Result GetDaemonStatus(DaemonStatus* out_status) {
    ScopedService service;
    Result rc = service.open();
    if (R_FAILED(rc)) {
        return rc;
    }

    return serviceDispatchOut(service.get(), static_cast<std::uint32_t>(CommandId::GetDaemonStatus), *out_status);
}

inline Result GetBuildInfo(BuildInfo* out_info) {
    ScopedService service;
    Result rc = service.open();
    if (R_FAILED(rc)) {
        return rc;
    }

    return serviceDispatchOut(service.get(), static_cast<std::uint32_t>(CommandId::GetBuildInfo), *out_info);
}

inline Result ListPeers(PeerInfo* out_peers, std::uint32_t max_peers, std::uint32_t* out_count) {
    ScopedService service;
    Result rc = service.open();
    if (R_FAILED(rc)) {
        return rc;
    }

    return serviceDispatchOut(
        service.get(),
        static_cast<std::uint32_t>(CommandId::ListPeers),
        *out_count,
        .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
        .buffers = {{out_peers, max_peers * sizeof(PeerInfo)}},
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

inline Result TriggerDebugPayload(DebugTriggerAction action) {
    ScopedService service;
    Result rc = service.open();
    if (R_FAILED(rc)) {
        return rc;
    }

    const DebugTriggerRequest request = {
        .action = static_cast<std::uint32_t>(action),
        .reserved = 0,
    };

    return serviceDispatchIn(service.get(), static_cast<std::uint32_t>(CommandId::TriggerDebugPayload), request);
}

inline Result BumpUdpBinding() {
    ScopedService service;
    Result rc = service.open();
    if (R_FAILED(rc)) {
        return rc;
    }

    return serviceDispatch(service.get(), static_cast<std::uint32_t>(CommandId::BumpUdpBinding));
}

inline Result Shutdown() {
    ScopedService service;
    Result rc = service.open();
    if (R_FAILED(rc)) {
        return rc;
    }

    return serviceDispatch(service.get(), static_cast<std::uint32_t>(CommandId::Shutdown));
}

inline Result
SubmitInnerIpv4Packet(ScopedService& service, const void* packet, std::size_t packet_size, PacketSubmissionResult* out_result) {
    if (!service.isOpen()) {
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    }

    const std::uint64_t pid_placeholder = 0;

    return serviceDispatchInOut(
        service.get(),
        static_cast<std::uint32_t>(CommandId::SubmitInnerIpv4Packet),
        pid_placeholder,
        *out_result,
        .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_In},
        .buffers = {{packet, packet_size}},
        .in_send_pid = true
    );
}

inline Result ReceiveInnerIpv4Packet(ScopedService& service, void* packet, std::size_t packet_capacity, PacketReceiveResult* out_result) {
    if (!service.isOpen()) {
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    }

    const std::uint64_t pid_placeholder = 0;

    return serviceDispatchInOut(
        service.get(),
        static_cast<std::uint32_t>(CommandId::ReceiveInnerIpv4Packet),
        pid_placeholder,
        *out_result,
        .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
        .buffers = {{packet, packet_capacity}},
        .in_send_pid = true
    );
}

inline Result SubmitInnerIpv4Packet(const void* packet, std::size_t packet_size, PacketSubmissionResult* out_result) {
    ScopedService service;
    Result rc = service.open();
    if (R_FAILED(rc)) {
        return rc;
    }

    return SubmitInnerIpv4Packet(service, packet, packet_size, out_result);
}

inline Result ReceiveInnerIpv4Packet(void* packet, std::size_t packet_capacity, PacketReceiveResult* out_result) {
    ScopedService service;
    Result rc = service.open();
    if (R_FAILED(rc)) {
        return rc;
    }

    return ReceiveInnerIpv4Packet(service, packet, packet_capacity, out_result);
}

} // namespace wgnx::client
