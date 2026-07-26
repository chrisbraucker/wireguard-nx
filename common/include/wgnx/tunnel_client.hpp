#pragma once

#include <switch.h>

#include "wgnx/tunnel_protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <utility>

namespace wgnx::tunnel::client {

class ScopedRootService {
  public:
    ScopedRootService() = default;
    ~ScopedRootService() {
        Close();
    }

    ScopedRootService(const ScopedRootService&) = delete;
    ScopedRootService& operator=(const ScopedRootService&) = delete;

    ScopedRootService(ScopedRootService&& other) noexcept {
        *this = std::move(other);
    }

    ScopedRootService& operator=(ScopedRootService&& other) noexcept {
        if (this != std::addressof(other)) {
            Close();
            m_service = other.m_service;
            m_active = other.m_active;
            other.m_service = {};
            other.m_active = false;
        }
        return *this;
    }

    [[nodiscard]] Result Open() {
        if (m_active) {
            return 0;
        }
        const Result rc = smGetService(&m_service, ServiceName);
        m_active = R_SUCCEEDED(rc);
        return rc;
    }

    void Close() {
        if (m_active) {
            serviceClose(&m_service);
            m_service = {};
            m_active = false;
        }
    }

    [[nodiscard]] bool IsOpen() const {
        return m_active;
    }

    [[nodiscard]] Service* Get() {
        return &m_service;
    }

  private:
    Service m_service{};
    bool m_active{false};
};

class ScopedClient {
  public:
    ScopedClient() = default;
    ~ScopedClient() {
        Close();
    }

    ScopedClient(const ScopedClient&) = delete;
    ScopedClient& operator=(const ScopedClient&) = delete;

    ScopedClient(ScopedClient&& other) noexcept {
        *this = std::move(other);
    }

    ScopedClient& operator=(ScopedClient&& other) noexcept {
        if (this != std::addressof(other)) {
            Close();
            m_service = other.m_service;
            m_active = other.m_active;
            other.m_service = {};
            other.m_active = false;
        }
        return *this;
    }

    void Close() {
        if (m_active) {
            serviceClose(&m_service);
            m_service = {};
            m_active = false;
        }
    }

    [[nodiscard]] bool IsOpen() const {
        return m_active;
    }

    [[nodiscard]] Service* Get() {
        return &m_service;
    }

  private:
    friend Result OpenTunnelClient(ScopedRootService& root, ScopedClient* out_client);

    void Adopt(Service service) {
        Close();
        m_service = service;
        m_active = serviceIsActive(&m_service);
    }

    Service m_service{};
    bool m_active{false};
};

[[nodiscard]] inline bool IsServiceRunning() {
    Handle handle = INVALID_HANDLE;
    const Result rc = smRegisterService(&handle, smEncodeName(ServiceName), false, 1);
    if (R_FAILED(rc)) {
        return true;
    }
    smUnregisterService(smEncodeName(ServiceName));
    svcCloseHandle(handle);
    return false;
}

[[nodiscard]] inline Result GetTunCapabilities(ScopedRootService& root, Capabilities* out_capabilities) {
    if (!root.IsOpen() || out_capabilities == nullptr) {
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    }
    return serviceDispatchOut(root.Get(), static_cast<std::uint32_t>(RootCommandId::GetTunApiVersion), *out_capabilities);
}

[[nodiscard]] inline Result OpenTunnelClient(ScopedRootService& root, ScopedClient* out_client) {
    if (!root.IsOpen() || out_client == nullptr) {
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    }
    Service child{};
    const Result rc = serviceDispatch(root.Get(), static_cast<std::uint32_t>(RootCommandId::OpenTunnelClient), .out_num_objects = 1,
                                      .out_objects = &child);
    if (R_SUCCEEDED(rc)) {
        out_client->Adopt(child);
    }
    return rc;
}

[[nodiscard]] inline Result GetCapabilities(ScopedClient& client, Capabilities* out_capabilities) {
    if (!client.IsOpen() || out_capabilities == nullptr) {
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    }
    return serviceDispatchOut(client.Get(), static_cast<std::uint32_t>(ClientCommandId::GetCapabilities), *out_capabilities);
}

[[nodiscard]] inline Result GetRoutingPolicySnapshot(ScopedClient& client, RouteRecord* routes, std::size_t route_capacity,
                                                     RoutingPolicySnapshot* out_snapshot) {
    if (!client.IsOpen() || out_snapshot == nullptr || route_capacity > MaximumPolicyRoutes || (route_capacity != 0 && routes == nullptr)) {
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }
    return serviceDispatchOut(client.Get(), static_cast<std::uint32_t>(ClientCommandId::GetRoutingPolicySnapshot), *out_snapshot,
                              .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
                              .buffers = {{routes, route_capacity * sizeof(RouteRecord)}});
}

[[nodiscard]] inline Result GetCompletionEvent(ScopedClient& client, Handle* out_handle) {
    if (!client.IsOpen() || out_handle == nullptr) {
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    }
    *out_handle = INVALID_HANDLE;
    return serviceDispatch(client.Get(), static_cast<std::uint32_t>(ClientCommandId::GetCompletionEvent),
                           .out_handle_attrs = {SfOutHandleAttr_HipcCopy}, .out_handles = out_handle);
}

[[nodiscard]] inline Result OpenConnectedUdpFlow(ScopedClient& client, const OpenConnectedUdpFlowRequest& request,
                                                 OpenConnectedUdpFlowResult* out_result) {
    if (!client.IsOpen() || out_result == nullptr) {
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    }
    return serviceDispatchInOut(client.Get(), static_cast<std::uint32_t>(ClientCommandId::OpenConnectedUdpFlow), request, *out_result);
}

[[nodiscard]] inline Result SendUdpDatagram(ScopedClient& client, const DatagramDescriptor& descriptor, const void* payload,
                                            std::size_t payload_size, DatagramDisposition* out_disposition) {
    if (!client.IsOpen() || out_disposition == nullptr || (payload_size != 0 && payload == nullptr)) {
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    }
    return serviceDispatchInOut(client.Get(), static_cast<std::uint32_t>(ClientCommandId::SendUdpDatagram), descriptor, *out_disposition,
                                .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_In}, .buffers = {{payload, payload_size}});
}

[[nodiscard]] inline Result SendUdpDatagramBatch(ScopedClient& client, const DatagramDescriptor* descriptors, std::size_t descriptor_count,
                                                 const void* payload, std::size_t payload_size, DatagramDisposition* out_dispositions,
                                                 std::size_t disposition_count) {
    if (!client.IsOpen() || descriptor_count > MaximumBatchEntries || disposition_count < descriptor_count ||
        (descriptor_count != 0 && (descriptors == nullptr || out_dispositions == nullptr)) || (payload_size != 0 && payload == nullptr)) {
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }
    return serviceDispatch(client.Get(), static_cast<std::uint32_t>(ClientCommandId::SendUdpDatagramBatch),
                           .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_In, SfBufferAttr_HipcMapAlias | SfBufferAttr_In,
                                            SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
                           .buffers = {{descriptors, descriptor_count * sizeof(DatagramDescriptor)},
                                       {payload, payload_size},
                                       {out_dispositions, disposition_count * sizeof(DatagramDisposition)}});
}

[[nodiscard]] inline Result ReceiveCompletions(ScopedClient& client, CompletionRecord* records, std::size_t record_capacity, void* payload,
                                               std::size_t payload_capacity, std::uint32_t* out_count, ProtocolStatus* out_status) {
    if (!client.IsOpen() || out_count == nullptr || out_status == nullptr || record_capacity > MaximumBatchEntries ||
        (record_capacity != 0 && records == nullptr) || (payload_capacity != 0 && payload == nullptr)) {
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }
    CompletionDrainResult result{};
    const Result rc =
        serviceDispatchOut(client.Get(), static_cast<std::uint32_t>(ClientCommandId::ReceiveCompletions), result,
                           .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out, SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
                           .buffers = {{records, record_capacity * sizeof(CompletionRecord)}, {payload, payload_capacity}});
    if (R_SUCCEEDED(rc)) {
        *out_count = result.count;
        *out_status = result.status;
    }
    return rc;
}

[[nodiscard]] inline Result GetFlowState(ScopedClient& client, const FlowHandle& flow, FlowStateResult* out_state) {
    if (!client.IsOpen() || out_state == nullptr) {
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    }
    return serviceDispatchInOut(client.Get(), static_cast<std::uint32_t>(ClientCommandId::GetFlowState), flow, *out_state);
}

[[nodiscard]] inline Result CloseFlow(ScopedClient& client, const FlowHandle& flow, ProtocolStatus* out_status) {
    if (!client.IsOpen() || out_status == nullptr) {
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    }
    return serviceDispatchInOut(client.Get(), static_cast<std::uint32_t>(ClientCommandId::CloseFlow), flow, *out_status);
}

} // namespace wgnx::tunnel::client
