#pragma once

#include <stratosphere.hpp>

#include "runtime/daemon_runtime.hpp"
#include "wgnx/tunnel_protocol.hpp"

#define WGNX_I_TUNNEL_ROOT_INTERFACE_INFO(C, H)                                                                                            \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C,                                                                                                                                 \
        H,                                                                                                                                 \
        static_cast<u32>(wgnx::tunnel::RootCommandId::GetCapabilities),                                                                    \
        ams::Result,                                                                                                                       \
        GetCapabilities,                                                                                                                   \
        (ams::sf::Out<wgnx::tunnel::Capabilities> out),                                                                                    \
        (out),                                                                                                                             \
        ams::hos::Version_Min,                                                                                                             \
        ams::hos::Version_Max                                                                                                              \
    )                                                                                                                                      \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C,                                                                                                                                 \
        H,                                                                                                                                 \
        static_cast<u32>(wgnx::tunnel::RootCommandId::OpenTunnelClient),                                                                   \
        ams::Result,                                                                                                                       \
        OpenTunnelClient,                                                                                                                  \
        (ams::sf::Out<ams::sf::SharedPointer<wgnx::sysmodule::ITunnelClient>> out),                                                        \
        (out),                                                                                                                             \
        ams::hos::Version_Min,                                                                                                             \
        ams::hos::Version_Max                                                                                                              \
    )

#define WGNX_I_TUNNEL_CLIENT_INTERFACE_INFO(C, H)                                                                                          \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C,                                                                                                                                 \
        H,                                                                                                                                 \
        static_cast<u32>(wgnx::tunnel::ClientCommandId::GetCapabilities),                                                                  \
        ams::Result,                                                                                                                       \
        GetCapabilities,                                                                                                                   \
        (ams::sf::Out<wgnx::tunnel::Capabilities> out),                                                                                    \
        (out),                                                                                                                             \
        ams::hos::Version_Min,                                                                                                             \
        ams::hos::Version_Max                                                                                                              \
    )                                                                                                                                      \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C,                                                                                                                                 \
        H,                                                                                                                                 \
        static_cast<u32>(wgnx::tunnel::ClientCommandId::GetRoutingPolicySnapshot),                                                         \
        ams::Result,                                                                                                                       \
        GetRoutingPolicySnapshot,                                                                                                          \
        (ams::sf::Out<wgnx::tunnel::RoutingPolicySnapshot> out, const ams::sf::OutMapAliasArray<wgnx::tunnel::RouteRecord>& routes),       \
        (out, routes),                                                                                                                     \
        ams::hos::Version_Min,                                                                                                             \
        ams::hos::Version_Max                                                                                                              \
    )                                                                                                                                      \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C,                                                                                                                                 \
        H,                                                                                                                                 \
        static_cast<u32>(wgnx::tunnel::ClientCommandId::GetCompletionEvent),                                                               \
        ams::Result,                                                                                                                       \
        GetCompletionEvent,                                                                                                                \
        (ams::sf::OutCopyHandle out),                                                                                                      \
        (out),                                                                                                                             \
        ams::hos::Version_Min,                                                                                                             \
        ams::hos::Version_Max                                                                                                              \
    )                                                                                                                                      \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C,                                                                                                                                 \
        H,                                                                                                                                 \
        static_cast<u32>(wgnx::tunnel::ClientCommandId::OpenConnectedFlow),                                                                \
        ams::Result,                                                                                                                       \
        OpenConnectedFlow,                                                                                                                 \
        (ams::sf::Out<wgnx::tunnel::OpenConnectedFlowResult> out, const wgnx::tunnel::OpenConnectedFlowRequest& request),                  \
        (out, request),                                                                                                                    \
        ams::hos::Version_Min,                                                                                                             \
        ams::hos::Version_Max                                                                                                              \
    )                                                                                                                                      \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C,                                                                                                                                 \
        H,                                                                                                                                 \
        static_cast<u32>(wgnx::tunnel::ClientCommandId::SendUdpDatagramBatch),                                                             \
        ams::Result,                                                                                                                       \
        SendUdpDatagramBatch,                                                                                                              \
        (const ams::sf::InMapAliasArray<wgnx::tunnel::PayloadRange>& descriptors,                                                          \
         const ams::sf::InMapAliasBuffer& payload,                                                                                         \
         const ams::sf::OutMapAliasArray<wgnx::tunnel::PayloadResult>& dispositions),                                                      \
        (descriptors, payload, dispositions),                                                                                              \
        ams::hos::Version_Min,                                                                                                             \
        ams::hos::Version_Max                                                                                                              \
    )                                                                                                                                      \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C,                                                                                                                                 \
        H,                                                                                                                                 \
        static_cast<u32>(wgnx::tunnel::ClientCommandId::WriteTcpStream),                                                                   \
        ams::Result,                                                                                                                       \
        WriteTcpStream,                                                                                                                    \
        (ams::sf::Out<wgnx::tunnel::PayloadResult> out,                                                                                    \
         const wgnx::tunnel::PayloadRange& range,                                                                                          \
         const ams::sf::InMapAliasBuffer& payload),                                                                                        \
        (out, range, payload),                                                                                                             \
        ams::hos::Version_Min,                                                                                                             \
        ams::hos::Version_Max                                                                                                              \
    )                                                                                                                                      \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C,                                                                                                                                 \
        H,                                                                                                                                 \
        static_cast<u32>(wgnx::tunnel::ClientCommandId::ShutdownTcpWrite),                                                                 \
        ams::Result,                                                                                                                       \
        ShutdownTcpWrite,                                                                                                                  \
        (ams::sf::Out<wgnx::tunnel::ProtocolStatus> out, const wgnx::tunnel::FlowHandle& flow),                                            \
        (out, flow),                                                                                                                       \
        ams::hos::Version_Min,                                                                                                             \
        ams::hos::Version_Max                                                                                                              \
    )                                                                                                                                      \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C,                                                                                                                                 \
        H,                                                                                                                                 \
        static_cast<u32>(wgnx::tunnel::ClientCommandId::ReceiveCompletions),                                                               \
        ams::Result,                                                                                                                       \
        ReceiveCompletions,                                                                                                                \
        (ams::sf::Out<u32> out_count,                                                                                                      \
         ams::sf::Out<wgnx::tunnel::ProtocolStatus> out_status,                                                                            \
         const ams::sf::OutMapAliasArray<wgnx::tunnel::CompletionRecord>& records,                                                         \
         const ams::sf::OutMapAliasBuffer& payload),                                                                                       \
        (out_count, out_status, records, payload),                                                                                         \
        ams::hos::Version_Min,                                                                                                             \
        ams::hos::Version_Max                                                                                                              \
    )                                                                                                                                      \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C,                                                                                                                                 \
        H,                                                                                                                                 \
        static_cast<u32>(wgnx::tunnel::ClientCommandId::GetFlowState),                                                                     \
        ams::Result,                                                                                                                       \
        GetFlowState,                                                                                                                      \
        (ams::sf::Out<wgnx::tunnel::FlowStateResult> out, const wgnx::tunnel::FlowHandle& flow),                                           \
        (out, flow),                                                                                                                       \
        ams::hos::Version_Min,                                                                                                             \
        ams::hos::Version_Max                                                                                                              \
    )                                                                                                                                      \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C,                                                                                                                                 \
        H,                                                                                                                                 \
        static_cast<u32>(wgnx::tunnel::ClientCommandId::CloseFlow),                                                                        \
        ams::Result,                                                                                                                       \
        CloseFlow,                                                                                                                         \
        (ams::sf::Out<wgnx::tunnel::ProtocolStatus> out, const wgnx::tunnel::FlowHandle& flow),                                            \
        (out, flow),                                                                                                                       \
        ams::hos::Version_Min,                                                                                                             \
        ams::hos::Version_Max                                                                                                              \
    )

AMS_SF_DEFINE_INTERFACE(wgnx::sysmodule, ITunnelClient, WGNX_I_TUNNEL_CLIENT_INTERFACE_INFO, 0x57475443);
AMS_SF_DEFINE_INTERFACE(wgnx::sysmodule, ITunnelRoot, WGNX_I_TUNNEL_ROOT_INTERFACE_INFO, 0x57475452);

namespace wgnx::sysmodule {

class TunnelClientService {
  public:
    TunnelClientService();
    ~TunnelClientService();

    bool Initialize();
    ams::Result GetCapabilities(ams::sf::Out<wgnx::tunnel::Capabilities> out);
    ams::Result GetRoutingPolicySnapshot(
        ams::sf::Out<wgnx::tunnel::RoutingPolicySnapshot> out, const ams::sf::OutMapAliasArray<wgnx::tunnel::RouteRecord>& routes
    );
    ams::Result GetCompletionEvent(ams::sf::OutCopyHandle out);
    ams::Result OpenConnectedFlow(
        ams::sf::Out<wgnx::tunnel::OpenConnectedFlowResult> out, const wgnx::tunnel::OpenConnectedFlowRequest& request
    );
    ams::Result SendUdpDatagramBatch(
        const ams::sf::InMapAliasArray<wgnx::tunnel::PayloadRange>& descriptors,
        const ams::sf::InMapAliasBuffer& payload,
        const ams::sf::OutMapAliasArray<wgnx::tunnel::PayloadResult>& dispositions
    );
    ams::Result WriteTcpStream(
        ams::sf::Out<wgnx::tunnel::PayloadResult> out, const wgnx::tunnel::PayloadRange& range, const ams::sf::InMapAliasBuffer& payload
    );
    ams::Result ShutdownTcpWrite(ams::sf::Out<wgnx::tunnel::ProtocolStatus> out, const wgnx::tunnel::FlowHandle& flow);
    ams::Result ReceiveCompletions(
        ams::sf::Out<u32> out_count,
        ams::sf::Out<wgnx::tunnel::ProtocolStatus> out_status,
        const ams::sf::OutMapAliasArray<wgnx::tunnel::CompletionRecord>& records,
        const ams::sf::OutMapAliasBuffer& payload
    );
    ams::Result GetFlowState(ams::sf::Out<wgnx::tunnel::FlowStateResult> out, const wgnx::tunnel::FlowHandle& flow);
    ams::Result CloseFlow(ams::sf::Out<wgnx::tunnel::ProtocolStatus> out, const wgnx::tunnel::FlowHandle& flow);

  private:
    static void SignalCompletionEvent(void* context);
    static void ClearCompletionEvent(void* context);
    [[nodiscard]] bool IsPayloadRangeValid(const wgnx::tunnel::PayloadRange& descriptor, const ams::sf::InMapAliasBuffer& payload) const;

    ams::os::SystemEvent m_completion_event;
    runtime::TunnelClientId m_client{};
};
static_assert(IsITunnelClient<TunnelClientService>);

class TunnelRootService {
  public:
    ams::Result GetCapabilities(ams::sf::Out<wgnx::tunnel::Capabilities> out);
    ams::Result OpenTunnelClient(ams::sf::Out<ams::sf::SharedPointer<ITunnelClient>> out);
};
static_assert(IsITunnelRoot<TunnelRootService>);

ams::sf::SharedPointer<ITunnelRoot> GetTunnelRootServiceObject();

} // namespace wgnx::sysmodule
