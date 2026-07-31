#pragma once

#include <stratosphere.hpp>

#include "runtime/daemon_runtime.hpp"
#include "wgnx/tunnel_protocol.hpp"

#define WGNX_I_TUNNEL_ROOT_INTERFACE_INFO(C, H)                                                                                            \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C,                                                                                                                                 \
        H,                                                                                                                                 \
        static_cast<u32>(wgnx::tunnel::RootCommandId::GetTunApiVersion),                                                                   \
        ams::Result,                                                                                                                       \
        GetTunApiVersion,                                                                                                                  \
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
        static_cast<u32>(wgnx::tunnel::ClientCommandId::OpenConnectedUdpFlow),                                                             \
        ams::Result,                                                                                                                       \
        OpenConnectedUdpFlow,                                                                                                              \
        (ams::sf::Out<wgnx::tunnel::OpenConnectedUdpFlowResult> out, const wgnx::tunnel::OpenConnectedUdpFlowRequest& request),            \
        (out, request),                                                                                                                    \
        ams::hos::Version_Min,                                                                                                             \
        ams::hos::Version_Max                                                                                                              \
    )                                                                                                                                      \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C,                                                                                                                                 \
        H,                                                                                                                                 \
        static_cast<u32>(wgnx::tunnel::ClientCommandId::SendUdpDatagram),                                                                  \
        ams::Result,                                                                                                                       \
        SendUdpDatagram,                                                                                                                   \
        (ams::sf::Out<wgnx::tunnel::DatagramDisposition> out,                                                                              \
         const wgnx::tunnel::DatagramDescriptor& descriptor,                                                                               \
         const ams::sf::InMapAliasBuffer& payload),                                                                                        \
        (out, descriptor, payload),                                                                                                        \
        ams::hos::Version_Min,                                                                                                             \
        ams::hos::Version_Max                                                                                                              \
    )                                                                                                                                      \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C,                                                                                                                                 \
        H,                                                                                                                                 \
        static_cast<u32>(wgnx::tunnel::ClientCommandId::SendUdpDatagramBatch),                                                             \
        ams::Result,                                                                                                                       \
        SendUdpDatagramBatch,                                                                                                              \
        (const ams::sf::InMapAliasArray<wgnx::tunnel::DatagramDescriptor>& descriptors,                                                    \
         const ams::sf::InMapAliasBuffer& payload,                                                                                         \
         const ams::sf::OutMapAliasArray<wgnx::tunnel::DatagramDisposition>& dispositions),                                                \
        (descriptors, payload, dispositions),                                                                                              \
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
    ams::Result OpenConnectedUdpFlow(
        ams::sf::Out<wgnx::tunnel::OpenConnectedUdpFlowResult> out, const wgnx::tunnel::OpenConnectedUdpFlowRequest& request
    );
    ams::Result SendUdpDatagram(
        ams::sf::Out<wgnx::tunnel::DatagramDisposition> out,
        const wgnx::tunnel::DatagramDescriptor& descriptor,
        const ams::sf::InMapAliasBuffer& payload
    );
    ams::Result SendUdpDatagramBatch(
        const ams::sf::InMapAliasArray<wgnx::tunnel::DatagramDescriptor>& descriptors,
        const ams::sf::InMapAliasBuffer& payload,
        const ams::sf::OutMapAliasArray<wgnx::tunnel::DatagramDisposition>& dispositions
    );
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
    [[nodiscard]] bool
    IsPayloadRangeValid(const wgnx::tunnel::DatagramDescriptor& descriptor, const ams::sf::InMapAliasBuffer& payload) const;

    ams::os::SystemEvent m_completion_event;
    runtime::TunnelClientId m_client{};
};
static_assert(IsITunnelClient<TunnelClientService>);

class TunnelRootService {
  public:
    ams::Result GetTunApiVersion(ams::sf::Out<wgnx::tunnel::Capabilities> out);
    ams::Result OpenTunnelClient(ams::sf::Out<ams::sf::SharedPointer<ITunnelClient>> out);
};
static_assert(IsITunnelRoot<TunnelRootService>);

ams::sf::SharedPointer<ITunnelRoot> GetTunnelRootServiceObject();

} // namespace wgnx::sysmodule
