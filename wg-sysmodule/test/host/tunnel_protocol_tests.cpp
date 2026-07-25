#include "tunnel_protocol_tests.hpp"

#include "wgnx/tunnel_protocol.hpp"

namespace wgnx::test {

void TestTunnelProtocolContract(TestContext& context) {
    using namespace wgnx::tunnel;

    WGNX_TEST_REQUIRE(context,
                      TunApiVersion == 1 && wgnx::tunnel::ServiceName[0] == 'w' && wgnx::tunnel::ServiceName[4] == ':' &&
                          wgnx::tunnel::ServiceName[7] == 'n' && wgnx::tunnel::ServiceName[8] == '\0',
                      "tunnel root identity changed");
    WGNX_TEST_REQUIRE(context,
                      MaximumClientContexts == 4 && MaximumFlowsPerClient == 4 && MaximumFlows == 16 && MaximumUdpPayloadBytes == 1472 &&
                          OutboundPacketSlabCount == 16 && InboundPacketSlabCount == 16 && MaximumInboundDatagramsPerFlow == 4 &&
                          CompletionQueueCapacity == 16 && MaximumBatchEntries == 8 && MaximumPolicyRoutes == 16 &&
                          KernelHandlesPerClient == 1 && ReverseTupleQuarantineCapacity == 16,
                      "tunnel resource contract changed");
    WGNX_TEST_REQUIRE(context,
                      static_cast<std::uint32_t>(RootCommandId::GetTunApiVersion) == 0 &&
                          static_cast<std::uint32_t>(RootCommandId::OpenTunnelClient) == 1 &&
                          static_cast<std::uint32_t>(ClientCommandId::GetCapabilities) == 0 &&
                          static_cast<std::uint32_t>(ClientCommandId::GetRoutingPolicySnapshot) == 1 &&
                          static_cast<std::uint32_t>(ClientCommandId::GetCompletionEvent) == 2 &&
                          static_cast<std::uint32_t>(ClientCommandId::OpenConnectedUdpFlow) == 3 &&
                          static_cast<std::uint32_t>(ClientCommandId::SendUdpDatagram) == 4 &&
                          static_cast<std::uint32_t>(ClientCommandId::SendUdpDatagramBatch) == 5 &&
                          static_cast<std::uint32_t>(ClientCommandId::ReceiveCompletions) == 6 &&
                          static_cast<std::uint32_t>(ClientCommandId::GetFlowState) == 7 &&
                          static_cast<std::uint32_t>(ClientCommandId::CloseFlow) == 8,
                      "tunnel command identifiers changed");
    WGNX_TEST_REQUIRE(context,
                      SupportedCapabilityMask == 0x1FU && CapabilityMask(Capability::ConnectedIpv4Udp) == 0x01U &&
                          CapabilityMask(Capability::DatagramBatches) == 0x02U && CapabilityMask(Capability::CompletionEvent) == 0x04U &&
                          CapabilityMask(Capability::RoutingPolicySnapshot) == 0x08U && CapabilityMask(Capability::FlowStateQuery) == 0x10U,
                      "tunnel capability bits changed");
    WGNX_TEST_REQUIRE(
        context,
        static_cast<std::uint32_t>(ProtocolStatus::Success) == 0 && static_cast<std::uint32_t>(ProtocolStatus::MalformedInput) == 1 &&
            static_cast<std::uint32_t>(ProtocolStatus::UnsupportedOperation) == 2 &&
            static_cast<std::uint32_t>(ProtocolStatus::IncompatibleApiVersion) == 3 &&
            static_cast<std::uint32_t>(ProtocolStatus::RouteNotCovered) == 4 &&
            static_cast<std::uint32_t>(ProtocolStatus::PeerUnavailable) == 5 &&
            static_cast<std::uint32_t>(ProtocolStatus::TransportUnavailable) == 6 &&
            static_cast<std::uint32_t>(ProtocolStatus::FlowQuotaExhausted) == 7 &&
            static_cast<std::uint32_t>(ProtocolStatus::DatagramTooLarge) == 8 &&
            static_cast<std::uint32_t>(ProtocolStatus::QueueFull) == 9 && static_cast<std::uint32_t>(ProtocolStatus::StaleHandle) == 10 &&
            static_cast<std::uint32_t>(ProtocolStatus::FlowClosed) == 11 && static_cast<std::uint32_t>(ProtocolStatus::QueueEmpty) == 12 &&
            static_cast<std::uint32_t>(ProtocolStatus::OutputBufferTooSmall) == 13 &&
            static_cast<std::uint32_t>(ProtocolStatus::ReverseTupleExhausted) == 14,
        "tunnel protocol statuses changed");
    WGNX_TEST_REQUIRE(context,
                      static_cast<std::uint32_t>(FlowState::Open) == 0 && static_cast<std::uint32_t>(FlowState::Suspended) == 1 &&
                          static_cast<std::uint32_t>(FlowState::Closing) == 2 && static_cast<std::uint32_t>(FlowState::Closed) == 3 &&
                          static_cast<std::uint32_t>(FlowTerminalReason::None) == 0 &&
                          static_cast<std::uint32_t>(FlowTerminalReason::ClientClosed) == 1 &&
                          static_cast<std::uint32_t>(FlowTerminalReason::PeerDeactivated) == 2 &&
                          static_cast<std::uint32_t>(FlowTerminalReason::PeerActivationChanged) == 3 &&
                          static_cast<std::uint32_t>(FlowTerminalReason::PolicyInvalidated) == 4 &&
                          static_cast<std::uint32_t>(FlowTerminalReason::SysmoduleShutdown) == 5,
                      "tunnel flow lifecycle categories changed");
    WGNX_TEST_REQUIRE(context,
                      static_cast<std::uint32_t>(CompletionType::InboundDatagram) == 0 &&
                          static_cast<std::uint32_t>(CompletionType::FlowStateChanged) == 1 &&
                          static_cast<std::uint32_t>(CompletionType::PolicyChanged) == 2 &&
                          static_cast<std::uint32_t>(CompletionType::Writable) == 3,
                      "tunnel completion categories changed");
    WGNX_TEST_REQUIRE(context,
                      sizeof(FlowHandle) == 8 && sizeof(Ipv4Endpoint) == 8 && sizeof(Capabilities) == 64 &&
                          sizeof(OpenConnectedUdpFlowRequest) == 16 && sizeof(OpenConnectedUdpFlowResult) == 24 &&
                          sizeof(DatagramDescriptor) == 24 && sizeof(DatagramDisposition) == 16 && sizeof(CompletionRecord) == 48 &&
                          sizeof(FlowStateResult) == 40 && sizeof(RoutingPolicySnapshot) == 8 && sizeof(RouteRecord) == 32,
                      "tunnel binary record layout changed");
}

} // namespace wgnx::test
