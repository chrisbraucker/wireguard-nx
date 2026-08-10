#include "tunnel_protocol_tests.hpp"

#include "wgnx/tunnel_protocol.hpp"
#include "wgnx/tunnel_batch.hpp"
#include "wgnx/protocol.hpp"

#include <array>
#include <span>

namespace wgnx::test {

void TestTunnelProtocolContract(TestContext& context) {
    using namespace wgnx::tunnel;

    WGNX_TEST_REQUIRE(
        context,
        wgnx::IpcApiVersion == 5 && static_cast<std::uint32_t>(wgnx::CommandId::Shutdown) == 24,
        "control shutdown contract changed"
    );

    WGNX_TEST_REQUIRE(
        context,
        TunApiVersion == 4 && wgnx::tunnel::ServiceName[0] == 'w' && wgnx::tunnel::ServiceName[4] == ':' &&
            wgnx::tunnel::ServiceName[7] == 'n' && wgnx::tunnel::ServiceName[8] == '\0',
        "tunnel root identity changed"
    );
    WGNX_TEST_REQUIRE(
        context,
        MaximumClientContexts == 4 && MaximumFlowsPerClient == 4 && MaximumFlows == 16 && MaximumUdpPayloadStorageBytes == 1472 &&
            MaximumTcpWriteStorageBytes == 1460 && CompletionQueueCapacity == 16 && MaximumBatchEntries == 8 && MaximumPolicyRoutes == 16,
        "tunnel resource contract changed"
    );
    WGNX_TEST_REQUIRE(
        context,
        DefaultEffectiveInnerMtu == 1420 && MinimumEffectiveInnerMtu == 576 && MaximumEffectiveInnerMtu == 1500 &&
            IsValidEffectiveInnerMtu(DefaultEffectiveInnerMtu) && IsValidEffectiveInnerMtu(1500) && !IsValidEffectiveInnerMtu(575) &&
            !IsValidEffectiveInnerMtu(1501) && ResolveEffectiveInnerMtu(0) == DefaultEffectiveInnerMtu &&
            ResolveEffectiveInnerMtu(1280) == 1280 && MaximumUdpPayloadForInnerMtu(DefaultEffectiveInnerMtu) == 1392 &&
            MaximumUdpPayloadForInnerMtu(1280) == 1252 && MaximumUdpPayloadForInnerMtu(575) == 0,
        "effective inner MTU contract changed"
    );
    WGNX_TEST_REQUIRE(
        context,
        static_cast<std::uint32_t>(RootCommandId::GetCapabilities) == 0 &&
            static_cast<std::uint32_t>(RootCommandId::OpenTunnelClient) == 1 &&
            static_cast<std::uint32_t>(ClientCommandId::GetCapabilities) == 0 &&
            static_cast<std::uint32_t>(ClientCommandId::GetRoutingPolicySnapshot) == 1 &&
            static_cast<std::uint32_t>(ClientCommandId::GetCompletionEvent) == 2 &&
            static_cast<std::uint32_t>(ClientCommandId::OpenConnectedUdpFlow) == 3 &&
            static_cast<std::uint32_t>(ClientCommandId::SendUdpDatagramBatch) == 4 &&
            static_cast<std::uint32_t>(ClientCommandId::ReceiveCompletions) == 5 &&
            static_cast<std::uint32_t>(ClientCommandId::GetFlowState) == 6 && static_cast<std::uint32_t>(ClientCommandId::CloseFlow) == 7 &&
            static_cast<std::uint32_t>(ClientCommandId::OpenConnectedTcpFlow) == 8 &&
            static_cast<std::uint32_t>(ClientCommandId::WriteTcpStream) == 9 &&
            static_cast<std::uint32_t>(ClientCommandId::ShutdownTcpWrite) == 10,
        "tunnel command identifiers changed"
    );
    WGNX_TEST_REQUIRE(
        context,
        SupportedCapabilityMask == 0x03U && CapabilityMask(Capability::ConnectedIpv4Udp) == 0x01U &&
            CapabilityMask(Capability::ConnectedIpv4Tcp) == 0x02U,
        "tunnel capability bits changed"
    );
    WGNX_TEST_REQUIRE(
        context,
        static_cast<std::uint32_t>(ProtocolStatus::Success) == 0 && static_cast<std::uint32_t>(ProtocolStatus::MalformedInput) == 1 &&
            static_cast<std::uint32_t>(ProtocolStatus::UnsupportedOperation) == 2 &&
            static_cast<std::uint32_t>(ProtocolStatus::IncompatibleApiVersion) == 3 &&
            static_cast<std::uint32_t>(ProtocolStatus::RouteNotCovered) == 4 &&
            static_cast<std::uint32_t>(ProtocolStatus::PeerUnavailable) == 5 &&
            static_cast<std::uint32_t>(ProtocolStatus::TransportUnavailable) == 6 &&
            static_cast<std::uint32_t>(ProtocolStatus::FlowQuotaExhausted) == 7 &&
            static_cast<std::uint32_t>(ProtocolStatus::PayloadTooLarge) == 8 &&
            static_cast<std::uint32_t>(ProtocolStatus::QueueFull) == 9 && static_cast<std::uint32_t>(ProtocolStatus::StaleHandle) == 10 &&
            static_cast<std::uint32_t>(ProtocolStatus::FlowClosed) == 11 && static_cast<std::uint32_t>(ProtocolStatus::QueueEmpty) == 12 &&
            static_cast<std::uint32_t>(ProtocolStatus::OutputBufferTooSmall) == 13 &&
            static_cast<std::uint32_t>(ProtocolStatus::ReverseTupleExhausted) == 14 &&
            static_cast<std::uint32_t>(ProtocolStatus::TunnelBlockedByPolicy) == 15 &&
            static_cast<std::uint32_t>(ProtocolStatus::WrongFlowKind) == 16 &&
            static_cast<std::uint32_t>(ProtocolStatus::NotConnected) == 17 &&
            static_cast<std::uint32_t>(ProtocolStatus::LocalWriteClosed) == 18,
        "tunnel protocol statuses changed"
    );
    WGNX_TEST_REQUIRE(
        context,
        static_cast<std::uint32_t>(FlowState::Connecting) == 0 && static_cast<std::uint32_t>(FlowState::Open) == 1 &&
            static_cast<std::uint32_t>(FlowState::Closing) == 2 && static_cast<std::uint32_t>(FlowState::Closed) == 3 &&
            static_cast<std::uint32_t>(FlowTerminalReason::None) == 0 &&
            static_cast<std::uint32_t>(FlowTerminalReason::ClientClosed) == 1 &&
            static_cast<std::uint32_t>(FlowTerminalReason::PeerDeactivated) == 2 &&
            static_cast<std::uint32_t>(FlowTerminalReason::PeerActivationChanged) == 3 &&
            static_cast<std::uint32_t>(FlowTerminalReason::PolicyInvalidated) == 4 &&
            static_cast<std::uint32_t>(FlowTerminalReason::SysmoduleShutdown) == 5,
        "tunnel flow lifecycle categories changed"
    );
    WGNX_TEST_REQUIRE(
        context,
        static_cast<std::uint32_t>(CompletionType::InboundUdpDatagram) == 0 &&
            static_cast<std::uint32_t>(CompletionType::InboundTcpStream) == 1 &&
            static_cast<std::uint32_t>(CompletionType::FlowStateChanged) == 2 &&
            static_cast<std::uint32_t>(CompletionType::PolicyChanged) == 3 && static_cast<std::uint32_t>(CompletionType::Writable) == 4,
        "tunnel completion categories changed"
    );
    WGNX_TEST_REQUIRE(
        context,
        sizeof(FlowHandle) == 8 && sizeof(Ipv4Endpoint) == 8 && sizeof(Capabilities) == 48 && sizeof(OpenConnectedFlowRequest) == 16 &&
            sizeof(OpenConnectedFlowResult) == 24 && sizeof(PayloadRange) == 24 && sizeof(PayloadResult) == 16 &&
            sizeof(CompletionRecord) == 56 && sizeof(CompletionDrainResult) == 8 && sizeof(FlowStateResult) == 48 &&
            sizeof(RoutingPolicySnapshot) == 8 && sizeof(RouteRecord) == 32,
        "tunnel binary record layout changed"
    );

    std::array<std::uint8_t, MaximumUdpPayloadStorageBytes + 1> payload{};
    const std::array<PayloadRange, 5> descriptors = {
        PayloadRange{.flow = {.value = 1}, .payload_offset = 0, .payload_size = 8, .client_tag = 1},
        PayloadRange{
            .flow = {.value = 1},
            .payload_offset = static_cast<std::uint32_t>(payload.size()),
            .payload_size = 1,
            .client_tag = 2
        },
        PayloadRange{
            .flow = {.value = 1},
            .payload_offset = 0,
            .payload_size = static_cast<std::uint32_t>(payload.size()),
            .client_tag = 3
        },
        PayloadRange{.flow = {.value = 2}, .payload_offset = 0, .payload_size = 8, .client_tag = 4},
        PayloadRange{.flow = {.value = 3}, .payload_offset = 0, .payload_size = 8, .client_tag = 5},
    };
    std::array<PayloadResult, descriptors.size()> dispositions{};
    std::uint32_t send_count = 0;
    DispatchUdpDatagramBatch(
        descriptors,
        payload,
        dispositions,
        [&send_count](const PayloadRange& descriptor, std::span<const std::uint8_t>) {
            ++send_count;
            switch (descriptor.flow.value) {
            case 1:
                return descriptor.payload_size > MaximumUdpPayloadStorageBytes ? ProtocolStatus::PayloadTooLarge : ProtocolStatus::Success;
            case 2:
                return ProtocolStatus::StaleHandle;
            case 3:
                return ProtocolStatus::QueueFull;
            default:
                return ProtocolStatus::MalformedInput;
            }
        }
    );
    WGNX_TEST_REQUIRE(
        context,
        dispositions[0].client_tag == 1 && dispositions[0].status == ProtocolStatus::Success && dispositions[1].client_tag == 2 &&
            dispositions[1].status == ProtocolStatus::MalformedInput && dispositions[2].client_tag == 3 &&
            dispositions[2].status == ProtocolStatus::PayloadTooLarge && dispositions[3].client_tag == 4 &&
            dispositions[3].status == ProtocolStatus::StaleHandle && dispositions[4].client_tag == 5 &&
            dispositions[4].status == ProtocolStatus::QueueFull && send_count == 4,
        "batch dispatch did not preserve ordered partial dispositions"
    );

    const std::array<PayloadRange, 4> ordered_descriptors = {
        PayloadRange{.flow = {.value = 9}, .payload_offset = 0, .payload_size = 8, .client_tag = 6},
        PayloadRange{.flow = {.value = 9}, .payload_offset = 8, .payload_size = 8, .client_tag = 7},
        PayloadRange{.flow = {.value = 9}, .payload_offset = 16, .payload_size = 8, .client_tag = 8},
        PayloadRange{.flow = {.value = 9}, .payload_offset = 24, .payload_size = 8, .client_tag = 9},
    };
    std::array<PayloadResult, ordered_descriptors.size()> ordered_dispositions{};
    std::uint32_t remaining_admissions = 2;
    DispatchUdpDatagramBatch(
        ordered_descriptors,
        payload,
        ordered_dispositions,
        [&remaining_admissions](const PayloadRange&, std::span<const std::uint8_t>) {
            if (remaining_admissions != 0) {
                --remaining_admissions;
                return ProtocolStatus::Success;
            }
            return ProtocolStatus::QueueFull;
        }
    );
    WGNX_TEST_REQUIRE(
        context,
        ordered_dispositions[0].status == ProtocolStatus::Success && ordered_dispositions[1].status == ProtocolStatus::Success &&
            ordered_dispositions[2].status == ProtocolStatus::QueueFull && ordered_dispositions[3].status == ProtocolStatus::QueueFull,
        "same-flow batch did not preserve an admitted prefix and queue-full suffix"
    );
}

} // namespace wgnx::test
