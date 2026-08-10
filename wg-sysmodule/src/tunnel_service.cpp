#include "tunnel_service.hpp"

#include <memory>
#include <span>

#include "wgnx/resource_budget.hpp"
#include "wgnx/tunnel_batch.hpp"

namespace wgnx::sysmodule {

namespace {

constinit ams::sf::UnmanagedServiceObject<ITunnelRoot, TunnelRootService> g_tunnel_root_service_object;

struct TunnelClientAllocatorTag;
using TunnelClientAllocator =
    ams::sf::ExpHeapStaticAllocator<wgnx::resource_budget::TunnelClientServiceAllocatorBytes, TunnelClientAllocatorTag>;
using TunnelClientObjectFactory = ams::sf::ObjectFactory<typename TunnelClientAllocator::Policy>;

class TunnelClientAllocatorInitializer {
  public:
    TunnelClientAllocatorInitializer() {
        TunnelClientAllocator::Initialize(ams::lmem::CreateOption_None);
    }
} g_tunnel_client_allocator_initializer;

} // namespace

TunnelClientService::TunnelClientService() : m_completion_event(ams::os::EventClearMode_ManualClear, true) {}

TunnelClientService::~TunnelClientService() {
    runtime::DestroyTunnelClient(m_client);
}

bool TunnelClientService::Initialize() {
    m_client = runtime::CreateTunnelClient(SignalCompletionEvent, this);
    return m_client.IsValid();
}

ams::Result TunnelClientService::GetCapabilities(ams::sf::Out<wgnx::tunnel::Capabilities> out) {
    out.SetValue(runtime::GetTunnelCapabilities());
    R_SUCCEED();
}

ams::Result TunnelClientService::GetRoutingPolicySnapshot(
    ams::sf::Out<wgnx::tunnel::RoutingPolicySnapshot> out, const ams::sf::OutMapAliasArray<wgnx::tunnel::RouteRecord>& routes
) {
    if (routes.GetSize() > wgnx::tunnel::MaximumPolicyRoutes) {
        R_THROW(ams::fs::ResultInvalidArgument());
    }
    out.SetValue(runtime::CopyTunnelRoutingPolicy({routes.GetPointer(), routes.GetSize()}));
    R_SUCCEED();
}

ams::Result TunnelClientService::GetCompletionEvent(ams::sf::OutCopyHandle out) {
    out.SetValue(m_completion_event.GetReadableHandle(), false);
    R_SUCCEED();
}

ams::Result TunnelClientService::OpenConnectedUdpFlow(
    ams::sf::Out<wgnx::tunnel::OpenConnectedFlowResult> out, const wgnx::tunnel::OpenConnectedFlowRequest& request
) {
    out.SetValue(runtime::OpenTunnelConnectedUdpFlow(m_client, request));
    R_SUCCEED();
}

ams::Result TunnelClientService::SendUdpDatagramBatch(
    const ams::sf::InMapAliasArray<wgnx::tunnel::PayloadRange>& descriptors,
    const ams::sf::InMapAliasBuffer& payload,
    const ams::sf::OutMapAliasArray<wgnx::tunnel::PayloadResult>& dispositions
) {
    if (descriptors.GetSize() > wgnx::tunnel::MaximumBatchEntries || dispositions.GetSize() < descriptors.GetSize()) {
        R_THROW(ams::fs::ResultInvalidArgument());
    }
    const auto* bytes = static_cast<const std::uint8_t*>(payload.GetPointer());
    wgnx::tunnel::DispatchUdpDatagramBatch(
        {descriptors.GetPointer(), descriptors.GetSize()},
        {bytes, payload.GetSize()},
        {dispositions.GetPointer(), dispositions.GetSize()},
        [this](const wgnx::tunnel::PayloadRange& descriptor, std::span<const std::uint8_t> datagram) {
            return runtime::SendTunnelUdpDatagram(m_client, descriptor, datagram);
        }
    );
    R_SUCCEED();
}

ams::Result TunnelClientService::OpenConnectedTcpFlow(
    ams::sf::Out<wgnx::tunnel::OpenConnectedFlowResult> out, const wgnx::tunnel::OpenConnectedFlowRequest& request
) {
    out.SetValue(runtime::OpenTunnelConnectedTcpFlow(m_client, request));
    R_SUCCEED();
}

ams::Result TunnelClientService::WriteTcpStream(
    ams::sf::Out<wgnx::tunnel::PayloadResult> out, const wgnx::tunnel::PayloadRange& range, const ams::sf::InMapAliasBuffer& payload
) {
    if (!IsPayloadRangeValid(range, payload)) {
        out.SetValue({.client_tag = range.client_tag, .status = wgnx::tunnel::ProtocolStatus::MalformedInput, .accepted_bytes = 0});
        R_SUCCEED();
    }
    out.SetValue(
        runtime::WriteTunnelTcpStream(
            m_client,
            range,
            std::span<const std::uint8_t>(static_cast<const std::uint8_t*>(payload.GetPointer()), payload.GetSize())
                .subspan(range.payload_offset, range.payload_size)
        )
    );
    R_SUCCEED();
}

ams::Result TunnelClientService::ShutdownTcpWrite(ams::sf::Out<wgnx::tunnel::ProtocolStatus> out, const wgnx::tunnel::FlowHandle& flow) {
    out.SetValue(runtime::ShutdownTunnelTcpWrite(m_client, flow));
    R_SUCCEED();
}

ams::Result TunnelClientService::ReceiveCompletions(
    ams::sf::Out<u32> out_count,
    ams::sf::Out<wgnx::tunnel::ProtocolStatus> out_status,
    const ams::sf::OutMapAliasArray<wgnx::tunnel::CompletionRecord>& records,
    const ams::sf::OutMapAliasBuffer& payload
) {
    if (records.GetSize() > wgnx::tunnel::MaximumBatchEntries) {
        R_THROW(ams::fs::ResultInvalidArgument());
    }
    const auto outcome = runtime::ReceiveTunnelCompletions(
        m_client,
        {records.GetPointer(), records.GetSize()},
        {static_cast<std::uint8_t*>(payload.GetPointer()), payload.GetSize()},
        ClearCompletionEvent,
        this
    );
    out_count.SetValue(outcome.count);
    out_status.SetValue(outcome.status);
    R_SUCCEED();
}

ams::Result TunnelClientService::GetFlowState(ams::sf::Out<wgnx::tunnel::FlowStateResult> out, const wgnx::tunnel::FlowHandle& flow) {
    out.SetValue(runtime::GetTunnelFlowState(m_client, flow));
    R_SUCCEED();
}

ams::Result TunnelClientService::CloseFlow(ams::sf::Out<wgnx::tunnel::ProtocolStatus> out, const wgnx::tunnel::FlowHandle& flow) {
    out.SetValue(runtime::CloseTunnelFlow(m_client, flow));
    R_SUCCEED();
}

void TunnelClientService::SignalCompletionEvent(void* context) {
    if (context != nullptr) {
        static_cast<TunnelClientService*>(context)->m_completion_event.Signal();
    }
}

void TunnelClientService::ClearCompletionEvent(void* context) {
    if (context != nullptr) {
        static_cast<TunnelClientService*>(context)->m_completion_event.Clear();
    }
}

bool TunnelClientService::IsPayloadRangeValid(
    const wgnx::tunnel::PayloadRange& descriptor, const ams::sf::InMapAliasBuffer& payload
) const {
    const std::size_t offset = descriptor.payload_offset;
    const std::size_t size = descriptor.payload_size;
    return offset <= payload.GetSize() && size <= payload.GetSize() - offset;
}

ams::Result TunnelRootService::GetCapabilities(ams::sf::Out<wgnx::tunnel::Capabilities> out) {
    out.SetValue(runtime::GetTunnelCapabilities());
    R_SUCCEED();
}

ams::Result TunnelRootService::OpenTunnelClient(ams::sf::Out<ams::sf::SharedPointer<ITunnelClient>> out) {
    auto client = TunnelClientObjectFactory::CreateSharedEmplaced<ITunnelClient, TunnelClientService>();
    R_UNLESS(client != nullptr && client.GetImpl().Initialize(), ams::os::ResultOutOfMemory());
    out.SetValue(std::move(client));
    R_SUCCEED();
}

ams::sf::SharedPointer<ITunnelRoot> GetTunnelRootServiceObject() {
    return g_tunnel_root_service_object.GetShared();
}

} // namespace wgnx::sysmodule
