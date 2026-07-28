#include "tunnel_flow_worker.hpp"

#include "logger.hpp"
#include "tunnel_discovery_service.hpp"

#include "wgnx/tunnel_client.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

namespace wgnx::mitm {

namespace {

constexpr std::size_t WorkerThreadStackBytes = 24 * 1024;
constexpr std::size_t MaximumInboundDatagramsPerSocket = 4;
constexpr std::uint32_t RequiredTunnelCapabilities = wgnx::tunnel::CapabilityMask(wgnx::tunnel::Capability::ConnectedIpv4Udp) |
                                                     wgnx::tunnel::CapabilityMask(wgnx::tunnel::Capability::RoutingPolicySnapshot) |
                                                     wgnx::tunnel::CapabilityMask(wgnx::tunnel::Capability::CompletionEvent);

struct InboundDatagram {
    bool occupied{};
    std::size_t size{};
    TunnelFlowEndpoint remote{};
    std::array<std::uint8_t, wgnx::tunnel::MaximumUdpPayloadBytes> payload{};
};

struct FlowEntry {
    bool occupied{};
    std::uint64_t owner{};
    s32 descriptor{};
    wgnx::tunnel::client::ScopedClient client{};
    Handle completion_handle{INVALID_HANDLE};
    wgnx::tunnel::FlowHandle flow{};
    TunnelFlowEndpoint remote{};
    TunnelFlowEndpoint local{};
    bool closed{};
    std::array<InboundDatagram, MaximumInboundDatagramsPerSocket> inbound{};
};

alignas(ams::os::ThreadStackAlignment) constinit std::array<std::byte, WorkerThreadStackBytes> g_worker_stack{};
std::array<FlowEntry, TunnelFlowWorker::MaximumSockets> g_flows{};
std::array<wgnx::tunnel::CompletionRecord, wgnx::tunnel::MaximumBatchEntries> g_completions{};
std::array<std::uint8_t, wgnx::tunnel::MaximumBatchEntries * wgnx::tunnel::MaximumUdpPayloadBytes> g_completion_payload{};

[[nodiscard]] bool SameEndpoint(const wgnx::tunnel::Ipv4Endpoint& endpoint, const TunnelFlowEndpoint& value) {
    return endpoint.port == value.port && std::memcmp(endpoint.address, value.address, sizeof(value.address)) == 0;
}

[[nodiscard]] TunnelFlowEndpoint ToEndpoint(const wgnx::tunnel::Ipv4Endpoint& value) {
    TunnelFlowEndpoint endpoint{};
    std::memcpy(endpoint.address, value.address, sizeof(endpoint.address));
    endpoint.port = value.port;
    return endpoint;
}

[[nodiscard]] FlowEntry* FindFlow(std::uint64_t owner, s32 descriptor) {
    for (FlowEntry& flow : g_flows) {
        if (flow.occupied && flow.owner == owner && flow.descriptor == descriptor) {
            return std::addressof(flow);
        }
    }
    return nullptr;
}

[[nodiscard]] FlowEntry* AllocateFlow(std::uint64_t owner, s32 descriptor) {
    if (FlowEntry* existing = FindFlow(owner, descriptor); existing != nullptr) {
        return existing;
    }
    for (FlowEntry& flow : g_flows) {
        if (!flow.occupied) {
            flow.occupied = true;
            flow.owner = owner;
            flow.descriptor = descriptor;
            return std::addressof(flow);
        }
    }
    return nullptr;
}

void ResetFlow(FlowEntry& flow) {
    if (flow.completion_handle != INVALID_HANDLE) {
        svcCloseHandle(flow.completion_handle);
    }
    flow.client.Close();
    flow = {};
}

void ResetAllFlows() {
    for (FlowEntry& flow : g_flows) {
        if (flow.occupied) {
            ResetFlow(flow);
        }
    }
}

void CloseFlow(FlowEntry& flow) {
    if (flow.occupied && !flow.closed && flow.client.IsOpen()) {
        wgnx::tunnel::ProtocolStatus ignored{};
        const Result rc = wgnx::tunnel::client::CloseFlow(flow.client, flow.flow, std::addressof(ignored));
        logger::Log("tunnel flow close owner=%llu fd=%d rc=0x%08X status=%u", static_cast<unsigned long long>(flow.owner), flow.descriptor,
                    rc, static_cast<unsigned>(ignored));
    }
    ResetFlow(flow);
}

[[nodiscard]] InboundDatagram* AllocateInbound(FlowEntry& flow) {
    for (InboundDatagram& datagram : flow.inbound) {
        if (!datagram.occupied) {
            datagram.occupied = true;
            return std::addressof(datagram);
        }
    }
    return nullptr;
}

[[nodiscard]] InboundDatagram* TakeInbound(FlowEntry& flow) {
    for (InboundDatagram& datagram : flow.inbound) {
        if (datagram.occupied) {
            return std::addressof(datagram);
        }
    }
    return nullptr;
}

void DrainCompletions(FlowEntry& flow) {
    if (!flow.client.IsOpen() || flow.closed) {
        return;
    }

    for (;;) {
        std::uint32_t count = 0;
        wgnx::tunnel::ProtocolStatus status = wgnx::tunnel::ProtocolStatus::QueueEmpty;
        const Result rc =
            wgnx::tunnel::client::ReceiveCompletions(flow.client, g_completions.data(), g_completions.size(), g_completion_payload.data(),
                                                     g_completion_payload.size(), std::addressof(count), std::addressof(status));
        if (R_FAILED(rc)) {
            logger::Log("tunnel completion drain CMIF failure owner=%llu fd=%d rc=0x%08X", static_cast<unsigned long long>(flow.owner),
                        flow.descriptor, rc);
            flow.closed = true;
            GetTunnelDiscoveryService().ReportTunnelClientFailure();
            return;
        }
        if (status == wgnx::tunnel::ProtocolStatus::QueueEmpty) {
            return;
        }
        if (status != wgnx::tunnel::ProtocolStatus::Success) {
            logger::Log("tunnel completion drain rejected owner=%llu fd=%d status=%u", static_cast<unsigned long long>(flow.owner),
                        flow.descriptor, static_cast<unsigned>(status));
            flow.closed = true;
            return;
        }

        for (std::uint32_t index = 0; index < count; ++index) {
            const wgnx::tunnel::CompletionRecord& completion = g_completions[index];
            if (completion.flow.value != flow.flow.value) {
                logger::Log("tunnel completion ignored foreign flow owner=%llu fd=%d", static_cast<unsigned long long>(flow.owner),
                            flow.descriptor);
                continue;
            }
            if (completion.type == wgnx::tunnel::CompletionType::FlowStateChanged) {
                flow.closed = completion.flow_state == wgnx::tunnel::FlowState::Closed;
                continue;
            }
            if (completion.type != wgnx::tunnel::CompletionType::InboundDatagram ||
                completion.payload_offset > g_completion_payload.size() ||
                completion.payload_size > g_completion_payload.size() - completion.payload_offset ||
                !SameEndpoint(completion.remote, flow.remote)) {
                continue;
            }
            InboundDatagram* datagram = AllocateInbound(flow);
            if (datagram == nullptr) {
                logger::Log("tunnel inbound dropped mitm_queue_full owner=%llu fd=%d", static_cast<unsigned long long>(flow.owner),
                            flow.descriptor);
                continue;
            }
            datagram->size = completion.payload_size;
            datagram->remote = ToEndpoint(completion.remote);
            std::memcpy(datagram->payload.data(), g_completion_payload.data() + completion.payload_offset, datagram->size);
        }
    }
}

[[nodiscard]] bool WaitForCompletion(FlowEntry& flow, const Handle stop_handle, std::int32_t timeout_milliseconds) {
    if (flow.completion_handle == INVALID_HANDLE || timeout_milliseconds == 0) {
        return false;
    }
    const std::int64_t timeout_nanoseconds = timeout_milliseconds < 0 ? -1 : static_cast<std::int64_t>(timeout_milliseconds) * 1'000'000;
    const Handle handles[] = {flow.completion_handle, stop_handle};
    s32 index = 0;
    const Result rc = svcWaitSynchronization(std::addressof(index), handles, std::size(handles), timeout_nanoseconds);
    return R_SUCCEEDED(rc) && index == 0;
}

[[nodiscard]] TunnelFlowResult MapOpenStatus(wgnx::tunnel::ProtocolStatus status) {
    switch (status) {
    case wgnx::tunnel::ProtocolStatus::Success:
        return TunnelFlowResult::Opened;
    case wgnx::tunnel::ProtocolStatus::RouteNotCovered:
    case wgnx::tunnel::ProtocolStatus::PeerUnavailable:
    case wgnx::tunnel::ProtocolStatus::TransportUnavailable:
        return TunnelFlowResult::Bypass;
    default:
        return TunnelFlowResult::SocketError;
    }
}

} // namespace

TunnelFlowWorker::TunnelFlowWorker() = default;

void TunnelFlowWorker::Start() {
    std::scoped_lock lock(m_mutex);
    if (m_started) {
        return;
    }
    m_stop_requested = false;
    m_stop_event.Clear();
    m_started = true;
    R_ABORT_UNLESS(ams::os::CreateThread(std::addressof(m_thread), ThreadMain, this, g_worker_stack.data(), g_worker_stack.size(),
                                         ams::os::DefaultThreadPriority));
    ams::os::SetThreadNamePointer(std::addressof(m_thread), "wgnx-tun-flow");
    ams::os::StartThread(std::addressof(m_thread));
    logger::Log("tunnel flow worker started");
}

void TunnelFlowWorker::Stop() {
    {
        std::scoped_lock lock(m_mutex);
        if (!m_started) {
            logger::Log("tunnel flow worker shutdown skipped state=not_started");
            return;
        }
        m_stop_requested = true;
    }

    logger::Log("tunnel flow worker shutdown requested");
    m_stop_event.Signal();
    m_wake_event.Signal();
    ams::os::WaitThread(std::addressof(m_thread));
    ams::os::DestroyThread(std::addressof(m_thread));
    {
        std::scoped_lock lock(m_mutex);
        m_started = false;
    }
    logger::Log("tunnel flow worker shutdown complete");
}

void TunnelFlowWorker::RequestDiscoveryAttempt() {
    {
        std::scoped_lock lock(m_mutex);
        if (!m_started) {
            return;
        }
        m_discovery_requested.store(true, std::memory_order_release);
    }
    m_wake_event.Signal();
}

void TunnelFlowWorker::RequestTunnelInvalidation() {
    {
        std::scoped_lock lock(m_mutex);
        if (!m_started) {
            return;
        }
        m_invalidation_requested.store(true, std::memory_order_release);
    }
    m_wake_event.Signal();
}

bool TunnelFlowWorker::EnqueueAndWait(Operation& operation) {
    {
        std::scoped_lock lock(m_mutex);
        if (!m_started || m_stop_requested || m_operation_count == std::size(m_operations)) {
            return false;
        }
        m_operations[m_operation_count++] = std::addressof(operation);
    }
    m_wake_event.Signal();
    operation.complete.Wait();
    return true;
}

TunnelFlowResult TunnelFlowWorker::OpenConnectedUdp(std::uint64_t owner, s32 descriptor, const TunnelFlowEndpoint& remote) {
    Operation operation{OperationType::Open};
    operation.owner = owner;
    operation.descriptor = descriptor;
    operation.remote = remote;
    if (!EnqueueAndWait(operation)) {
        logger::Log("tunnel flow open bypass owner=%llu fd=%d reason=worker_queue_unavailable", static_cast<unsigned long long>(owner),
                    descriptor);
        return TunnelFlowResult::Bypass;
    }
    return operation.result;
}

TunnelFlowResult TunnelFlowWorker::Send(std::uint64_t owner, s32 descriptor, const void* payload, std::size_t payload_size) {
    Operation operation{OperationType::Send};
    operation.owner = owner;
    operation.descriptor = descriptor;
    operation.input = payload;
    operation.input_size = payload_size;
    return EnqueueAndWait(operation) ? operation.result : TunnelFlowResult::SocketError;
}

TunnelReceiveResult TunnelFlowWorker::Receive(std::uint64_t owner, s32 descriptor, void* payload, std::size_t payload_size) {
    Operation operation{OperationType::Receive};
    operation.owner = owner;
    operation.descriptor = descriptor;
    operation.output = payload;
    operation.output_size = payload_size;
    return EnqueueAndWait(operation) ? operation.receive : TunnelReceiveResult{.result = TunnelFlowResult::SocketError};
}

TunnelFlowResult TunnelFlowWorker::Poll(std::uint64_t owner, s32 descriptor, std::int32_t timeout_milliseconds) {
    Operation operation{OperationType::Poll};
    operation.owner = owner;
    operation.descriptor = descriptor;
    operation.timeout_milliseconds = timeout_milliseconds;
    return EnqueueAndWait(operation) ? operation.result : TunnelFlowResult::SocketError;
}

bool TunnelFlowWorker::GetEndpoints(std::uint64_t owner, s32 descriptor, TunnelFlowEndpoint* out_remote, TunnelFlowEndpoint* out_local) {
    Operation operation{OperationType::GetEndpoints};
    operation.owner = owner;
    operation.descriptor = descriptor;
    if (!EnqueueAndWait(operation) || !operation.endpoints_available) {
        return false;
    }
    if (out_remote != nullptr) {
        *out_remote = operation.remote;
    }
    if (out_local != nullptr) {
        *out_local = operation.local;
    }
    return true;
}

void TunnelFlowWorker::Close(std::uint64_t owner, s32 descriptor) {
    Operation operation{OperationType::Close};
    operation.owner = owner;
    operation.descriptor = descriptor;
    static_cast<void>(EnqueueAndWait(operation));
}

void TunnelFlowWorker::CloseOwner(std::uint64_t owner) {
    Operation operation{OperationType::CloseOwner};
    operation.owner = owner;
    static_cast<void>(EnqueueAndWait(operation));
}

void TunnelFlowWorker::ThreadMain(void* argument) {
    static_cast<TunnelFlowWorker*>(argument)->Run();
}

void TunnelFlowWorker::Run() {
    for (;;) {
        m_wake_event.Wait();
        m_wake_event.Clear();
        if (IsStopRequested()) {
            Operation* pending[MaximumSockets]{};
            std::size_t pending_count = 0;
            {
                std::scoped_lock lock(m_mutex);
                pending_count = m_operation_count;
                for (std::size_t index = 0; index < pending_count; ++index) {
                    pending[index] = m_operations[index];
                }
                m_operation_count = 0;
            }
            for (std::size_t index = 0; index < pending_count; ++index) {
                pending[index]->result = TunnelFlowResult::Closed;
                pending[index]->receive.result = TunnelFlowResult::Closed;
                pending[index]->complete.Signal();
            }
            InvalidateTunnelState();
            logger::Log("tunnel flow worker loop exited pending_operations=%zu", pending_count);
            return;
        }
        ProcessControlSignals();
        for (;;) {
            // A previous operation can report a CMIF failure while more BSD
            // work is already queued, so honor the invalidation before reuse.
            ProcessControlSignals();
            Operation* operation = nullptr;
            {
                std::scoped_lock lock(m_mutex);
                if (m_operation_count == 0) {
                    break;
                }
                operation = m_operations[0];
                for (std::size_t index = 1; index < m_operation_count; ++index) {
                    m_operations[index - 1] = m_operations[index];
                }
                --m_operation_count;
            }
            Dispatch(*operation);
            operation->complete.Signal();
        }
    }
}

bool TunnelFlowWorker::IsStopRequested() {
    std::scoped_lock lock(m_mutex);
    return m_stop_requested;
}

void TunnelFlowWorker::ProcessControlSignals() {
    if (m_invalidation_requested.exchange(false, std::memory_order_acq_rel)) {
        InvalidateTunnelState();
    }
    if (m_discovery_requested.exchange(false, std::memory_order_acq_rel)) {
        DiscoverTunnelService();
    }
}

void TunnelFlowWorker::InvalidateTunnelState() {
    std::size_t released_flows = 0;
    for (const FlowEntry& flow : g_flows) {
        released_flows += flow.occupied ? 1U : 0U;
    }
    ResetAllFlows();
    const bool root_was_open = m_root.IsOpen();
    m_root.Close();
    logger::Log("tunnel worker invalidated root_open=%u released_flows=%zu", root_was_open ? 1U : 0U, released_flows);
}

void TunnelFlowWorker::DiscoverTunnelService() {
    if (GetTunnelDiscoveryService().GetState() != TunnelAvailabilityState::DiscoveryPending) {
        logger::Log("tunnel discovery signal ignored state=%u", static_cast<unsigned>(GetTunnelDiscoveryService().GetState()));
        return;
    }

    // This worker owns every raw SM request and all tunnel CMIF handles.
    // A pending discovery cannot coexist with live routed flows.
    ResetAllFlows();
    m_root.Close();

    bool service_present = false;
    const ams::Result presence_result = ams::sm::HasService(std::addressof(service_present), ams::sm::ServiceName::Encode("wgnx:tun"));
    if (R_FAILED(presence_result) || !service_present) {
        logger::Log("tunnel discovery presence failed rc=0x%08X present=%u", presence_result.GetValue(), service_present ? 1U : 0U);
        GetTunnelDiscoveryService().CompleteDiscoveryFailure();
        return;
    }

    const Result root_rc = m_root.Open();
    if (R_FAILED(root_rc)) {
        logger::Log("tunnel discovery root open failed rc=0x%08X", root_rc);
        GetTunnelDiscoveryService().CompleteDiscoveryFailure();
        return;
    }

    wgnx::tunnel::Capabilities capabilities{};
    const Result capability_rc = wgnx::tunnel::client::GetTunCapabilities(m_root, std::addressof(capabilities));
    const bool compatible = R_SUCCEEDED(capability_rc) && capabilities.api_version == wgnx::tunnel::TunApiVersion &&
                            (capabilities.capability_mask & RequiredTunnelCapabilities) == RequiredTunnelCapabilities;
    if (!compatible) {
        logger::Log("tunnel discovery capability failed rc=0x%08X api=%u capabilities=0x%08X", capability_rc, capabilities.api_version,
                    capabilities.capability_mask);
        m_root.Close();
        GetTunnelDiscoveryService().CompleteDiscoveryFailure();
        return;
    }

    GetTunnelDiscoveryService().CompleteDiscoverySuccess();
    logger::Log("tunnel root ready api=%u capabilities=0x%08X", capabilities.api_version, capabilities.capability_mask);
}

void TunnelFlowWorker::Dispatch(Operation& operation) {
    auto close_matching = [&](std::uint64_t owner, s32 descriptor, bool all_owner) {
        for (FlowEntry& flow : g_flows) {
            if (flow.occupied && flow.owner == owner && (all_owner || flow.descriptor == descriptor)) {
                CloseFlow(flow);
            }
        }
    };

    if (operation.type == OperationType::Close) {
        close_matching(operation.owner, operation.descriptor, false);
        operation.result = TunnelFlowResult::Closed;
        return;
    }
    if (operation.type == OperationType::CloseOwner) {
        close_matching(operation.owner, 0, true);
        operation.result = TunnelFlowResult::Closed;
        return;
    }

    FlowEntry* flow = FindFlow(operation.owner, operation.descriptor);
    if (operation.type == OperationType::Open) {
        if (flow != nullptr) {
            operation.result = flow->closed ? TunnelFlowResult::SocketError : TunnelFlowResult::Opened;
            logger::Log("tunnel flow open reused owner=%llu fd=%d closed=%u", static_cast<unsigned long long>(operation.owner),
                        operation.descriptor, flow->closed ? 1U : 0U);
            return;
        }
        if (GetTunnelDiscoveryService().GetState() != TunnelAvailabilityState::Ready) {
            logger::Log("tunnel flow open bypass owner=%llu fd=%d reason=discovery_state state=%u",
                        static_cast<unsigned long long>(operation.owner), operation.descriptor,
                        static_cast<unsigned>(GetTunnelDiscoveryService().GetState()));
            operation.result = TunnelFlowResult::Bypass;
            return;
        }
        if (!m_root.IsOpen()) {
            logger::Log("tunnel flow open rejected missing_ready_root owner=%llu fd=%d", static_cast<unsigned long long>(operation.owner),
                        operation.descriptor);
            GetTunnelDiscoveryService().ReportTunnelClientFailure();
            operation.result = TunnelFlowResult::Bypass;
            return;
        }
        flow = AllocateFlow(operation.owner, operation.descriptor);
        if (flow == nullptr) {
            logger::Log("tunnel flow open rejected owner=%llu fd=%d reason=flow_capacity", static_cast<unsigned long long>(operation.owner),
                        operation.descriptor);
            operation.result = TunnelFlowResult::SocketError;
            return;
        }
        const Result client_rc = wgnx::tunnel::client::OpenTunnelClient(m_root, std::addressof(flow->client));
        if (R_FAILED(client_rc)) {
            logger::Log("tunnel flow open bypass owner=%llu fd=%d reason=client_open rc=0x%08X",
                        static_cast<unsigned long long>(operation.owner), operation.descriptor, static_cast<unsigned>(client_rc));
            ResetFlow(*flow);
            GetTunnelDiscoveryService().ReportTunnelClientFailure();
            operation.result = TunnelFlowResult::Bypass;
            return;
        }
        const wgnx::tunnel::OpenConnectedUdpFlowRequest request{
            .remote = {.address = {operation.remote.address[0], operation.remote.address[1], operation.remote.address[2],
                                   operation.remote.address[3]},
                       .port = operation.remote.port,
                       .reserved = 0},
            .diagnostic_tag = (operation.owner << 16U) ^ static_cast<std::uint32_t>(operation.descriptor),
        };
        wgnx::tunnel::OpenConnectedUdpFlowResult opened{};
        const Result open_rc = wgnx::tunnel::client::OpenConnectedUdpFlow(flow->client, request, std::addressof(opened));
        if (R_FAILED(open_rc)) {
            logger::Log("tunnel flow open bypass owner=%llu fd=%d reason=open_cmif rc=0x%08X",
                        static_cast<unsigned long long>(operation.owner), operation.descriptor, static_cast<unsigned>(open_rc));
            ResetFlow(*flow);
            GetTunnelDiscoveryService().ReportTunnelClientFailure();
            operation.result = TunnelFlowResult::Bypass;
            return;
        }
        operation.result = MapOpenStatus(opened.status);
        if (operation.result != TunnelFlowResult::Opened) {
            logger::Log("tunnel flow open rejected owner=%llu fd=%d status=%u mapped=%u", static_cast<unsigned long long>(operation.owner),
                        operation.descriptor, static_cast<unsigned>(opened.status), static_cast<unsigned>(operation.result));
            ResetFlow(*flow);
            return;
        }
        flow->flow = opened.flow;
        flow->remote = operation.remote;
        const Result event_rc = wgnx::tunnel::client::GetCompletionEvent(flow->client, std::addressof(flow->completion_handle));
        if (R_FAILED(event_rc)) {
            CloseFlow(*flow);
            GetTunnelDiscoveryService().ReportTunnelClientFailure();
            operation.result = TunnelFlowResult::SocketError;
            return;
        }
        wgnx::tunnel::FlowStateResult state{};
        if (R_SUCCEEDED(wgnx::tunnel::client::GetFlowState(flow->client, flow->flow, std::addressof(state))) &&
            state.status == wgnx::tunnel::ProtocolStatus::Success) {
            flow->local = ToEndpoint(state.advertised_local);
        }
        logger::Log("tunnel flow opened owner=%llu fd=%d remote=%u.%u.%u.%u:%u", static_cast<unsigned long long>(flow->owner),
                    flow->descriptor, flow->remote.address[0], flow->remote.address[1], flow->remote.address[2], flow->remote.address[3],
                    flow->remote.port);
        return;
    }

    if (flow == nullptr || flow->closed) {
        operation.result = TunnelFlowResult::Closed;
        operation.receive.result = TunnelFlowResult::Closed;
        return;
    }

    if (operation.type == OperationType::Send) {
        if (operation.input_size > wgnx::tunnel::MaximumUdpPayloadBytes) {
            operation.result = TunnelFlowResult::MessageTooLarge;
            return;
        }
        const wgnx::tunnel::DatagramDescriptor descriptor{
            .flow = flow->flow,
            .payload_offset = 0,
            .payload_size = static_cast<std::uint32_t>(operation.input_size),
            .client_tag = static_cast<std::uint64_t>(operation.descriptor),
        };
        wgnx::tunnel::DatagramDisposition disposition{};
        const Result send_rc = wgnx::tunnel::client::SendUdpDatagram(flow->client, descriptor, operation.input, operation.input_size,
                                                                     std::addressof(disposition));
        if (R_FAILED(send_rc)) {
            flow->closed = true;
            GetTunnelDiscoveryService().ReportTunnelClientFailure();
            operation.result = TunnelFlowResult::SocketError;
            return;
        }
        operation.result = disposition.status == wgnx::tunnel::ProtocolStatus::Success
                               ? TunnelFlowResult::Opened
                               : (disposition.status == wgnx::tunnel::ProtocolStatus::QueueFull ? TunnelFlowResult::WouldBlock
                                                                                                : TunnelFlowResult::SocketError);
        return;
    }

    if (operation.type == OperationType::Poll) {
        DrainCompletions(*flow);
        if (TakeInbound(*flow) == nullptr && !flow->closed) {
            static_cast<void>(WaitForCompletion(*flow, m_stop_event.GetReadableHandle(), operation.timeout_milliseconds));
            if (IsStopRequested()) {
                operation.result = TunnelFlowResult::Closed;
                return;
            }
            DrainCompletions(*flow);
        }
        operation.result = flow->closed ? TunnelFlowResult::Closed
                                        : (TakeInbound(*flow) != nullptr ? TunnelFlowResult::Opened : TunnelFlowResult::WouldBlock);
        return;
    }

    if (operation.type == OperationType::Receive) {
        DrainCompletions(*flow);
        InboundDatagram* datagram = TakeInbound(*flow);
        if (datagram == nullptr) {
            operation.receive.result = flow->closed ? TunnelFlowResult::Closed : TunnelFlowResult::WouldBlock;
            return;
        }
        if (operation.output_size < datagram->size) {
            operation.receive.result = TunnelFlowResult::SocketError;
            return;
        }
        std::memcpy(operation.output, datagram->payload.data(), datagram->size);
        operation.receive = {.result = TunnelFlowResult::Opened, .size = datagram->size, .remote = datagram->remote};
        datagram->occupied = false;
        return;
    }

    if (operation.type == OperationType::GetEndpoints) {
        operation.remote = flow->remote;
        operation.local = flow->local;
        operation.endpoints_available = true;
    }
}

TunnelFlowWorker& GetTunnelFlowWorker() {
    static TunnelFlowWorker worker;
    return worker;
}

} // namespace wgnx::mitm
