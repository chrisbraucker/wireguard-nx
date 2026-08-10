#include "tunnel_flow_worker.hpp"

#include "logger.hpp"
#include "tunnel_discovery_service.hpp"
#include "tunnel_completion_validation.hpp"
#include "tunnel_datagram_receive.hpp"
#include "tunnel_flow_readiness.hpp"
#include "tunnel_flow_submission_state.hpp"
#include "tunnel_open_disposition.hpp"

#include "wgnx/tunnel_client.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

namespace wgnx::mitm {

namespace {

constexpr std::size_t WorkerThreadStackBytes = 24 * 1024;
constexpr std::size_t MaximumInboundDatagramsPerSocket = 4;
constexpr std::size_t MaximumQueuedOutboundDatagrams = 8;
constexpr std::size_t MaximumQueuedOutboundDatagramsPerSocket = 4;
constexpr std::size_t MaximumBatchEntriesPerSubmission = 4;
constexpr std::size_t MaximumQueuedOutboundPayloadBytes = wgnx::tunnel::MaximumUdpPayloadForInnerMtu(1500);
static_assert(MaximumQueuedOutboundDatagramsPerSocket <= MaximumQueuedOutboundDatagrams);
static_assert(MaximumBatchEntriesPerSubmission <= wgnx::tunnel::MaximumBatchEntries);
static_assert(MaximumQueuedOutboundPayloadBytes != 0);
constexpr std::uint32_t RequiredTunnelCapabilities = wgnx::tunnel::CapabilityMask(wgnx::tunnel::Capability::ConnectedIpv4Udp);

struct InboundDatagram {
    bool occupied{};
    std::size_t size{};
    TunnelFlowEndpoint remote{};
    std::array<std::uint8_t, wgnx::tunnel::MaximumUdpPayloadStorageBytes> payload{};
};

struct OutboundDatagram {
    bool occupied{};
    std::size_t size{};
    std::array<std::uint8_t, MaximumQueuedOutboundPayloadBytes> payload{};
};

struct FlowEntry {
    bool occupied{};
    std::uint64_t owner{};
    s32 descriptor{};
    wgnx::tunnel::client::ScopedClient client{};
    Handle completion_handle{INVALID_HANDLE};
    wgnx::tunnel::FlowHandle flow{};
    TunnelFlowEndpoint remote{};
    TunnelFlowSubmissionState submission{};
    std::array<InboundDatagram, MaximumInboundDatagramsPerSocket> inbound{};
    std::array<std::uint8_t, MaximumQueuedOutboundDatagramsPerSocket> outbound_slots{};
    std::uint64_t sends{};
    std::uint64_t adapter_queued{};
    std::uint64_t adapter_queue_full{};
    std::uint64_t send_accepted{};
    std::uint64_t send_queue_full{};
    std::uint64_t send_too_large{};
    std::uint64_t inbound_delivered{};
    std::uint64_t inbound_dropped{};
    std::uint64_t writable_notifications{};
    std::uint64_t batch_submissions{};
    std::uint64_t queued_discarded{};
};

alignas(ams::os::ThreadStackAlignment) constinit std::array<std::byte, WorkerThreadStackBytes> g_worker_stack{};
std::array<FlowEntry, TunnelFlowWorker::MaximumSockets> g_flows{};
std::array<wgnx::tunnel::CompletionRecord, wgnx::tunnel::MaximumBatchEntries> g_completions{};
std::array<std::uint8_t, wgnx::tunnel::MaximumBatchEntries * wgnx::tunnel::MaximumUdpPayloadStorageBytes> g_completion_payload{};
std::array<OutboundDatagram, MaximumQueuedOutboundDatagrams> g_outbound_datagrams{};
std::array<wgnx::tunnel::PayloadRange, MaximumBatchEntriesPerSubmission> g_batch_descriptors{};
std::array<wgnx::tunnel::PayloadResult, MaximumBatchEntriesPerSubmission> g_batch_dispositions{};
std::array<std::uint8_t, MaximumBatchEntriesPerSubmission * MaximumQueuedOutboundPayloadBytes> g_batch_payload{};
std::size_t g_outbound_datagram_count{};

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

void ReleaseQueuedOutbound(FlowEntry& flow, TunnelFlowWorkerMetrics* metrics) {
    const std::size_t queued = flow.submission.queued;
    for (std::size_t index = 0; index < queued; ++index) {
        const std::uint8_t slot = flow.outbound_slots[index];
        AMS_ABORT_UNLESS(slot < g_outbound_datagrams.size() && g_outbound_datagrams[slot].occupied);
        g_outbound_datagrams[slot] = {};
        --g_outbound_datagram_count;
    }
    if (queued != 0) {
        flow.queued_discarded += queued;
        if (metrics != nullptr) {
            metrics->send_discarded += queued;
        }
    }
}

void DiscardQueuedOutbound(FlowEntry& flow, TunnelFlowWorkerMetrics* metrics) {
    const std::size_t queued = flow.submission.queued;
    ReleaseQueuedOutbound(flow, metrics);
    if (queued != 0) {
        flow.submission.Retire(queued);
    }
}

void ResetFlow(FlowEntry& flow, TunnelFlowWorkerMetrics* metrics = nullptr) {
    DiscardQueuedOutbound(flow, metrics);
    if (flow.completion_handle != INVALID_HANDLE) {
        svcCloseHandle(flow.completion_handle);
    }
    flow.client.Close();
    flow = {};
}

void LogFlowSummary(const FlowEntry& flow, const char* reason) {
    if (!flow.occupied) {
        return;
    }
    logger::Log(
        "tunnel flow summary owner=%llu fd=%d reason=%s sends=%llu adapter_queued=%llu adapter_queue_full=%llu "
        "accepted=%llu queue_full=%llu too_large=%llu batches=%llu "
        "queued=%zu discarded=%llu inbound_delivered=%llu inbound_dropped=%llu writable=%llu closed=%u",
        static_cast<unsigned long long>(flow.owner),
        flow.descriptor,
        reason,
        static_cast<unsigned long long>(flow.sends),
        static_cast<unsigned long long>(flow.adapter_queued),
        static_cast<unsigned long long>(flow.adapter_queue_full),
        static_cast<unsigned long long>(flow.send_accepted),
        static_cast<unsigned long long>(flow.send_queue_full),
        static_cast<unsigned long long>(flow.send_too_large),
        static_cast<unsigned long long>(flow.batch_submissions),
        flow.submission.queued,
        static_cast<unsigned long long>(flow.queued_discarded),
        static_cast<unsigned long long>(flow.inbound_delivered),
        static_cast<unsigned long long>(flow.inbound_dropped),
        static_cast<unsigned long long>(flow.writable_notifications),
        flow.submission.closed ? 1U : 0U
    );
}

void ResetAllFlows(const char* reason, TunnelFlowWorkerMetrics* metrics = nullptr) {
    for (FlowEntry& flow : g_flows) {
        if (flow.occupied) {
            LogFlowSummary(flow, reason);
            ResetFlow(flow, metrics);
        }
    }
}

void CloseFlow(FlowEntry& flow, TunnelFlowWorkerMetrics& metrics) {
    if (flow.occupied && !flow.submission.closed && flow.client.IsOpen()) {
        wgnx::tunnel::ProtocolStatus ignored{};
        const Result rc = wgnx::tunnel::client::CloseFlow(flow.client, flow.flow, std::addressof(ignored));
        logger::Log(
            "tunnel flow close owner=%llu fd=%d rc=0x%08X status=%u",
            static_cast<unsigned long long>(flow.owner),
            flow.descriptor,
            rc,
            static_cast<unsigned>(ignored)
        );
    }
    LogFlowSummary(flow, "close");
    ++metrics.flows_closed;
    ResetFlow(flow, std::addressof(metrics));
}

[[nodiscard]] OutboundDatagram* AllocateOutbound() {
    for (OutboundDatagram& datagram : g_outbound_datagrams) {
        if (!datagram.occupied) {
            datagram.occupied = true;
            ++g_outbound_datagram_count;
            return std::addressof(datagram);
        }
    }
    return nullptr;
}

[[nodiscard]] std::uint8_t OutboundSlotIndex(const OutboundDatagram& datagram) {
    const auto index = static_cast<std::size_t>(std::addressof(datagram) - g_outbound_datagrams.data());
    AMS_ABORT_UNLESS(index < g_outbound_datagrams.size());
    return static_cast<std::uint8_t>(index);
}

[[nodiscard]] bool QueueOutbound(FlowEntry& flow, const void* payload, const std::size_t payload_size) {
    if (!flow.submission.CanAccept(MaximumQueuedOutboundDatagramsPerSocket) || g_outbound_datagram_count == g_outbound_datagrams.size()) {
        return false;
    }
    OutboundDatagram* datagram = AllocateOutbound();
    if (datagram == nullptr) {
        return false;
    }
    datagram->size = payload_size;
    std::memcpy(datagram->payload.data(), payload, payload_size);
    flow.outbound_slots[flow.submission.queued] = OutboundSlotIndex(*datagram);
    flow.submission.Enqueue();
    return true;
}

void RetireQueuedOutboundPrefix(FlowEntry& flow, const std::size_t count) {
    AMS_ABORT_UNLESS(count <= flow.submission.queued);
    for (std::size_t index = 0; index < count; ++index) {
        const std::uint8_t slot = flow.outbound_slots[index];
        AMS_ABORT_UNLESS(slot < g_outbound_datagrams.size() && g_outbound_datagrams[slot].occupied);
        g_outbound_datagrams[slot] = {};
        --g_outbound_datagram_count;
    }
    const std::size_t remaining = flow.submission.queued - count;
    for (std::size_t index = 0; index < remaining; ++index) {
        flow.outbound_slots[index] = flow.outbound_slots[index + count];
    }
    flow.submission.Retire(count);
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

void DrainCompletions(FlowEntry& flow, TunnelFlowWorkerMetrics& metrics) {
    if (!flow.client.IsOpen() || flow.submission.closed) {
        return;
    }

    for (;;) {
        ++metrics.completion_drains;
        std::uint32_t count = 0;
        wgnx::tunnel::ProtocolStatus status = wgnx::tunnel::ProtocolStatus::QueueEmpty;
        const Result rc = wgnx::tunnel::client::ReceiveCompletions(
            flow.client,
            g_completions.data(),
            g_completions.size(),
            g_completion_payload.data(),
            g_completion_payload.size(),
            std::addressof(count),
            std::addressof(status)
        );
        if (R_FAILED(rc)) {
            logger::Log(
                "tunnel completion drain CMIF failure owner=%llu fd=%d rc=0x%08X",
                static_cast<unsigned long long>(flow.owner),
                flow.descriptor,
                rc
            );
            flow.submission.Close();
            DiscardQueuedOutbound(flow, std::addressof(metrics));
            GetTunnelDiscoveryService().ReportTunnelClientFailure();
            return;
        }
        if (status == wgnx::tunnel::ProtocolStatus::QueueEmpty) {
            return;
        }
        if (status != wgnx::tunnel::ProtocolStatus::Success) {
            logger::Log(
                "tunnel completion drain rejected owner=%llu fd=%d status=%u",
                static_cast<unsigned long long>(flow.owner),
                flow.descriptor,
                static_cast<unsigned>(status)
            );
            flow.submission.Close();
            DiscardQueuedOutbound(flow, std::addressof(metrics));
            return;
        }
        if (!ValidateTunnelCompletionDrain(count, g_completions.size(), g_completions, g_completion_payload.size())) {
            logger::Log(
                "tunnel completion drain rejected malformed response owner=%llu fd=%d count=%u",
                static_cast<unsigned long long>(flow.owner),
                flow.descriptor,
                count
            );
            flow.submission.Close();
            DiscardQueuedOutbound(flow, std::addressof(metrics));
            GetTunnelDiscoveryService().ReportTunnelClientFailure();
            return;
        }

        metrics.completion_records += count;

        for (std::uint32_t index = 0; index < count; ++index) {
            const wgnx::tunnel::CompletionRecord& completion = g_completions[index];
            if (completion.flow.value != flow.flow.value) {
                logger::Log(
                    "tunnel completion ignored foreign flow owner=%llu fd=%d",
                    static_cast<unsigned long long>(flow.owner),
                    flow.descriptor
                );
                continue;
            }
            if (flow.submission.closed) {
                continue;
            }
            if (completion.type == wgnx::tunnel::CompletionType::FlowStateChanged) {
                if (completion.flow_state == wgnx::tunnel::FlowState::Closed) {
                    flow.submission.Close();
                    DiscardQueuedOutbound(flow, std::addressof(metrics));
                    ++metrics.terminal_flow_notifications;
                }
                continue;
            }
            if (completion.type == wgnx::tunnel::CompletionType::Writable) {
                flow.submission.NoteWritable();
                ++flow.writable_notifications;
                ++metrics.writable_notifications;
                continue;
            }
            if (completion.type != wgnx::tunnel::CompletionType::InboundUdpDatagram || !SameEndpoint(completion.remote, flow.remote)) {
                continue;
            }
            InboundDatagram* datagram = AllocateInbound(flow);
            if (datagram == nullptr) {
                ++flow.inbound_dropped;
                ++metrics.inbound_dropped;
                logger::LogPacket(
                    "tunnel inbound dropped mitm_queue_full owner=%llu fd=%d",
                    static_cast<unsigned long long>(flow.owner),
                    flow.descriptor
                );
                continue;
            }
            datagram->size = completion.payload_size;
            datagram->remote = ToEndpoint(completion.remote);
            std::memcpy(datagram->payload.data(), g_completion_payload.data() + completion.payload_offset, datagram->size);
            ++flow.inbound_delivered;
            ++metrics.inbound_delivered;
        }
    }
}

[[nodiscard]] TunnelFlowResult MapOpenStatus(wgnx::tunnel::ProtocolStatus status) {
    switch (ClassifyTunnelOpenStatus(status)) {
    case TunnelOpenDisposition::Tunnel:
        return TunnelFlowResult::Opened;
    case TunnelOpenDisposition::Direct:
        return status == wgnx::tunnel::ProtocolStatus::RouteNotCovered ? TunnelFlowResult::RouteNotCovered
                                                                       : TunnelFlowResult::TunnelUnavailable;
    case TunnelOpenDisposition::Blocked:
        return TunnelFlowResult::BlockedByPolicy;
    case TunnelOpenDisposition::Error:
        return TunnelFlowResult::SocketError;
    }
    return TunnelFlowResult::SocketError;
}

} // namespace

TunnelFlowWorker::TunnelFlowWorker() = default;

void TunnelFlowWorker::Start() {
    std::scoped_lock lock(m_mutex);
    if (m_started) {
        return;
    }
    m_stop_requested = false;
    m_metrics = {};
    m_maximum_udp_payload_bytes = 0;
    m_stop_event.Clear();
    m_started = true;
    R_ABORT_UNLESS(
        ams::os::CreateThread(
            std::addressof(m_thread),
            ThreadMain,
            this,
            g_worker_stack.data(),
            g_worker_stack.size(),
            ams::os::DefaultThreadPriority
        )
    );
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
    logger::Log(
        "tunnel worker summary operations_enqueued=%llu operations_rejected=%llu operation_queue_high_water=%llu flows_opened=%llu "
        "flows_closed=%llu send_attempts=%llu send_queued=%llu send_accepted=%llu send_queue_full=%llu "
        "send_adapter_queue_full=%llu send_too_large=%llu send_failures=%llu send_discarded=%llu batch_submissions=%llu "
        "completion_drains=%llu completion_records=%llu completion_event_waits=%llu writable_notifications=%llu "
        "inbound_delivered=%llu inbound_dropped=%llu terminal_flow_notifications=%llu",
        static_cast<unsigned long long>(m_metrics.operations_enqueued),
        static_cast<unsigned long long>(m_metrics.operations_rejected),
        static_cast<unsigned long long>(m_metrics.operation_queue_high_water),
        static_cast<unsigned long long>(m_metrics.flows_opened),
        static_cast<unsigned long long>(m_metrics.flows_closed),
        static_cast<unsigned long long>(m_metrics.send_attempts),
        static_cast<unsigned long long>(m_metrics.send_queued),
        static_cast<unsigned long long>(m_metrics.send_accepted),
        static_cast<unsigned long long>(m_metrics.send_queue_full),
        static_cast<unsigned long long>(m_metrics.send_adapter_queue_full),
        static_cast<unsigned long long>(m_metrics.send_too_large),
        static_cast<unsigned long long>(m_metrics.send_failures),
        static_cast<unsigned long long>(m_metrics.send_discarded),
        static_cast<unsigned long long>(m_metrics.batch_submissions),
        static_cast<unsigned long long>(m_metrics.completion_drains),
        static_cast<unsigned long long>(m_metrics.completion_records),
        static_cast<unsigned long long>(m_metrics.completion_event_waits),
        static_cast<unsigned long long>(m_metrics.writable_notifications),
        static_cast<unsigned long long>(m_metrics.inbound_delivered),
        static_cast<unsigned long long>(m_metrics.inbound_dropped),
        static_cast<unsigned long long>(m_metrics.terminal_flow_notifications)
    );
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
        if (!m_started || m_stop_requested) {
            ++m_metrics.operations_rejected;
            return false;
        }
        if (m_operation_count == std::size(m_operations)) {
            operation.result = TunnelFlowResult::QueueFull;
            ++m_metrics.operations_rejected;
            return false;
        }
        m_operations[m_operation_count++] = std::addressof(operation);
        ++m_metrics.operations_enqueued;
        m_metrics.operation_queue_high_water =
            std::max(m_metrics.operation_queue_high_water, static_cast<std::uint64_t>(m_operation_count));
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
        logger::Log(
            "tunnel flow open bypass owner=%llu fd=%d reason=worker_queue_unavailable",
            static_cast<unsigned long long>(owner),
            descriptor
        );
        return TunnelFlowResult::TunnelUnavailable;
    }
    return operation.result;
}

TunnelFlowResult TunnelFlowWorker::Send(std::uint64_t owner, s32 descriptor, const void* payload, std::size_t payload_size) {
    Operation operation{OperationType::Send};
    operation.owner = owner;
    operation.descriptor = descriptor;
    operation.input = payload;
    operation.input_size = payload_size;
    static_cast<void>(EnqueueAndWait(operation));
    return operation.result;
}

TunnelReceiveResult TunnelFlowWorker::Receive(std::uint64_t owner, s32 descriptor, void* payload, std::size_t payload_size) {
    Operation operation{OperationType::Receive};
    operation.owner = owner;
    operation.descriptor = descriptor;
    operation.output = payload;
    operation.output_size = payload_size;
    if (EnqueueAndWait(operation)) {
        return operation.receive;
    }
    return {.result = operation.result};
}

TunnelPollResult TunnelFlowWorker::Poll(std::uint64_t owner, s32 descriptor, short events, std::int32_t timeout_milliseconds) {
    Operation operation{OperationType::Poll};
    operation.owner = owner;
    operation.descriptor = descriptor;
    operation.events = events;
    operation.timeout_milliseconds = timeout_milliseconds;
    static_cast<void>(EnqueueAndWait(operation));
    return {.result = operation.result, .revents = operation.revents};
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
            CompleteAllPendingPolls(TunnelFlowResult::Closed);
            InvalidateTunnelState();
            logger::Log("tunnel flow worker loop exited pending_operations=%zu", pending_count);
            return;
        }
        ProcessControlSignals();
        DrainAllCompletions();
        CompletePendingPolls();

        for (;;) {
            // A previous operation can report a CMIF failure while more BSD
            // work is already queued, so honor invalidation before reuse.
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
            if (Dispatch(*operation)) {
                operation->complete.Signal();
            }
        }

        SubmitQueuedDatagrams();
        CompletePendingPolls();
        WaitForWorkerActivity();
    }
}

void TunnelFlowWorker::DrainAllCompletions() {
    for (FlowEntry& flow : g_flows) {
        if (flow.occupied) {
            DrainCompletions(flow, m_metrics);
        }
    }
}

bool TunnelFlowWorker::HasQueuedOperations() {
    std::scoped_lock lock(m_mutex);
    return m_operation_count != 0;
}

bool TunnelFlowWorker::HasControlSignals() const {
    return m_discovery_requested.load(std::memory_order_acquire) || m_invalidation_requested.load(std::memory_order_acquire);
}

std::int64_t TunnelFlowWorker::NextPollTimeoutNanoseconds() const {
    std::int64_t deadline = -1;
    for (std::size_t index = 0; index < m_pending_poll_count; ++index) {
        const std::int64_t candidate = m_pending_polls[index]->deadline_nanoseconds;
        if (candidate >= 0 && (deadline < 0 || candidate < deadline)) {
            deadline = candidate;
        }
    }
    if (deadline < 0) {
        return -1;
    }
    const std::int64_t now = ams::os::GetSystemTick().ToTimeSpan().GetNanoSeconds();
    return std::max<std::int64_t>(0, deadline - now);
}

void TunnelFlowWorker::WaitForWorkerActivity() {
    m_wake_event.Clear();
    if (HasQueuedOperations() || HasControlSignals()) {
        return;
    }

    std::array<Handle, MaximumSockets + 2> handles{};
    std::size_t handle_count = 0;
    handles[handle_count++] = m_wake_event.GetReadableHandle();
    handles[handle_count++] = m_stop_event.GetReadableHandle();
    for (const FlowEntry& flow : g_flows) {
        if (flow.occupied && flow.completion_handle != INVALID_HANDLE) {
            handles[handle_count++] = flow.completion_handle;
        }
    }

    s32 signaled_index = 0;
    const Result rc = svcWaitSynchronization(std::addressof(signaled_index), handles.data(), handle_count, NextPollTimeoutNanoseconds());
    if (R_SUCCEEDED(rc) && signaled_index >= 2) {
        ++m_metrics.completion_event_waits;
    }
    if (R_FAILED(rc) && !ams::svc::ResultTimedOut::Includes(rc)) {
        logger::Log("tunnel worker activity wait failed rc=0x%08X", rc);
    }
}

void TunnelFlowWorker::SubmitQueuedDatagrams() {
    for (;;) {
        bool made_progress = false;
        for (FlowEntry& flow : g_flows) {
            if (!flow.occupied || !flow.submission.CanSubmit()) {
                continue;
            }

            const std::size_t entry_count = std::min(flow.submission.queued, MaximumBatchEntriesPerSubmission);
            std::size_t payload_size = 0;
            for (std::size_t index = 0; index < entry_count; ++index) {
                const std::uint8_t slot = flow.outbound_slots[index];
                AMS_ABORT_UNLESS(slot < g_outbound_datagrams.size() && g_outbound_datagrams[slot].occupied);
                const OutboundDatagram& datagram = g_outbound_datagrams[slot];
                AMS_ABORT_UNLESS(datagram.size <= g_batch_payload.size() - payload_size);
                g_batch_descriptors[index] = {
                    .flow = flow.flow,
                    .payload_offset = static_cast<std::uint32_t>(payload_size),
                    .payload_size = static_cast<std::uint32_t>(datagram.size),
                    .client_tag = static_cast<std::uint64_t>(flow.descriptor),
                };
                std::memcpy(g_batch_payload.data() + payload_size, datagram.payload.data(), datagram.size);
                payload_size += datagram.size;
            }

            const Result rc = wgnx::tunnel::client::SendUdpDatagramBatch(
                flow.client,
                g_batch_descriptors.data(),
                entry_count,
                g_batch_payload.data(),
                payload_size,
                g_batch_dispositions.data(),
                g_batch_dispositions.size()
            );
            ++flow.batch_submissions;
            ++m_metrics.batch_submissions;
            m_metrics.batch_entries += entry_count;
            if (R_FAILED(rc)) {
                logger::Log(
                    "tunnel batch submission CMIF failure owner=%llu fd=%d entries=%zu rc=0x%08X",
                    static_cast<unsigned long long>(flow.owner),
                    flow.descriptor,
                    entry_count,
                    rc
                );
                flow.submission.Close();
                DiscardQueuedOutbound(flow, std::addressof(m_metrics));
                ++m_metrics.send_failures;
                GetTunnelDiscoveryService().ReportTunnelClientFailure();
                continue;
            }

            std::size_t accepted_count = 0;
            bool queue_full = false;
            bool terminal_failure = false;
            for (std::size_t index = 0; index < entry_count; ++index) {
                const wgnx::tunnel::ProtocolStatus status = g_batch_dispositions[index].status;
                if (status == wgnx::tunnel::ProtocolStatus::Success && !queue_full && !terminal_failure) {
                    ++accepted_count;
                    ++flow.send_accepted;
                    ++m_metrics.send_accepted;
                    continue;
                }
                if (status == wgnx::tunnel::ProtocolStatus::QueueFull && !terminal_failure) {
                    queue_full = true;
                    ++flow.send_queue_full;
                    ++m_metrics.send_queue_full;
                    continue;
                }

                // The batch service processes descriptors in order under one
                // bounded staging lock. A non-prefix disposition would violate
                // per-socket UDP ordering, so close rather than silently reorder.
                logger::Log(
                    "tunnel batch submission rejected owner=%llu fd=%d index=%zu status=%u prefix_rejected=%u",
                    static_cast<unsigned long long>(flow.owner),
                    flow.descriptor,
                    index,
                    static_cast<unsigned>(status),
                    queue_full ? 1U : 0U
                );
                terminal_failure = true;
                ++m_metrics.send_failures;
            }
            if (accepted_count != 0) {
                RetireQueuedOutboundPrefix(flow, accepted_count);
                made_progress = true;
            }
            if (terminal_failure) {
                flow.submission.Close();
                DiscardQueuedOutbound(flow, std::addressof(m_metrics));
                continue;
            }
            if (queue_full) {
                flow.submission.NoteQueueFull();
            }
        }
        if (!made_progress) {
            return;
        }
    }
}

bool TunnelFlowWorker::QueuePendingPoll(Operation& operation) {
    if (m_pending_poll_count == std::size(m_pending_polls)) {
        return false;
    }
    m_pending_polls[m_pending_poll_count++] = std::addressof(operation);
    return true;
}

void TunnelFlowWorker::CompletePendingPolls() {
    const std::int64_t now = ams::os::GetSystemTick().ToTimeSpan().GetNanoSeconds();
    std::size_t retained_count = 0;
    for (std::size_t index = 0; index < m_pending_poll_count; ++index) {
        Operation& operation = *m_pending_polls[index];
        FlowEntry* flow = FindFlow(operation.owner, operation.descriptor);
        if (flow == nullptr || flow->submission.closed) {
            operation.result = TunnelFlowResult::Closed;
            operation.revents = POLLHUP;
            operation.complete.Signal();
            continue;
        }
        const TunnelFlowReadiness readiness{
            .inbound_available = TakeInbound(*flow) != nullptr,
            .outbound_admission_available = flow->submission.CanAccept(MaximumQueuedOutboundDatagramsPerSocket) &&
                                            g_outbound_datagram_count < g_outbound_datagrams.size(),
            .closed = flow->submission.closed
        };
        operation.revents = readiness.Revents(operation.events);
        if (operation.revents != 0) {
            operation.result = TunnelFlowResult::Opened;
            operation.complete.Signal();
            continue;
        }
        if (operation.deadline_nanoseconds >= 0 && now >= operation.deadline_nanoseconds) {
            operation.result = TunnelFlowResult::WouldBlock;
            operation.complete.Signal();
            continue;
        }
        m_pending_polls[retained_count++] = std::addressof(operation);
    }
    m_pending_poll_count = retained_count;
}

void TunnelFlowWorker::CompleteAllPendingPolls(const TunnelFlowResult result) {
    for (std::size_t index = 0; index < m_pending_poll_count; ++index) {
        Operation& operation = *m_pending_polls[index];
        operation.result = result;
        operation.revents = result == TunnelFlowResult::Closed ? POLLHUP : 0;
        operation.complete.Signal();
    }
    m_pending_poll_count = 0;
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
    ResetAllFlows("invalidation", std::addressof(m_metrics));
    m_maximum_udp_payload_bytes = 0;
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
    ResetAllFlows("rediscovery", std::addressof(m_metrics));
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
        logger::Log(
            "tunnel discovery capability failed rc=0x%08X api=%u capabilities=0x%08X",
            capability_rc,
            capabilities.api_version,
            capabilities.capability_mask
        );
        m_root.Close();
        GetTunnelDiscoveryService().CompleteDiscoveryFailure();
        return;
    }

    GetTunnelDiscoveryService().CompleteDiscoverySuccess();
    m_maximum_udp_payload_bytes = std::min<std::size_t>(capabilities.maximum_udp_payload_bytes, MaximumQueuedOutboundPayloadBytes);
    logger::Log(
        "tunnel root ready api=%u capabilities=0x%08X max_payload=%zu",
        capabilities.api_version,
        capabilities.capability_mask,
        m_maximum_udp_payload_bytes
    );
}

bool TunnelFlowWorker::Dispatch(Operation& operation) {
    auto close_matching = [&](std::uint64_t owner, s32 descriptor, bool all_owner) {
        for (FlowEntry& flow : g_flows) {
            if (flow.occupied && flow.owner == owner && (all_owner || flow.descriptor == descriptor)) {
                CloseFlow(flow, m_metrics);
            }
        }
    };

    if (operation.type == OperationType::Close) {
        close_matching(operation.owner, operation.descriptor, false);
        operation.result = TunnelFlowResult::Closed;
        return true;
    }
    if (operation.type == OperationType::CloseOwner) {
        close_matching(operation.owner, 0, true);
        operation.result = TunnelFlowResult::Closed;
        return true;
    }

    FlowEntry* flow = FindFlow(operation.owner, operation.descriptor);
    if (operation.type == OperationType::Open) {
        if (flow != nullptr) {
            operation.result = flow->submission.closed ? TunnelFlowResult::SocketError : TunnelFlowResult::Opened;
            logger::Log(
                "tunnel flow open reused owner=%llu fd=%d closed=%u",
                static_cast<unsigned long long>(operation.owner),
                operation.descriptor,
                flow->submission.closed ? 1U : 0U
            );
            return true;
        }
        if (GetTunnelDiscoveryService().GetState() != TunnelAvailabilityState::Ready) {
            logger::Log(
                "tunnel flow open bypass owner=%llu fd=%d reason=discovery_state state=%u",
                static_cast<unsigned long long>(operation.owner),
                operation.descriptor,
                static_cast<unsigned>(GetTunnelDiscoveryService().GetState())
            );
            operation.result = TunnelFlowResult::TunnelUnavailable;
            return true;
        }
        if (!m_root.IsOpen()) {
            logger::Log(
                "tunnel flow open rejected missing_ready_root owner=%llu fd=%d",
                static_cast<unsigned long long>(operation.owner),
                operation.descriptor
            );
            GetTunnelDiscoveryService().ReportTunnelClientFailure();
            operation.result = TunnelFlowResult::TunnelUnavailable;
            return true;
        }
        flow = AllocateFlow(operation.owner, operation.descriptor);
        if (flow == nullptr) {
            logger::Log(
                "tunnel flow open rejected owner=%llu fd=%d reason=flow_capacity",
                static_cast<unsigned long long>(operation.owner),
                operation.descriptor
            );
            operation.result = TunnelFlowResult::SocketError;
            return true;
        }
        const Result client_rc = wgnx::tunnel::client::OpenTunnelClient(m_root, std::addressof(flow->client));
        if (R_FAILED(client_rc)) {
            logger::Log(
                "tunnel flow open bypass owner=%llu fd=%d reason=client_open rc=0x%08X",
                static_cast<unsigned long long>(operation.owner),
                operation.descriptor,
                static_cast<unsigned>(client_rc)
            );
            ResetFlow(*flow);
            GetTunnelDiscoveryService().ReportTunnelClientFailure();
            operation.result = TunnelFlowResult::TunnelUnavailable;
            return true;
        }
        const wgnx::tunnel::OpenConnectedFlowRequest request{
            .remote =
                {.address =
                     {operation.remote.address[0], operation.remote.address[1], operation.remote.address[2], operation.remote.address[3]},
                 .port = operation.remote.port,
                 .reserved = 0},
            .diagnostic_tag = (operation.owner << 16U) ^ static_cast<std::uint32_t>(operation.descriptor),
        };
        wgnx::tunnel::OpenConnectedFlowResult opened{};
        const Result open_rc = wgnx::tunnel::client::OpenConnectedUdpFlow(flow->client, request, std::addressof(opened));
        if (R_FAILED(open_rc)) {
            logger::Log(
                "tunnel flow open bypass owner=%llu fd=%d reason=open_cmif rc=0x%08X",
                static_cast<unsigned long long>(operation.owner),
                operation.descriptor,
                static_cast<unsigned>(open_rc)
            );
            ResetFlow(*flow);
            GetTunnelDiscoveryService().ReportTunnelClientFailure();
            operation.result = TunnelFlowResult::TunnelUnavailable;
            return true;
        }
        operation.result = MapOpenStatus(opened.status);
        if (operation.result != TunnelFlowResult::Opened) {
            logger::Log(
                "tunnel flow open rejected owner=%llu fd=%d status=%u mapped=%u",
                static_cast<unsigned long long>(operation.owner),
                operation.descriptor,
                static_cast<unsigned>(opened.status),
                static_cast<unsigned>(operation.result)
            );
            ResetFlow(*flow);
            return true;
        }
        flow->flow = opened.flow;
        flow->remote = operation.remote;
        const Result event_rc = wgnx::tunnel::client::GetCompletionEvent(flow->client, std::addressof(flow->completion_handle));
        if (R_FAILED(event_rc)) {
            CloseFlow(*flow, m_metrics);
            GetTunnelDiscoveryService().ReportTunnelClientFailure();
            operation.result = TunnelFlowResult::SocketError;
            return true;
        }
        logger::Log(
            "tunnel flow opened owner=%llu fd=%d remote=%u.%u.%u.%u:%u",
            static_cast<unsigned long long>(flow->owner),
            flow->descriptor,
            flow->remote.address[0],
            flow->remote.address[1],
            flow->remote.address[2],
            flow->remote.address[3],
            flow->remote.port
        );
        ++m_metrics.flows_opened;
        return true;
    }

    if (flow == nullptr || flow->submission.closed) {
        operation.result = TunnelFlowResult::Closed;
        operation.receive.result = TunnelFlowResult::Closed;
        return true;
    }

    if (operation.type == OperationType::Send) {
        ++flow->sends;
        ++m_metrics.send_attempts;
        if (operation.input_size > m_maximum_udp_payload_bytes || operation.input_size > MaximumQueuedOutboundPayloadBytes) {
            operation.result = TunnelFlowResult::MessageTooLarge;
            ++flow->send_too_large;
            ++m_metrics.send_too_large;
            return true;
        }
        if (!QueueOutbound(*flow, operation.input, operation.input_size)) {
            operation.result = TunnelFlowResult::WouldBlock;
            ++flow->adapter_queue_full;
            ++m_metrics.send_adapter_queue_full;
            return true;
        }
        ++flow->adapter_queued;
        ++m_metrics.send_queued;
        operation.result = TunnelFlowResult::Opened;
        return true;
    }

    if (operation.type == OperationType::Poll) {
        const TunnelFlowReadiness readiness{
            .inbound_available = TakeInbound(*flow) != nullptr,
            .outbound_admission_available = flow->submission.CanAccept(MaximumQueuedOutboundDatagramsPerSocket) &&
                                            g_outbound_datagram_count < g_outbound_datagrams.size(),
            .closed = flow->submission.closed
        };
        operation.revents = readiness.Revents(operation.events);
        if (operation.revents != 0) {
            operation.result = TunnelFlowResult::Opened;
            return true;
        }
        if (operation.timeout_milliseconds == 0) {
            operation.result = TunnelFlowResult::WouldBlock;
            return true;
        }
        if (operation.timeout_milliseconds > 0) {
            operation.deadline_nanoseconds = ams::os::GetSystemTick().ToTimeSpan().GetNanoSeconds() +
                                             static_cast<std::int64_t>(operation.timeout_milliseconds) * 1'000'000;
        }
        if (QueuePendingPoll(operation)) {
            return false;
        }
        operation.result = TunnelFlowResult::QueueFull;
        return true;
    }

    if (operation.type == OperationType::Receive) {
        InboundDatagram* datagram = TakeInbound(*flow);
        if (datagram == nullptr) {
            operation.receive.result = flow->submission.closed ? TunnelFlowResult::Closed : TunnelFlowResult::WouldBlock;
            return true;
        }
        const auto received = ReceiveTunneledDatagram(
            std::addressof(datagram->occupied),
            {static_cast<std::uint8_t*>(operation.output), operation.output_size},
            std::span<const std::uint8_t>(datagram->payload.data(), datagram->size)
        );
        operation.receive = {.result = TunnelFlowResult::Opened, .size = received.size, .remote = datagram->remote};
        return true;
    }

    operation.result = TunnelFlowResult::SocketError;
    return true;
}

TunnelFlowWorker& GetTunnelFlowWorker() {
    static TunnelFlowWorker worker;
    return worker;
}

} // namespace wgnx::mitm
