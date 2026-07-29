#pragma once

#include "wgnx/tunnel_client.hpp"
#include "wgnx/tunnel_protocol.hpp"

#include <stratosphere.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace wgnx::mitm {

enum class TunnelFlowResult : std::uint8_t {
    Opened,
    RouteNotCovered,
    TunnelUnavailable,
    BlockedByPolicy,
    SocketError,
    MessageTooLarge,
    WouldBlock,
    Closed,
};

struct TunnelFlowEndpoint {
    std::uint8_t address[4]{};
    std::uint16_t port{};
};

struct TunnelReceiveResult {
    TunnelFlowResult result{TunnelFlowResult::WouldBlock};
    std::size_t size{};
    TunnelFlowEndpoint remote{};
};

struct TunnelPollResult {
    TunnelFlowResult result{TunnelFlowResult::WouldBlock};
    short revents{};
};

struct TunnelFlowWorkerMetrics {
    std::uint64_t operations_enqueued{};
    std::uint64_t operations_rejected{};
    std::uint64_t operation_queue_high_water{};
    std::uint64_t flows_opened{};
    std::uint64_t flows_closed{};
    std::uint64_t send_attempts{};
    std::uint64_t send_queued{};
    std::uint64_t send_accepted{};
    std::uint64_t send_queue_full{};
    std::uint64_t send_adapter_queue_full{};
    std::uint64_t send_too_large{};
    std::uint64_t send_failures{};
    std::uint64_t send_discarded{};
    std::uint64_t batch_submissions{};
    std::uint64_t batch_entries{};
    std::uint64_t completion_drains{};
    std::uint64_t completion_records{};
    std::uint64_t completion_event_waits{};
    std::uint64_t writable_notifications{};
    std::uint64_t inbound_delivered{};
    std::uint64_t inbound_dropped{};
    std::uint64_t terminal_flow_notifications{};
};

class TunnelFlowWorker {
  public:
    static constexpr std::size_t MaximumSockets = 4;

    TunnelFlowWorker();

    TunnelFlowWorker(const TunnelFlowWorker&) = delete;
    TunnelFlowWorker& operator=(const TunnelFlowWorker&) = delete;

    void Start();
    void Stop();
    // Discovery and invalidation are coalesced worker-local control signals.
    // They never carry caller-owned storage into the asynchronous work loop.
    void RequestDiscoveryAttempt();
    void RequestTunnelInvalidation();
    TunnelFlowResult OpenConnectedUdp(std::uint64_t owner, s32 descriptor, const TunnelFlowEndpoint& remote);
    TunnelFlowResult Send(std::uint64_t owner, s32 descriptor, const void* payload, std::size_t payload_size);
    TunnelReceiveResult Receive(std::uint64_t owner, s32 descriptor, void* payload, std::size_t payload_size);
    TunnelPollResult Poll(std::uint64_t owner, s32 descriptor, short events, std::int32_t timeout_milliseconds);
    void Close(std::uint64_t owner, s32 descriptor);
    void CloseOwner(std::uint64_t owner);

  private:
    enum class OperationType : std::uint8_t {
        Open,
        Send,
        Receive,
        Poll,
        Close,
        CloseOwner,
    };

    struct Operation {
        explicit Operation(OperationType operation_type) : type(operation_type), complete(ams::os::EventClearMode_AutoClear) {}

        OperationType type;
        std::uint64_t owner{};
        s32 descriptor{};
        TunnelFlowEndpoint remote{};
        const void* input{};
        std::size_t input_size{};
        void* output{};
        std::size_t output_size{};
        short events{};
        short revents{};
        std::int32_t timeout_milliseconds{};
        std::int64_t deadline_nanoseconds{-1};
        TunnelFlowResult result{TunnelFlowResult::SocketError};
        TunnelReceiveResult receive{};
        ams::os::Event complete;
    };

    static void ThreadMain(void* argument);
    void Run();
    [[nodiscard]] bool Dispatch(Operation& operation);
    void DrainAllCompletions();
    void SubmitQueuedDatagrams();
    void CompletePendingPolls();
    void CompleteAllPendingPolls(TunnelFlowResult result);
    [[nodiscard]] bool QueuePendingPoll(Operation& operation);
    [[nodiscard]] bool HasQueuedOperations();
    [[nodiscard]] bool HasControlSignals() const;
    [[nodiscard]] std::int64_t NextPollTimeoutNanoseconds() const;
    void WaitForWorkerActivity();
    void ProcessControlSignals();
    void InvalidateTunnelState();
    void DiscoverTunnelService();
    bool EnqueueAndWait(Operation& operation);
    [[nodiscard]] bool IsStopRequested();

    ams::os::Mutex m_mutex{false};
    ams::os::SystemEvent m_wake_event{ams::os::EventClearMode_ManualClear, true};
    ams::os::SystemEvent m_stop_event{ams::os::EventClearMode_ManualClear, true};
    ams::os::ThreadType m_thread{};
    wgnx::tunnel::client::ScopedRootService m_root{};
    std::atomic_bool m_discovery_requested{false};
    std::atomic_bool m_invalidation_requested{false};
    Operation* m_operations[MaximumSockets]{};
    std::size_t m_operation_count{};
    Operation* m_pending_polls[MaximumSockets]{};
    std::size_t m_pending_poll_count{};
    std::size_t m_maximum_udp_payload_bytes{};
    bool m_started{};
    bool m_stop_requested{};
    TunnelFlowWorkerMetrics m_metrics{};
};

TunnelFlowWorker& GetTunnelFlowWorker();

} // namespace wgnx::mitm
