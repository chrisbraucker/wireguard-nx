#include "runtime/encrypted_receive_pump.hpp"

#include "runtime/horizon_dispatcher.hpp"
#include "runtime/runtime_effect_executor.hpp"

#include "logger.hpp"
#include "wgnx/platform/clock.hpp"
#include "wgnx/platform/udp.hpp"
#include "wireguard/timers.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <memory>
#include <mutex>
#include <span>

namespace wgnx::sysmodule::runtime {

namespace {

wgnx::platform::ktime_t GetRuntimeNowNs() {
    return wgnx::platform::ktime_get_coarse_boottime_ns();
}

void FormatEndpointText(
    const wgnx::platform::endpoint &endpoint,
    std::span<char> out_text) {
    if (out_text.empty()) {
        return;
    }
    if (!wgnx::platform::endpoint_to_string(endpoint, out_text)) {
        std::snprintf(out_text.data(), out_text.size(), "<invalid>");
    }
}

} // namespace

UdpRebindQueueResult EncryptedReceivePump::QueueRebindLocked(
    const UdpRebindRequest &request) {
    return m_rebind_requests.Queue(request);
}

void EncryptedReceivePump::Queue() {
    m_dispatcher.QueueReceive();
}

bool EncryptedReceivePump::SnapshotReceiveRuntime(
    ReceiveRuntimeSnapshot &out) {
    std::scoped_lock lock(m_state_mutex);
    return m_coordinator.SnapshotReceiveRuntime(out);
}

void EncryptedReceivePump::ProcessPendingRebind(
    RuntimeEffectExecutor &effect_executor) {
    std::unique_lock lock(m_state_mutex);
    const auto pending = m_rebind_requests.Take();
    if (!pending.has_value()) {
        return;
    }
    const UdpRebindRequest request = *pending;

    const PeerIdentity identity{
        .peer_index = request.peer_index,
        .activation_generation = request.activation_generation,
    };
    logger::Log(
        "Dispatching UDP bind bump peer=%zu activation=%u",
        static_cast<std::size_t>(request.peer_index.Value()),
        request.activation_generation.Value());
    const EffectBatch effects = m_coordinator.Dispatch(
        UdpRebindRequestedEvent{
            .peer = identity,
            .occurred_at = GetRuntimeNowNs(),
        });
    lock.unlock();
    effect_executor.Execute(effects);
}

NOINLINE void EncryptedReceivePump::CommitReceivedPacket(
    const ReceiveRuntimeSnapshot &snapshot,
    std::span<const std::uint8_t> packet,
    const wgnx::platform::endpoint &source,
    EffectBatch &out_effects) {
    out_effects.Clear();
    std::scoped_lock lock(m_state_mutex);
    const auto binding =
        m_coordinator.BindingSnapshot(snapshot.peer.peer_index.Value());
    if (!m_coordinator.IsActiveTransportIdentity(snapshot.peer) ||
        !binding.Matches(snapshot.socket_generation, snapshot.socket)) {
        return;
    }

    const auto *lifecycle =
        m_coordinator.Lifecycle(snapshot.peer.peer_index.Value());
    AMS_ABORT_UNLESS(lifecycle != nullptr);
    std::array<char, sizeof(wgnx::PeerInfo::resolved_endpoint)> source_text{};
    FormatEndpointText(source, source_text);
    const auto now_jiffies = wgnx::platform::get_jiffies_64();
    out_effects = m_coordinator.Dispatch(
        EncryptedDatagramReceivedEvent{
            .peer = snapshot.peer,
            .packet = packet,
            .source = source,
            .source_text = source_text,
            .keepalive_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(now_jiffies) +
                std::chrono::seconds{
                    lifecycle->persistent_keepalive_interval},
            .rekey_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(now_jiffies) +
                wgnx::wireguard::RekeyAfterTime,
            .zero_key_material_deadline =
                wgnx::wireguard::TimerDeadlineFromJiffies(now_jiffies) +
                wgnx::wireguard::ZeroKeyMaterialAfterTime,
            .occurred_at = GetRuntimeNowNs(),
        });
}

void EncryptedReceivePump::CommitReceiveFailure(
    const ReceiveRuntimeSnapshot &snapshot,
    const wgnx::platform::udp_receive_result &result,
    RuntimeEffectExecutor &effect_executor) {
    EffectBatch effects{};
    std::unique_lock lock(m_state_mutex);
    const auto binding =
        m_coordinator.BindingSnapshot(snapshot.peer.peer_index.Value());
    if (!m_coordinator.IsActiveTransportIdentity(snapshot.peer) ||
        !binding.Matches(snapshot.socket_generation, snapshot.socket)) {
        return;
    }

    logger::Log(
        "UDP receive failed for peer %u endpoint=%s error=%u native_condition=%u native_result=%lld native_error=%u",
        snapshot.peer.peer_index.Value(),
        binding.endpoint_text.data(),
        static_cast<unsigned int>(result.error),
        static_cast<unsigned int>(result.native_condition),
        static_cast<long long>(result.native_result),
        result.native_error);
    effects = m_coordinator.Dispatch(TransportFailureEvent{
        .peer = snapshot.peer,
        .operation = TransportIoOperation::Receive,
        .socket = snapshot.socket,
        .socket_generation = snapshot.socket_generation,
        .error = result.error,
        .occurred_at = GetRuntimeNowNs(),
    });
    logger::Log(
        "WG receive worker stopped after transport failure peer=%u activation=%u socket_generation=%u socket=%d",
        snapshot.peer.peer_index.Value(),
        snapshot.peer.activation_generation.Value(),
        snapshot.socket_generation.Value(),
        static_cast<int>(snapshot.socket));
    lock.unlock();
    effect_executor.Execute(effects);
}

void EncryptedReceivePump::Run(RuntimeEffectExecutor &effect_executor) {
    // HorizonDispatcher serializes this callback on one ordered work queue, so
    // the process-lifetime receive storage has one exclusive user at a time.
    wgnx::platform::packet_buffer packet{
        .data = m_packet_storage.data(),
        .len = 0,
        .capacity = m_packet_storage.size(),
    };
    while (true) {
        ProcessPendingRebind(effect_executor);

        ReceiveRuntimeSnapshot snapshot{};
        if (!SnapshotReceiveRuntime(snapshot)) {
            return;
        }

        logger::Log(
            "WG receive iteration begin peer=%u activation=%u socket_generation=%u socket=%d",
            snapshot.peer.peer_index.Value(),
            snapshot.peer.activation_generation.Value(),
            snapshot.socket_generation.Value(),
            static_cast<int>(snapshot.socket));
        const auto receive_result = wgnx::platform::udp_receive(
            snapshot.socket,
            packet.storage());
        logger::Log(
            "WG receive iteration end peer=%u activation=%u socket_generation=%u socket=%d disposition=%u error=%u native_condition=%u native_result=%lld native_error=%u bytes=%zu",
            snapshot.peer.peer_index.Value(),
            snapshot.peer.activation_generation.Value(),
            snapshot.socket_generation.Value(),
            static_cast<int>(snapshot.socket),
            static_cast<unsigned int>(receive_result.disposition),
            static_cast<unsigned int>(receive_result.error),
            static_cast<unsigned int>(receive_result.native_condition),
            static_cast<long long>(receive_result.native_result),
            receive_result.native_error,
            receive_result.bytes_received);
        if (receive_result.disposition ==
            wgnx::platform::udp_receive_disposition::retry) {
            continue;
        }
        if (receive_result.disposition ==
            wgnx::platform::udp_receive_disposition::failure) {
            CommitReceiveFailure(snapshot, receive_result, effect_executor);
            return;
        }

        AMS_ABORT_UNLESS(wgnx::platform::packet_set_len(
            std::addressof(packet), receive_result.bytes_received));
        CommitReceivedPacket(
            snapshot,
            packet.bytes(),
            receive_result.source,
            m_receive_effects);
        effect_executor.Execute(m_receive_effects);
        m_receive_effects.Clear();
        wgnx::platform::packet_clear(std::addressof(packet));
    }
}

} // namespace wgnx::sysmodule::runtime
