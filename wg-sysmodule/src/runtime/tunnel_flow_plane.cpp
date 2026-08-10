#include "runtime/tunnel_flow_plane.hpp"

#include "logger.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>

namespace wgnx::sysmodule::runtime {

namespace {

constexpr std::uint8_t InvalidSlabSlot = 0xFF;

std::uint32_t AllocateNonZero(std::uint32_t& next) {
    const std::uint32_t value = next;
    ++next;
    if (next == 0) {
        next = 1;
    }
    return value == 0 ? AllocateNonZero(next) : value;
}

bool EndpointEqual(const wgnx::tunnel::Ipv4Endpoint& lhs, const wgnx::tunnel::Ipv4Endpoint& rhs) {
    return lhs.port == rhs.port && std::equal(std::begin(lhs.address), std::end(lhs.address), std::begin(rhs.address));
}

bool IsZeroEndpoint(const wgnx::tunnel::Ipv4Endpoint& endpoint) {
    return endpoint.port == 0 &&
           std::all_of(std::begin(endpoint.address), std::end(endpoint.address), [](std::uint8_t value) { return value == 0; });
}

void FormatIpv4Text(const std::array<std::uint8_t, 4>& address, char* out, std::size_t out_size) {
    if (out == nullptr || out_size == 0) {
        return;
    }
    std::snprintf(
        out,
        out_size,
        "%u.%u.%u.%u",
        static_cast<unsigned int>(address[0]),
        static_cast<unsigned int>(address[1]),
        static_cast<unsigned int>(address[2]),
        static_cast<unsigned int>(address[3])
    );
}

} // namespace

TunnelClientId TunnelFlowPlane::CreateClient(CompletionNotifier notifier, void* notifier_context) {
    for (std::size_t index = 0; index < m_clients.size(); ++index) {
        ClientSlot& client = m_clients[index];
        if (client.allocated) {
            continue;
        }
        client = {};
        client.allocated = true;
        client.generation = AllocateNonZero(m_next_client_generation);
        client.notifier = notifier;
        client.notifier_context = notifier_context;
        return {
            .slot = static_cast<std::uint8_t>(index),
            .generation = client.generation,
        };
    }
    return {};
}

void TunnelFlowPlane::DestroyClient(TunnelClientId client, wgnx::platform::ktime_t now) {
    ClientSlot* client_slot = FindClient(client);
    if (client_slot == nullptr) {
        return;
    }
    for (std::size_t index = 0; index < m_flows.size(); ++index) {
        FlowSlot& flow = m_flows[index];
        if (flow.allocated && flow.client_slot == client.slot && flow.client_generation == client.generation) {
            CloseFlowSlot(index, wgnx::tunnel::FlowTerminalReason::ClientClosed, now, false);
        }
    }
    while (client_slot->completion_count != 0) {
        CompletionEntry entry{};
        static_cast<void>(RemoveCompletionFront(*client_slot, &entry));
        ReleaseInboundSlab(entry.inbound_slab_slot);
    }
    *client_slot = {};
}

void TunnelFlowPlane::RefreshPolicy(const TunnelPolicyInput& input, wgnx::platform::ktime_t now) {
    const auto previous_routes = m_routes;
    const auto previous_source = m_tunnel_source;
    const PeerIdentity previous_peer = m_policy_peer;
    const bool previous_available = m_policy_available;
    const bool previous_leak_protection = m_policy_leak_protection;
    const std::uint32_t previous_count = m_route_count;
    const std::uint16_t previous_effective_inner_mtu = m_effective_inner_mtu;

    m_policy_available = ParseAndNormalizePolicy(input);
    if (!m_policy_available) {
        m_route_count = 0;
        m_tunnel_source = {};
        m_policy_peer = {};
        m_policy_leak_protection = false;
        m_effective_inner_mtu = wgnx::tunnel::DefaultEffectiveInnerMtu;
    }

    const bool changed = previous_available != m_policy_available || previous_count != m_route_count ||
                         previous_source != m_tunnel_source || previous_peer != m_policy_peer || previous_routes != m_routes ||
                         previous_leak_protection != m_policy_leak_protection || previous_effective_inner_mtu != m_effective_inner_mtu;
    if (!changed) {
        return;
    }

    m_policy_generation = AllocateNonZero(m_next_policy_generation);
    for (std::size_t index = 0; index < m_flows.size(); ++index) {
        FlowSlot& flow = m_flows[index];
        if (!flow.allocated || flow.closed) {
            continue;
        }
        if (!m_policy_available || flow.peer != m_policy_peer || SelectRoute(flow.remote) == nullptr) {
            CloseFlowSlot(index, wgnx::tunnel::FlowTerminalReason::PolicyInvalidated, now, true);
        } else {
            flow.policy_generation = m_policy_generation;
        }
    }
    EnqueuePolicyChanged();
}

std::uint32_t TunnelFlowPlane::PolicyGeneration() const {
    return m_policy_generation;
}

wgnx::tunnel::Capabilities TunnelFlowPlane::GetCapabilities() const {
    return {
        .api_version = wgnx::tunnel::TunApiVersion,
        .capability_mask = wgnx::tunnel::SupportedCapabilityMask,
        .effective_inner_mtu = m_effective_inner_mtu,
        .maximum_udp_payload_bytes = static_cast<std::uint32_t>(wgnx::tunnel::MaximumUdpPayloadStorageBytes),
        .maximum_tcp_write_bytes = static_cast<std::uint32_t>(wgnx::tunnel::MaximumTcpWriteStorageBytes),
        .maximum_client_contexts = wgnx::tunnel::MaximumClientContexts,
        .maximum_flows_per_client = wgnx::tunnel::MaximumFlowsPerClient,
        .maximum_flows = wgnx::tunnel::MaximumFlows,
        .completion_queue_capacity = wgnx::tunnel::CompletionQueueCapacity,
        .maximum_batch_entries = wgnx::tunnel::MaximumBatchEntries,
        .maximum_policy_routes = wgnx::tunnel::MaximumPolicyRoutes,
        .reserved = 0,
    };
}

std::uint32_t TunnelFlowPlane::SignalAllClientCompletionEvents() const {
    std::uint32_t signaled = 0;
    for (const ClientSlot& client : m_clients) {
        if (!client.allocated || client.notifier == nullptr) {
            continue;
        }
        client.notifier(client.notifier_context);
        ++signaled;
    }
    return signaled;
}

wgnx::tunnel::RoutingPolicySnapshot TunnelFlowPlane::CopyRoutingPolicy(std::span<wgnx::tunnel::RouteRecord> out) const {
    const std::size_t copy_count = std::min<std::size_t>(out.size(), m_route_count);
    for (std::size_t index = 0; index < copy_count; ++index) {
        const NormalizedRoute& route = m_routes[index];
        out[index] = {
            .address_family = 4,
            .prefix_length = route.prefix_length,
            .reserved = 0,
            .network_address = {route.network[0], route.network[1], route.network[2], route.network[3]},
            .route_identifier = route.route_identifier,
        };
    }
    return {
        .policy_generation = m_policy_generation,
        .route_count = m_route_count,
    };
}

TunnelFlowReservation TunnelFlowPlane::ReserveConnectedUdpFlow(
    TunnelClientId client,
    const wgnx::tunnel::OpenConnectedFlowRequest& request,
    wgnx::platform::ktime_t now,
    TunnelTransportAvailability availability
) {
    return ReserveConnectedFlow(client, request, now, availability, wgnx::tunnel::FlowKind::Udp);
}

TunnelFlowReservation TunnelFlowPlane::ReserveConnectedTcpFlow(
    TunnelClientId client,
    const wgnx::tunnel::OpenConnectedFlowRequest& request,
    wgnx::platform::ktime_t now,
    TunnelTransportAvailability availability
) {
    return ReserveConnectedFlow(client, request, now, availability, wgnx::tunnel::FlowKind::Tcp);
}

TunnelFlowReservation TunnelFlowPlane::ReserveConnectedFlow(
    TunnelClientId client,
    const wgnx::tunnel::OpenConnectedFlowRequest& request,
    wgnx::platform::ktime_t now,
    TunnelTransportAvailability availability,
    wgnx::tunnel::FlowKind kind
) {
    TunnelFlowReservation reservation{};
    wgnx::tunnel::OpenConnectedFlowResult& result = reservation.result;
    result.routing_policy_generation = m_policy_generation;
    ClientSlot* client_slot = FindClient(client);
    if (client_slot == nullptr || request.remote.reserved != 0 || request.remote.port == 0 || IsZeroEndpoint(request.remote)) {
        return reservation;
    }
    if (!m_policy_available || m_policy_peer.activation_generation.IsZero()) {
        result.status = wgnx::tunnel::ProtocolStatus::PeerUnavailable;
        return reservation;
    }
    if (SelectRoute(request.remote) == nullptr) {
        result.status = wgnx::tunnel::ProtocolStatus::RouteNotCovered;
        return reservation;
    }
    if (!availability.protocol_available) {
        result.status = m_policy_leak_protection ? wgnx::tunnel::ProtocolStatus::TunnelBlockedByPolicy
                                                 : wgnx::tunnel::ProtocolStatus::TransportUnavailable;
        return reservation;
    }

    std::size_t owned_flows = 0;
    for (const FlowSlot& flow : m_flows) {
        if (flow.allocated && !flow.closed && flow.client_slot == client.slot && flow.client_generation == client.generation) {
            ++owned_flows;
        }
    }
    if (owned_flows >= wgnx::tunnel::MaximumFlowsPerClient) {
        result.status = wgnx::tunnel::ProtocolStatus::FlowQuotaExhausted;
        return reservation;
    }

    auto free_slot = std::find_if(m_flows.begin(), m_flows.end(), [](const FlowSlot& flow) { return !flow.allocated || flow.closed; });
    if (free_slot == m_flows.end()) {
        result.status = wgnx::tunnel::ProtocolStatus::FlowQuotaExhausted;
        return reservation;
    }
    if (!HasTombstoneReservation(now)) {
        result.status = wgnx::tunnel::ProtocolStatus::ReverseTupleExhausted;
        return reservation;
    }
    std::uint16_t source_port = 0;
    if (!AllocateVirtualTuple(request.remote, &source_port, now)) {
        result.status = wgnx::tunnel::ProtocolStatus::ReverseTupleExhausted;
        return reservation;
    }

    const std::size_t slot = static_cast<std::size_t>(std::distance(m_flows.begin(), free_slot));
    FlowSlot& flow = *free_slot;
    flow = {
        .allocated = true,
        .closed = false,
        .pending = true,
        .state = wgnx::tunnel::FlowState::Connecting,
        .stream_flags = kind == wgnx::tunnel::FlowKind::Tcp
                            ? wgnx::tunnel::FlowStreamFlagLocalWriteOpen | wgnx::tunnel::FlowStreamFlagRemoteWriteOpen
                            : wgnx::tunnel::FlowStreamFlagNone,
        .client_slot = client.slot,
        .client_generation = client.generation,
        .allocation_generation = AllocateFlowGeneration(),
        .peer = m_policy_peer,
        .policy_generation = m_policy_generation,
        .kind = kind,
        .remote = request.remote,
        .tunnel_source = m_tunnel_source,
        .virtual_source_port = source_port,
        .created_at = now,
        .last_activity_at = now,
        .diagnostic_tag = request.diagnostic_tag,
    };
    result.status = wgnx::tunnel::ProtocolStatus::Success;
    result.flow = MakeFlowHandle(slot, flow);
    result.peer_activation_generation = flow.peer.activation_generation.Value();
    reservation.local = {
        .address = {flow.tunnel_source[0], flow.tunnel_source[1], flow.tunnel_source[2], flow.tunnel_source[3]},
        .port = flow.virtual_source_port,
        .reserved = 0,
    };
    reservation.remote = flow.remote;
    reservation.client = client;
    reservation.peer = flow.peer;
    reservation.adapter_token = result.flow.value;
    char remote_text[16] = {};
    char tunnel_source_text[16] = {};
    FormatIpv4Text(
        {flow.remote.address[0], flow.remote.address[1], flow.remote.address[2], flow.remote.address[3]},
        remote_text,
        sizeof(remote_text)
    );
    FormatIpv4Text(flow.tunnel_source, tunnel_source_text, sizeof(tunnel_source_text));
    logger::Log(
        "Opened tunnel %s flow=%llu slot=%zu client=%u/%u peer=%u activation=%u policy=%u remote=%s:%u "
        "tunnel_source=%s virtual_source_port=%u tag=%llu",
        kind == wgnx::tunnel::FlowKind::Tcp ? "TCP" : "UDP",
        static_cast<unsigned long long>(result.flow.value),
        slot,
        static_cast<unsigned int>(flow.client_slot),
        flow.client_generation,
        flow.peer.peer_index.Value(),
        flow.peer.activation_generation.Value(),
        flow.policy_generation,
        remote_text,
        static_cast<unsigned int>(flow.remote.port),
        tunnel_source_text,
        static_cast<unsigned int>(flow.virtual_source_port),
        static_cast<unsigned long long>(flow.diagnostic_tag)
    );
    return reservation;
}

wgnx::tunnel::OpenConnectedFlowResult TunnelFlowPlane::OpenConnectedUdpFlow(
    TunnelClientId client,
    const wgnx::tunnel::OpenConnectedFlowRequest& request,
    wgnx::platform::ktime_t now,
    TunnelTransportAvailability availability
) {
    const TunnelFlowReservation reservation = ReserveConnectedUdpFlow(client, request, now, availability);
    if (!reservation.IsReserved()) {
        return reservation.result;
    }
    if (!CommitFlowReservation(reservation)) {
        CancelFlowReservation(reservation);
        auto result = reservation.result;
        result.status = wgnx::tunnel::ProtocolStatus::PeerUnavailable;
        result.flow = {};
        return result;
    }
    return reservation.result;
}

bool TunnelFlowPlane::CommitFlowReservation(const TunnelFlowReservation& reservation) {
    if (!reservation.IsReserved()) {
        return false;
    }
    FlowSlot* flow = FindFlow(reservation.client, reservation.result.flow);
    if (flow == nullptr || !flow->pending || flow->closed || flow->peer != reservation.peer ||
        flow->remote.port != reservation.remote.port ||
        !std::equal(std::begin(flow->remote.address), std::end(flow->remote.address), std::begin(reservation.remote.address)) ||
        m_policy_peer != reservation.peer || m_policy_generation != reservation.result.routing_policy_generation) {
        return false;
    }
    flow->pending = false;
    flow->state = flow->kind == wgnx::tunnel::FlowKind::Tcp ? wgnx::tunnel::FlowState::Connecting : wgnx::tunnel::FlowState::Open;
    return true;
}

void TunnelFlowPlane::CancelFlowReservation(const TunnelFlowReservation& reservation) {
    if (!reservation.IsReserved()) {
        return;
    }
    FlowSlot* flow = FindFlow(reservation.client, reservation.result.flow);
    if (flow != nullptr && flow->pending) {
        *flow = {};
    }
}

bool TunnelFlowPlane::GetFlowAdapterToken(TunnelClientId client, wgnx::tunnel::FlowHandle flow_handle, std::uint64_t* out_token) const {
    const FlowSlot* flow = FindFlow(client, flow_handle);
    if (flow == nullptr || flow->pending || flow->closed || out_token == nullptr) {
        return false;
    }
    *out_token = flow_handle.value;
    return true;
}

TunnelTcpOutputRoute TunnelFlowPlane::ResolveTcpOutput(
    const wgnx::tunnel::Ipv4Endpoint& local, const wgnx::tunnel::Ipv4Endpoint& remote
) const {
    for (std::size_t index = 0; index < m_flows.size(); ++index) {
        const FlowSlot& flow = m_flows[index];
        if (!flow.allocated || flow.closed || flow.pending || flow.kind != wgnx::tunnel::FlowKind::Tcp ||
            !EndpointEqual(flow.remote, remote) || flow.virtual_source_port != local.port ||
            !std::equal(flow.tunnel_source.begin(), flow.tunnel_source.end(), std::begin(local.address)) ||
            FindClient({.slot = flow.client_slot, .generation = flow.client_generation}) == nullptr || !m_policy_available ||
            flow.peer != m_policy_peer || flow.policy_generation != m_policy_generation) {
            continue;
        }
        return {
            .peer = flow.peer,
            .flow = MakeFlowHandle(index, flow),
            .policy_generation = flow.policy_generation,
        };
    }
    return {};
}

std::uint32_t TunnelFlowPlane::CopyClientAdapterTokens(TunnelClientId client, std::span<std::uint64_t> out) const {
    if (FindClient(client) == nullptr) {
        return 0;
    }
    std::uint32_t count = 0;
    for (std::size_t index = 0; index < m_flows.size(); ++index) {
        const FlowSlot& flow = m_flows[index];
        if (!flow.allocated || flow.pending || flow.closed || flow.client_slot != client.slot ||
            flow.client_generation != client.generation) {
            continue;
        }
        if (count < out.size()) {
            out[count] = MakeFlowHandle(index, flow).value;
        }
        ++count;
    }
    return count;
}

PreparedTunnelDatagram TunnelFlowPlane::PrepareSend(
    TunnelClientId client,
    const wgnx::tunnel::PayloadRange& descriptor,
    std::span<const std::uint8_t> payload,
    TunnelTransportAvailability availability,
    wgnx::platform::ktime_t now
) {
    PreparedTunnelDatagram outcome{.flow = descriptor.flow};
    if (descriptor.payload_size != payload.size()) {
        outcome.status = wgnx::tunnel::ProtocolStatus::MalformedInput;
        return outcome;
    }
    if (payload.size() > wgnx::tunnel::MaximumUdpPayloadStorageBytes) {
        outcome.status = wgnx::tunnel::ProtocolStatus::PayloadTooLarge;
        return outcome;
    }
    FlowSlot* flow = FindFlow(client, descriptor.flow);
    if (flow == nullptr) {
        outcome.status = wgnx::tunnel::ProtocolStatus::StaleHandle;
        return outcome;
    }
    if (flow->closed || flow->pending) {
        outcome.status = wgnx::tunnel::ProtocolStatus::FlowClosed;
        return outcome;
    }
    ++flow->send_attempts;
    if (!m_policy_available || flow->peer != m_policy_peer) {
        outcome.status = wgnx::tunnel::ProtocolStatus::PeerUnavailable;
        return outcome;
    }
    if (!availability.protocol_available) {
        outcome.status = wgnx::tunnel::ProtocolStatus::TransportUnavailable;
        return outcome;
    }
    if (!availability.staging_available) {
        flow->writable_waiter = true;
        ++flow->send_queue_full;
        outcome.status = wgnx::tunnel::ProtocolStatus::QueueFull;
        return outcome;
    }

    flow->last_activity_at = now;
    ++flow->send_admitted;
    outcome.status = wgnx::tunnel::ProtocolStatus::Success;
    outcome.peer = flow->peer;
    outcome.adapter_token = descriptor.flow.value;
    return outcome;
}

PreparedTunnelDatagram TunnelFlowPlane::PrepareTcpWrite(
    TunnelClientId client, const wgnx::tunnel::PayloadRange& range, std::span<const std::uint8_t> payload, wgnx::platform::ktime_t now
) {
    PreparedTunnelDatagram outcome{.flow = range.flow};
    if (range.payload_size != payload.size()) {
        outcome.status = wgnx::tunnel::ProtocolStatus::MalformedInput;
        return outcome;
    }
    if (payload.size() > wgnx::tunnel::MaximumTcpWriteStorageBytes) {
        outcome.status = wgnx::tunnel::ProtocolStatus::PayloadTooLarge;
        return outcome;
    }
    FlowSlot* flow = FindFlow(client, range.flow);
    if (flow == nullptr) {
        outcome.status = wgnx::tunnel::ProtocolStatus::StaleHandle;
    } else if (flow->kind != wgnx::tunnel::FlowKind::Tcp) {
        outcome.status = wgnx::tunnel::ProtocolStatus::WrongFlowKind;
    } else if (flow->closed) {
        outcome.status = wgnx::tunnel::ProtocolStatus::FlowClosed;
    } else if ((flow->stream_flags & wgnx::tunnel::FlowStreamFlagLocalWriteOpen) == 0) {
        outcome.status = wgnx::tunnel::ProtocolStatus::LocalWriteClosed;
    } else if (flow->state != wgnx::tunnel::FlowState::Open) {
        outcome.status = wgnx::tunnel::ProtocolStatus::NotConnected;
    } else if (!m_policy_available || flow->peer != m_policy_peer || flow->policy_generation != m_policy_generation) {
        outcome.status = wgnx::tunnel::ProtocolStatus::PeerUnavailable;
    } else {
        flow->last_activity_at = now;
        outcome.status = wgnx::tunnel::ProtocolStatus::Success;
        outcome.peer = flow->peer;
        outcome.adapter_token = range.flow.value;
    }
    return outcome;
}

PreparedTunnelDatagram TunnelFlowPlane::PrepareTcpShutdown(
    TunnelClientId client, wgnx::tunnel::FlowHandle flow_handle, wgnx::platform::ktime_t now
) {
    PreparedTunnelDatagram outcome{.flow = flow_handle};
    FlowSlot* flow = FindFlow(client, flow_handle);
    if (flow == nullptr) {
        outcome.status = wgnx::tunnel::ProtocolStatus::StaleHandle;
    } else if (flow->kind != wgnx::tunnel::FlowKind::Tcp) {
        outcome.status = wgnx::tunnel::ProtocolStatus::WrongFlowKind;
    } else if (flow->closed) {
        outcome.status = wgnx::tunnel::ProtocolStatus::FlowClosed;
    } else if (flow->state != wgnx::tunnel::FlowState::Open && flow->state != wgnx::tunnel::FlowState::Closing) {
        outcome.status = wgnx::tunnel::ProtocolStatus::NotConnected;
    } else if ((flow->stream_flags & wgnx::tunnel::FlowStreamFlagLocalWriteOpen) == 0) {
        outcome.status = wgnx::tunnel::ProtocolStatus::Success;
        outcome.peer = flow->peer;
        outcome.adapter_token = flow_handle.value;
    } else {
        flow->last_activity_at = now;
        outcome.status = wgnx::tunnel::ProtocolStatus::Success;
        outcome.peer = flow->peer;
        outcome.adapter_token = flow_handle.value;
    }
    return outcome;
}

void TunnelFlowPlane::CompleteSend(const PreparedTunnelDatagram& datagram, wgnx::tunnel::ProtocolStatus completion_status) {
    if (!datagram.IsPrepared()) {
        return;
    }
    for (std::size_t index = 0; index < m_flows.size(); ++index) {
        FlowSlot& flow = m_flows[index];
        if (!flow.allocated || MakeFlowHandle(index, flow).value != datagram.flow.value) {
            continue;
        }
        if (completion_status == wgnx::tunnel::ProtocolStatus::QueueFull) {
            flow.writable_waiter = true;
            ++flow.send_queue_full;
        } else if (completion_status == wgnx::tunnel::ProtocolStatus::Success) {
            flow.writable_waiter = false;
        }
        return;
    }
}

void TunnelFlowPlane::NotifyOutboundCapacityAvailable(const PeerIdentity& peer) {
    for (std::size_t index = 0; index < m_flows.size(); ++index) {
        FlowSlot& flow = m_flows[index];
        if (!flow.allocated || flow.closed || flow.pending || flow.peer != peer || !flow.writable_waiter) {
            continue;
        }

        flow.writable_waiter = false;
        wgnx::tunnel::CompletionRecord completion{};
        completion.type = wgnx::tunnel::CompletionType::Writable;
        completion.status = wgnx::tunnel::ProtocolStatus::Success;
        completion.flow = MakeFlowHandle(index, flow);
        completion.peer_activation_generation = flow.peer.activation_generation.Value();
        completion.routing_policy_generation = flow.policy_generation;
        completion.flow_state = wgnx::tunnel::FlowState::Open;
        EnqueueControlCompletion({.slot = flow.client_slot, .generation = flow.client_generation}, completion);
    }
}

TunnelCompletionDrainOutcome TunnelFlowPlane::ReceiveCompletions(
    TunnelClientId client, std::span<wgnx::tunnel::CompletionRecord> records, std::span<std::uint8_t> payload
) {
    TunnelCompletionDrainOutcome outcome{};
    ClientSlot* client_slot = FindClient(client);
    if (client_slot == nullptr) {
        outcome.status = wgnx::tunnel::ProtocolStatus::StaleHandle;
        return outcome;
    }
    if (records.empty()) {
        outcome.status = wgnx::tunnel::ProtocolStatus::OutputBufferTooSmall;
        return outcome;
    }
    std::size_t payload_offset = 0;
    while (outcome.count < records.size() && client_slot->completion_count != 0) {
        const CompletionEntry* entry = CompletionAt(*client_slot, 0);
        if (entry == nullptr) {
            break;
        }
        if (entry->inbound_slab_slot != InvalidSlabSlot) {
            const InboundSlab& slab = m_inbound_slabs[entry->inbound_slab_slot];
            if (payload.size() - payload_offset < slab.size) {
                outcome.status =
                    outcome.count == 0 ? wgnx::tunnel::ProtocolStatus::OutputBufferTooSmall : wgnx::tunnel::ProtocolStatus::Success;
                return outcome;
            }
        }
        CompletionEntry delivered{};
        static_cast<void>(RemoveCompletionFront(*client_slot, &delivered));
        wgnx::tunnel::CompletionRecord record = delivered.record;
        if (delivered.inbound_slab_slot != InvalidSlabSlot) {
            InboundSlab& slab = m_inbound_slabs[delivered.inbound_slab_slot];
            std::memcpy(payload.data() + payload_offset, slab.bytes.data(), slab.size);
            record.payload_offset = static_cast<std::uint32_t>(payload_offset);
            record.payload_size = slab.size;
            payload_offset += slab.size;
            ReleaseInboundSlab(delivered.inbound_slab_slot);
            FlowSlot* flow = FindFlow(client, record.flow);
            if (flow != nullptr && flow->inbound_occupancy > 0) {
                --flow->inbound_occupancy;
            }
        }
        records[outcome.count++] = record;
    }
    outcome.status = outcome.count == 0 ? wgnx::tunnel::ProtocolStatus::QueueEmpty : wgnx::tunnel::ProtocolStatus::Success;
    return outcome;
}

bool TunnelFlowPlane::HasCompletions(TunnelClientId client) const {
    const ClientSlot* client_slot = FindClient(client);
    return client_slot != nullptr && client_slot->completion_count != 0;
}

wgnx::tunnel::FlowStateResult TunnelFlowPlane::GetFlowState(TunnelClientId client, wgnx::tunnel::FlowHandle flow_handle) const {
    wgnx::tunnel::FlowStateResult result{
        .status = wgnx::tunnel::ProtocolStatus::StaleHandle,
        .state = wgnx::tunnel::FlowState::Closed,
        .terminal_reason = wgnx::tunnel::FlowTerminalReason::None,
        .flow_kind = wgnx::tunnel::FlowKind::Udp,
        .peer_activation_generation = 0,
        .routing_policy_generation = m_policy_generation,
        .advertised_local = {},
        .diagnostic_tag = 0,
        .stream_flags = wgnx::tunnel::FlowStreamFlagNone,
        .reserved = 0,
    };
    const FlowSlot* flow = FindFlow(client, flow_handle);
    if (flow == nullptr) {
        return result;
    }
    result.status = flow->closed ? wgnx::tunnel::ProtocolStatus::FlowClosed : wgnx::tunnel::ProtocolStatus::Success;
    result.state = flow->closed ? wgnx::tunnel::FlowState::Closed : flow->state;
    result.terminal_reason = flow->terminal_reason;
    result.flow_kind = flow->kind;
    result.peer_activation_generation = flow->peer.activation_generation.Value();
    result.routing_policy_generation = flow->policy_generation;
    std::copy(flow->tunnel_source.begin(), flow->tunnel_source.end(), std::begin(result.advertised_local.address));
    result.advertised_local.port = flow->virtual_source_port;
    result.diagnostic_tag = flow->diagnostic_tag;
    result.stream_flags = flow->stream_flags;
    return result;
}

wgnx::tunnel::ProtocolStatus TunnelFlowPlane::CloseFlow(
    TunnelClientId client, wgnx::tunnel::FlowHandle flow_handle, wgnx::platform::ktime_t now
) {
    FlowSlot* flow = FindFlow(client, flow_handle);
    if (flow == nullptr) {
        return wgnx::tunnel::ProtocolStatus::StaleHandle;
    }
    if (!flow->closed) {
        const std::size_t slot = static_cast<std::size_t>(flow - m_flows.data());
        CloseFlowSlot(slot, wgnx::tunnel::FlowTerminalReason::ClientClosed, now, true);
    }
    return wgnx::tunnel::ProtocolStatus::Success;
}

TunnelInboundOutcome TunnelFlowPlane::DeliverInboundUdpDatagram(
    const PeerIdentity& peer,
    std::uint32_t policy_generation,
    std::uint64_t adapter_token,
    const wgnx::tunnel::Ipv4Endpoint& remote,
    std::span<const std::uint8_t> payload,
    wgnx::platform::ktime_t now
) {
    TunnelInboundOutcome outcome{};
    if (adapter_token == 0 || payload.size() > wgnx::tunnel::MaximumUdpPayloadStorageBytes) {
        outcome.disposition = TunnelInboundDisposition::DroppedMalformed;
        return outcome;
    }
    for (std::size_t index = 0; index < m_flows.size(); ++index) {
        FlowSlot& flow = m_flows[index];
        if (!flow.allocated || MakeFlowHandle(index, flow).value != adapter_token) {
            continue;
        }
        outcome.client = {.slot = flow.client_slot, .generation = flow.client_generation};
        outcome.flow = MakeFlowHandle(index, flow);
        outcome.payload_size = payload.size();
        if (flow.closed || flow.pending || flow.kind != wgnx::tunnel::FlowKind::Udp || FindClient(outcome.client) == nullptr ||
            flow.peer != peer || flow.policy_generation != policy_generation || m_policy_generation != policy_generation ||
            m_policy_peer != peer || !EndpointEqual(flow.remote, remote)) {
            outcome.disposition = TunnelInboundDisposition::DroppedStale;
            return outcome;
        }
        if (flow.inbound_occupancy >= wgnx::tunnel::MaximumInboundDatagramsPerFlow) {
            ++flow.inbound_dropped;
            outcome.disposition = TunnelInboundDisposition::DroppedQueueFull;
            return outcome;
        }
        const std::uint8_t slab_slot = AllocateInboundSlab();
        if (slab_slot == InvalidSlabSlot) {
            ++flow.inbound_dropped;
            outcome.disposition = TunnelInboundDisposition::DroppedQueueFull;
            return outcome;
        }
        InboundSlab& slab = m_inbound_slabs[slab_slot];
        slab.size = static_cast<std::uint16_t>(payload.size());
        std::memcpy(slab.bytes.data(), payload.data(), payload.size());
        ++flow.inbound_occupancy;
        flow.last_activity_at = now;
        outcome.disposition =
            EnqueueDataCompletion(index, slab_slot) ? TunnelInboundDisposition::Delivered : TunnelInboundDisposition::DroppedQueueFull;
        if (outcome.disposition == TunnelInboundDisposition::Delivered) {
            ++flow.inbound_delivered;
        } else {
            ++flow.inbound_dropped;
        }
        return outcome;
    }
    outcome.disposition = TunnelInboundDisposition::DroppedUnknown;
    return outcome;
}

TunnelInboundOutcome TunnelFlowPlane::DeliverInboundTcpStream(
    const PeerIdentity& peer,
    std::uint32_t policy_generation,
    std::uint64_t adapter_token,
    std::span<const std::uint8_t> payload,
    wgnx::platform::ktime_t now
) {
    TunnelInboundOutcome outcome{};
    if (adapter_token == 0 || payload.size() > wgnx::tunnel::MaximumTcpWriteStorageBytes) {
        outcome.disposition = TunnelInboundDisposition::DroppedMalformed;
        return outcome;
    }
    for (std::size_t index = 0; index < m_flows.size(); ++index) {
        FlowSlot& flow = m_flows[index];
        if (!flow.allocated || MakeFlowHandle(index, flow).value != adapter_token) {
            continue;
        }
        outcome.client = {.slot = flow.client_slot, .generation = flow.client_generation};
        outcome.flow = MakeFlowHandle(index, flow);
        outcome.payload_size = payload.size();
        if (flow.closed || flow.pending || flow.kind != wgnx::tunnel::FlowKind::Tcp || FindClient(outcome.client) == nullptr ||
            flow.peer != peer || flow.policy_generation != policy_generation || m_policy_generation != policy_generation ||
            m_policy_peer != peer) {
            outcome.disposition = TunnelInboundDisposition::DroppedStale;
            return outcome;
        }
        if (flow.inbound_occupancy >= wgnx::tunnel::MaximumInboundDatagramsPerFlow) {
            ++flow.inbound_dropped;
            outcome.disposition = TunnelInboundDisposition::DroppedQueueFull;
            return outcome;
        }
        const std::uint8_t slab_slot = AllocateInboundSlab();
        if (slab_slot == InvalidSlabSlot) {
            ++flow.inbound_dropped;
            outcome.disposition = TunnelInboundDisposition::DroppedQueueFull;
            return outcome;
        }
        InboundSlab& slab = m_inbound_slabs[slab_slot];
        slab.size = static_cast<std::uint16_t>(payload.size());
        std::memcpy(slab.bytes.data(), payload.data(), payload.size());
        ++flow.inbound_occupancy;
        flow.last_activity_at = now;
        outcome.disposition =
            EnqueueDataCompletion(index, slab_slot) ? TunnelInboundDisposition::Delivered : TunnelInboundDisposition::DroppedQueueFull;
        if (outcome.disposition == TunnelInboundDisposition::Delivered) {
            ++flow.inbound_delivered;
        } else {
            ++flow.inbound_dropped;
        }
        return outcome;
    }
    outcome.disposition = TunnelInboundDisposition::DroppedUnknown;
    return outcome;
}

bool TunnelFlowPlane::MarkTcpConnected(std::uint64_t adapter_token, wgnx::platform::ktime_t now) {
    for (std::size_t index = 0; index < m_flows.size(); ++index) {
        FlowSlot& flow = m_flows[index];
        if (!flow.allocated || MakeFlowHandle(index, flow).value != adapter_token) {
            continue;
        }
        if (flow.closed || flow.pending || flow.kind != wgnx::tunnel::FlowKind::Tcp || flow.state != wgnx::tunnel::FlowState::Connecting) {
            return false;
        }
        flow.state = wgnx::tunnel::FlowState::Open;
        flow.last_activity_at = now;
        wgnx::tunnel::CompletionRecord completion{};
        completion.type = wgnx::tunnel::CompletionType::FlowStateChanged;
        completion.status = wgnx::tunnel::ProtocolStatus::Success;
        completion.flow = MakeFlowHandle(index, flow);
        completion.peer_activation_generation = flow.peer.activation_generation.Value();
        completion.routing_policy_generation = flow.policy_generation;
        completion.flow_state = flow.state;
        completion.flow_kind = flow.kind;
        EnqueueControlCompletion({.slot = flow.client_slot, .generation = flow.client_generation}, completion);
        return true;
    }
    return false;
}

bool TunnelFlowPlane::MarkTcpLocalWriteClosed(std::uint64_t adapter_token, wgnx::platform::ktime_t now) {
    for (std::size_t index = 0; index < m_flows.size(); ++index) {
        FlowSlot& flow = m_flows[index];
        if (!flow.allocated || MakeFlowHandle(index, flow).value != adapter_token) {
            continue;
        }
        if (flow.closed || flow.pending || flow.kind != wgnx::tunnel::FlowKind::Tcp) {
            return false;
        }
        if ((flow.stream_flags & wgnx::tunnel::FlowStreamFlagLocalWriteOpen) == 0) {
            return true;
        }
        flow.stream_flags &= ~wgnx::tunnel::FlowStreamFlagLocalWriteOpen;
        flow.state = wgnx::tunnel::FlowState::Closing;
        flow.last_activity_at = now;
        wgnx::tunnel::CompletionRecord completion{};
        completion.type = wgnx::tunnel::CompletionType::FlowStateChanged;
        completion.status = wgnx::tunnel::ProtocolStatus::Success;
        completion.flow = MakeFlowHandle(index, flow);
        completion.peer_activation_generation = flow.peer.activation_generation.Value();
        completion.routing_policy_generation = flow.policy_generation;
        completion.flow_state = flow.state;
        completion.flow_kind = flow.kind;
        EnqueueControlCompletion({.slot = flow.client_slot, .generation = flow.client_generation}, completion);
        return true;
    }
    return false;
}

bool TunnelFlowPlane::MarkTcpRemoteWriteClosed(std::uint64_t adapter_token, wgnx::platform::ktime_t now) {
    for (std::size_t index = 0; index < m_flows.size(); ++index) {
        FlowSlot& flow = m_flows[index];
        if (!flow.allocated || MakeFlowHandle(index, flow).value != adapter_token) {
            continue;
        }
        if (flow.closed || flow.pending || flow.kind != wgnx::tunnel::FlowKind::Tcp) {
            return false;
        }
        if ((flow.stream_flags & wgnx::tunnel::FlowStreamFlagRemoteWriteOpen) == 0) {
            return true;
        }
        flow.stream_flags &= ~wgnx::tunnel::FlowStreamFlagRemoteWriteOpen;
        flow.state = wgnx::tunnel::FlowState::Closing;
        flow.last_activity_at = now;
        wgnx::tunnel::CompletionRecord completion{};
        completion.type = wgnx::tunnel::CompletionType::FlowStateChanged;
        completion.status = wgnx::tunnel::ProtocolStatus::Success;
        completion.flow = MakeFlowHandle(index, flow);
        completion.peer_activation_generation = flow.peer.activation_generation.Value();
        completion.routing_policy_generation = flow.policy_generation;
        completion.flow_state = flow.state;
        completion.flow_kind = flow.kind;
        EnqueueControlCompletion({.slot = flow.client_slot, .generation = flow.client_generation}, completion);
        return true;
    }
    return false;
}

bool TunnelFlowPlane::MarkTcpReset(std::uint64_t adapter_token, wgnx::platform::ktime_t now) {
    for (std::size_t index = 0; index < m_flows.size(); ++index) {
        FlowSlot& flow = m_flows[index];
        if (!flow.allocated || MakeFlowHandle(index, flow).value != adapter_token) {
            continue;
        }
        if (flow.closed || flow.pending || flow.kind != wgnx::tunnel::FlowKind::Tcp) {
            return false;
        }
        CloseFlowSlot(
            index,
            flow.state == wgnx::tunnel::FlowState::Connecting ? wgnx::tunnel::FlowTerminalReason::ResetDuringConnect
                                                              : wgnx::tunnel::FlowTerminalReason::ResetAfterConnect,
            now,
            true
        );
        return true;
    }
    return false;
}

bool TunnelFlowPlane::MarkTcpWriteBlocked(std::uint64_t adapter_token) {
    for (std::size_t index = 0; index < m_flows.size(); ++index) {
        FlowSlot& flow = m_flows[index];
        if (flow.allocated && !flow.closed && !flow.pending && flow.kind == wgnx::tunnel::FlowKind::Tcp &&
            MakeFlowHandle(index, flow).value == adapter_token) {
            flow.writable_waiter = true;
            ++flow.send_queue_full;
            return true;
        }
    }
    return false;
}

bool TunnelFlowPlane::MarkTcpWritable(std::uint64_t adapter_token) {
    for (std::size_t index = 0; index < m_flows.size(); ++index) {
        FlowSlot& flow = m_flows[index];
        if (!flow.allocated || flow.closed || flow.pending || flow.kind != wgnx::tunnel::FlowKind::Tcp ||
            MakeFlowHandle(index, flow).value != adapter_token) {
            continue;
        }
        if (!flow.writable_waiter) {
            return true;
        }
        flow.writable_waiter = false;
        wgnx::tunnel::CompletionRecord completion{};
        completion.type = wgnx::tunnel::CompletionType::Writable;
        completion.status = wgnx::tunnel::ProtocolStatus::Success;
        completion.flow = MakeFlowHandle(index, flow);
        completion.peer_activation_generation = flow.peer.activation_generation.Value();
        completion.routing_policy_generation = flow.policy_generation;
        completion.flow_state = flow.state;
        completion.flow_kind = flow.kind;
        EnqueueControlCompletion({.slot = flow.client_slot, .generation = flow.client_generation}, completion);
        return true;
    }
    return false;
}

std::uint32_t TunnelFlowPlane::ExpireTcpConnectingFlows(wgnx::platform::ktime_t now, std::span<std::uint64_t> adapter_tokens) {
    std::uint32_t expired = 0;
    for (std::size_t index = 0; index < m_flows.size() && expired < adapter_tokens.size(); ++index) {
        FlowSlot& flow = m_flows[index];
        if (!flow.allocated || flow.closed || flow.pending || flow.kind != wgnx::tunnel::FlowKind::Tcp ||
            flow.state != wgnx::tunnel::FlowState::Connecting || now < flow.created_at || now - flow.created_at < TcpConnectTimeoutNs) {
            continue;
        }
        adapter_tokens[expired++] = MakeFlowHandle(index, flow).value;
        CloseFlowSlot(index, wgnx::tunnel::FlowTerminalReason::ConnectTimedOut, now, true);
    }
    return expired;
}

void TunnelFlowPlane::InvalidatePeerActivation(
    const PeerIdentity& peer, wgnx::tunnel::FlowTerminalReason reason, wgnx::platform::ktime_t now
) {
    for (std::size_t index = 0; index < m_flows.size(); ++index) {
        if (m_flows[index].allocated && !m_flows[index].closed && !m_flows[index].pending && m_flows[index].peer == peer) {
            CloseFlowSlot(index, reason, now, true);
        }
    }
}

TunnelFlowPlane::ClientSlot* TunnelFlowPlane::FindClient(TunnelClientId client) {
    if (!client.IsValid()) {
        return nullptr;
    }
    ClientSlot& slot = m_clients[client.slot];
    return slot.allocated && slot.generation == client.generation ? &slot : nullptr;
}

const TunnelFlowPlane::ClientSlot* TunnelFlowPlane::FindClient(TunnelClientId client) const {
    return const_cast<TunnelFlowPlane*>(this)->FindClient(client);
}

TunnelFlowPlane::FlowSlot* TunnelFlowPlane::FindFlow(TunnelClientId client, wgnx::tunnel::FlowHandle handle) {
    std::size_t slot = 0;
    std::uint32_t generation = 0;
    std::uint8_t handle_client_slot = 0;
    std::uint32_t handle_client_generation = 0;
    if (FindClient(client) == nullptr || !DecodeFlowHandle(handle, &slot, &generation, &handle_client_slot, &handle_client_generation) ||
        handle_client_slot != client.slot || handle_client_generation != client.generation) {
        return nullptr;
    }
    FlowSlot& flow = m_flows[slot];
    return flow.allocated && flow.allocation_generation == generation && flow.client_slot == client.slot &&
                   flow.client_generation == client.generation
               ? &flow
               : nullptr;
}

const TunnelFlowPlane::FlowSlot* TunnelFlowPlane::FindFlow(TunnelClientId client, wgnx::tunnel::FlowHandle handle) const {
    return const_cast<TunnelFlowPlane*>(this)->FindFlow(client, handle);
}

wgnx::tunnel::FlowHandle TunnelFlowPlane::MakeFlowHandle(std::size_t flow_slot, const FlowSlot& flow) const {
    const std::uint64_t low = (static_cast<std::uint64_t>(flow.client_slot) << 4U) | static_cast<std::uint64_t>(flow_slot);
    const std::uint64_t middle = static_cast<std::uint64_t>(flow.allocation_generation & 0x00FFFFFFU) << 8U;
    const std::uint64_t high = static_cast<std::uint64_t>(flow.client_generation & 0xFFFFFFFFU) << 32U;
    return {.value = high | middle | low};
}

bool TunnelFlowPlane::DecodeFlowHandle(
    wgnx::tunnel::FlowHandle handle,
    std::size_t* out_slot,
    std::uint32_t* out_generation,
    std::uint8_t* out_client_slot,
    std::uint32_t* out_client_generation
) const {
    if (out_slot == nullptr || out_generation == nullptr || out_client_slot == nullptr || out_client_generation == nullptr ||
        handle.value == 0) {
        return false;
    }
    const std::uint8_t encoded_slot = static_cast<std::uint8_t>(handle.value & 0x0FU);
    const std::uint8_t client_slot = static_cast<std::uint8_t>((handle.value >> 4U) & 0x03U);
    if (encoded_slot >= m_flows.size() || client_slot >= m_clients.size()) {
        return false;
    }
    *out_slot = encoded_slot;
    *out_generation = static_cast<std::uint32_t>((handle.value >> 8U) & 0x00FFFFFFU);
    *out_client_slot = client_slot;
    *out_client_generation = static_cast<std::uint32_t>(handle.value >> 32U);
    return *out_generation != 0 && *out_client_generation != 0;
}

void TunnelFlowPlane::ClearExpiredTombstones(wgnx::platform::ktime_t now) {
    for (ReverseTupleTombstone& tombstone : m_tombstones) {
        if (tombstone.occupied && tombstone.expires_at <= now) {
            tombstone = {};
        }
    }
}

bool TunnelFlowPlane::HasTombstoneReservation(wgnx::platform::ktime_t now) {
    ClearExpiredTombstones(now);
    const std::size_t free_tombstones = static_cast<std::size_t>(
        std::count_if(m_tombstones.begin(), m_tombstones.end(), [](const ReverseTupleTombstone& tombstone) { return !tombstone.occupied; })
    );
    const std::size_t live_flows = static_cast<std::size_t>(std::count_if(m_flows.begin(), m_flows.end(), [](const FlowSlot& flow) {
        return flow.allocated && !flow.closed;
    }));
    // Every live flow must be able to reserve a tombstone when it closes.
    return free_tombstones > live_flows;
}

std::uint32_t TunnelFlowPlane::AllocateFlowGeneration() {
    constexpr std::uint32_t GenerationMask = 0x00FFFFFFU;
    const std::uint32_t generation = m_next_flow_generation & GenerationMask;
    ++m_next_flow_generation;
    if ((m_next_flow_generation & GenerationMask) == 0) {
        ++m_next_flow_generation;
    }
    return generation == 0 ? AllocateFlowGeneration() : generation;
}

bool TunnelFlowPlane::AllocateVirtualTuple(const wgnx::tunnel::Ipv4Endpoint& remote, std::uint16_t* out_port, wgnx::platform::ktime_t now) {
    if (out_port == nullptr) {
        return false;
    }
    ClearExpiredTombstones(now);
    for (std::uint32_t tries = 0; tries < 16384; ++tries) {
        const std::uint16_t port = m_next_virtual_source_port;
        ++m_next_virtual_source_port;
        if (m_next_virtual_source_port < 49152) {
            m_next_virtual_source_port = 49152;
        }
        bool in_use = false;
        for (const FlowSlot& flow : m_flows) {
            if (flow.allocated && !flow.closed && flow.virtual_source_port == port && flow.tunnel_source == m_tunnel_source &&
                EndpointEqual(flow.remote, remote)) {
                in_use = true;
                break;
            }
        }
        if (!in_use && !IsTombstoned(m_tunnel_source, port, remote, now)) {
            *out_port = port;
            return true;
        }
    }
    return false;
}

void TunnelFlowPlane::QuarantineTuple(const FlowSlot& flow, wgnx::platform::ktime_t now) {
    if (flow.virtual_source_port == 0) {
        return;
    }
    ClearExpiredTombstones(now);
    auto slot =
        std::find_if(m_tombstones.begin(), m_tombstones.end(), [](const ReverseTupleTombstone& tombstone) { return !tombstone.occupied; });
    if (slot == m_tombstones.end()) {
        return;
    }
    *slot = {
        .occupied = true,
        .tunnel_destination = flow.tunnel_source,
        .tunnel_destination_port = flow.virtual_source_port,
        .remote = flow.remote,
        .expires_at = now + ReverseTupleQuarantineNs,
    };
}

bool TunnelFlowPlane::IsTombstoned(
    const std::array<std::uint8_t, 4>& tunnel_destination,
    std::uint16_t tunnel_destination_port,
    const wgnx::tunnel::Ipv4Endpoint& remote,
    wgnx::platform::ktime_t now
) const {
    return std::any_of(m_tombstones.begin(), m_tombstones.end(), [&](const ReverseTupleTombstone& tombstone) {
        return tombstone.occupied && tombstone.expires_at > now && tombstone.tunnel_destination == tunnel_destination &&
               tombstone.tunnel_destination_port == tunnel_destination_port && EndpointEqual(tombstone.remote, remote);
    });
}

std::uint8_t TunnelFlowPlane::AllocateInboundSlab() {
    for (std::size_t index = 0; index < m_inbound_slabs.size(); ++index) {
        if (!m_inbound_slabs[index].allocated) {
            m_inbound_slabs[index].allocated = true;
            return static_cast<std::uint8_t>(index);
        }
    }
    return InvalidSlabSlot;
}

void TunnelFlowPlane::ReleaseInboundSlab(std::uint8_t slot) {
    if (slot < m_inbound_slabs.size()) {
        m_inbound_slabs[slot] = {};
    }
}

void TunnelFlowPlane::RemoveFlowCompletions(std::size_t flow_slot, ClientSlot& client) {
    std::array<CompletionEntry, wgnx::tunnel::CompletionQueueCapacity> retained{};
    std::uint8_t retained_count = 0;
    std::uint8_t retained_data_count = 0;
    const wgnx::tunnel::FlowHandle flow_handle = MakeFlowHandle(flow_slot, m_flows[flow_slot]);
    for (std::size_t index = 0; index < client.completion_count; ++index) {
        const CompletionEntry* entry = CompletionAt(client, index);
        if (entry != nullptr && entry->record.flow.value == flow_handle.value && entry->inbound_slab_slot != InvalidSlabSlot) {
            ReleaseInboundSlab(entry->inbound_slab_slot);
            continue;
        }
        if (entry != nullptr) {
            retained[retained_count++] = *entry;
            if (entry->inbound_slab_slot != InvalidSlabSlot) {
                ++retained_data_count;
            }
        }
    }
    client.completions = retained;
    client.completion_head = 0;
    client.completion_count = retained_count;
    client.data_completion_count = retained_data_count;
}

void TunnelFlowPlane::CloseFlowSlot(
    std::size_t flow_slot, wgnx::tunnel::FlowTerminalReason reason, wgnx::platform::ktime_t now, bool notify
) {
    FlowSlot& flow = m_flows[flow_slot];
    if (!flow.allocated || flow.closed) {
        return;
    }
    if (flow.pending) {
        flow = {};
        return;
    }
    const TunnelClientId client{.slot = flow.client_slot, .generation = flow.client_generation};
    if (ClientSlot* client_slot = FindClient(client); client_slot != nullptr) {
        RemoveFlowCompletions(flow_slot, *client_slot);
    }
    QuarantineTuple(flow, now);
    flow.closed = true;
    flow.state = wgnx::tunnel::FlowState::Closed;
    flow.terminal_reason = reason;
    flow.inbound_occupancy = 0;
    flow.last_activity_at = now;
    char remote_text[16] = {};
    char tunnel_source_text[16] = {};
    FormatIpv4Text(
        {flow.remote.address[0], flow.remote.address[1], flow.remote.address[2], flow.remote.address[3]},
        remote_text,
        sizeof(remote_text)
    );
    FormatIpv4Text(flow.tunnel_source, tunnel_source_text, sizeof(tunnel_source_text));
    logger::Log(
        "Closed tunnel %s flow=%llu slot=%zu client=%u/%u peer=%u activation=%u policy=%u reason=%u remote=%s:%u "
        "tunnel_source=%s virtual_source_port=%u send_attempts=%llu send_admitted=%llu send_queue_full=%llu "
        "inbound_delivered=%llu inbound_dropped=%llu",
        flow.kind == wgnx::tunnel::FlowKind::Tcp ? "TCP" : "UDP",
        static_cast<unsigned long long>(MakeFlowHandle(flow_slot, flow).value),
        flow_slot,
        static_cast<unsigned int>(flow.client_slot),
        flow.client_generation,
        flow.peer.peer_index.Value(),
        flow.peer.activation_generation.Value(),
        flow.policy_generation,
        static_cast<unsigned int>(reason),
        remote_text,
        static_cast<unsigned int>(flow.remote.port),
        tunnel_source_text,
        static_cast<unsigned int>(flow.virtual_source_port),
        static_cast<unsigned long long>(flow.send_attempts),
        static_cast<unsigned long long>(flow.send_admitted),
        static_cast<unsigned long long>(flow.send_queue_full),
        static_cast<unsigned long long>(flow.inbound_delivered),
        static_cast<unsigned long long>(flow.inbound_dropped)
    );
    if (notify) {
        wgnx::tunnel::CompletionRecord completion{};
        completion.type = wgnx::tunnel::CompletionType::FlowStateChanged;
        completion.status = wgnx::tunnel::ProtocolStatus::FlowClosed;
        completion.flow = MakeFlowHandle(flow_slot, flow);
        completion.peer_activation_generation = flow.peer.activation_generation.Value();
        completion.routing_policy_generation = flow.policy_generation;
        completion.flow_state = wgnx::tunnel::FlowState::Closed;
        completion.terminal_reason = reason;
        completion.flow_kind = flow.kind;
        EnqueueControlCompletion(client, completion);
    }
}

bool TunnelFlowPlane::EnqueueDataCompletion(std::size_t flow_slot, std::uint8_t inbound_slab_slot) {
    FlowSlot& flow = m_flows[flow_slot];
    const TunnelClientId client_id{.slot = flow.client_slot, .generation = flow.client_generation};
    ClientSlot* client = FindClient(client_id);
    if (client == nullptr || client->data_completion_count >= DataCompletionCapacity ||
        client->completion_count >= wgnx::tunnel::CompletionQueueCapacity) {
        ReleaseInboundSlab(inbound_slab_slot);
        if (flow.inbound_occupancy > 0) {
            --flow.inbound_occupancy;
        }
        return false;
    }
    const bool was_empty = client->completion_count == 0;
    const std::size_t insert = (client->completion_head + client->completion_count) % client->completions.size();
    client->completions[insert] = {
        .record =
            {
                .type = flow.kind == wgnx::tunnel::FlowKind::Tcp ? wgnx::tunnel::CompletionType::InboundTcpStream
                                                                 : wgnx::tunnel::CompletionType::InboundUdpDatagram,
                .status = wgnx::tunnel::ProtocolStatus::Success,
                .flow = MakeFlowHandle(flow_slot, flow),
                .remote = flow.remote,
                .payload_offset = 0,
                .payload_size = m_inbound_slabs[inbound_slab_slot].size,
                .peer_activation_generation = flow.peer.activation_generation.Value(),
                .routing_policy_generation = flow.policy_generation,
                .flow_state = flow.state,
                .terminal_reason = wgnx::tunnel::FlowTerminalReason::None,
                .flow_kind = flow.kind,
            },
        .inbound_slab_slot = inbound_slab_slot,
    };
    ++client->completion_count;
    ++client->data_completion_count;
    NotifyIfNeeded(*client, was_empty);
    return true;
}

void TunnelFlowPlane::EnqueueControlCompletion(TunnelClientId client_id, const wgnx::tunnel::CompletionRecord& completion) {
    ClientSlot* client = FindClient(client_id);
    if (client == nullptr) {
        return;
    }
    for (std::size_t index = 0; index < client->completion_count; ++index) {
        CompletionEntry* entry = CompletionAt(*client, index);
        if (entry != nullptr && entry->inbound_slab_slot == InvalidSlabSlot && entry->record.type == completion.type &&
            entry->record.flow.value == completion.flow.value) {
            entry->record = completion;
            return;
        }
    }
    if (client->completion_count >= wgnx::tunnel::CompletionQueueCapacity) {
        return;
    }
    const bool was_empty = client->completion_count == 0;
    const std::size_t insert = (client->completion_head + client->completion_count) % client->completions.size();
    client->completions[insert] = {.record = completion};
    ++client->completion_count;
    NotifyIfNeeded(*client, was_empty);
}

void TunnelFlowPlane::EnqueuePolicyChanged() {
    for (std::size_t index = 0; index < m_clients.size(); ++index) {
        const ClientSlot& client = m_clients[index];
        if (!client.allocated) {
            continue;
        }
        wgnx::tunnel::CompletionRecord completion{};
        completion.type = wgnx::tunnel::CompletionType::PolicyChanged;
        completion.status = wgnx::tunnel::ProtocolStatus::Success;
        completion.routing_policy_generation = m_policy_generation;
        EnqueueControlCompletion({.slot = static_cast<std::uint8_t>(index), .generation = client.generation}, completion);
    }
}

void TunnelFlowPlane::NotifyIfNeeded(ClientSlot& client, bool was_empty) {
    if (was_empty && client.notifier != nullptr) {
        client.notifier(client.notifier_context);
    }
}

bool TunnelFlowPlane::RemoveCompletionFront(ClientSlot& client, CompletionEntry* out) {
    if (client.completion_count == 0) {
        return false;
    }
    CompletionEntry& entry = client.completions[client.completion_head];
    if (out != nullptr) {
        *out = entry;
    }
    if (entry.inbound_slab_slot != InvalidSlabSlot && client.data_completion_count > 0) {
        --client.data_completion_count;
    }
    entry = {};
    client.completion_head = static_cast<std::uint8_t>((client.completion_head + 1U) % client.completions.size());
    --client.completion_count;
    return true;
}

TunnelFlowPlane::CompletionEntry* TunnelFlowPlane::CompletionAt(ClientSlot& client, std::size_t index) {
    return index < client.completion_count ? &client.completions[(client.completion_head + index) % client.completions.size()] : nullptr;
}

const TunnelFlowPlane::CompletionEntry* TunnelFlowPlane::CompletionAt(const ClientSlot& client, std::size_t index) const {
    return index < client.completion_count ? &client.completions[(client.completion_head + index) % client.completions.size()] : nullptr;
}

bool TunnelFlowPlane::ParseAndNormalizePolicy(const TunnelPolicyInput& input) {
    m_routes = {};
    m_route_count = 0;
    m_tunnel_source = {};
    m_policy_peer = {};
    if (!input.selected || input.configuration == nullptr || input.peer.activation_generation.IsZero()) {
        return false;
    }
    const std::uint16_t effective_inner_mtu = wgnx::tunnel::ResolveEffectiveInnerMtu(input.configuration->mtu);
    if (!wgnx::tunnel::IsValidEffectiveInnerMtu(effective_inner_mtu)) {
        return false;
    }
    std::array<std::uint8_t, 4> source{};
    std::uint8_t source_prefix = 0;
    if (!ParseIpv4Cidr(input.configuration->address.data(), &source, &source_prefix)) {
        return false;
    }

    const char* cursor = input.configuration->allowed_ips.data();
    std::uint64_t route_identifier = 1;
    while (*cursor != '\0') {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == ',') {
            ++cursor;
        }
        const char* start = cursor;
        while (*cursor != '\0' && *cursor != ',') {
            ++cursor;
        }
        const std::size_t length = static_cast<std::size_t>(cursor - start);
        if (length == 0 || length >= 32 || m_route_count >= m_routes.size()) {
            return false;
        }
        std::array<char, 32> item{};
        std::memcpy(item.data(), start, length);
        std::array<std::uint8_t, 4> address{};
        std::uint8_t prefix = 0;
        if (!ParseIpv4Cidr(item.data(), &address, &prefix)) {
            return false;
        }
        for (std::size_t byte = 0; byte < address.size(); ++byte) {
            const std::size_t bits_before = byte * 8U;
            const std::uint8_t mask = prefix >= bits_before + 8U ? 0xFFU
                                      : prefix <= bits_before    ? 0U
                                                                 : static_cast<std::uint8_t>(0xFFU << (8U - (prefix - bits_before)));
            address[byte] &= mask;
        }
        m_routes[m_route_count++] = {.network = address, .prefix_length = prefix, .route_identifier = route_identifier++};
    }
    if (m_route_count == 0) {
        return false;
    }
    std::sort(m_routes.begin(), m_routes.begin() + m_route_count, [](const NormalizedRoute& lhs, const NormalizedRoute& rhs) {
        if (lhs.prefix_length != rhs.prefix_length) {
            return lhs.prefix_length > rhs.prefix_length;
        }
        if (lhs.network != rhs.network) {
            return lhs.network < rhs.network;
        }
        return lhs.route_identifier < rhs.route_identifier;
    });
    m_tunnel_source = source;
    m_policy_peer = input.peer;
    m_policy_leak_protection = input.configuration->leak_protection;
    m_effective_inner_mtu = effective_inner_mtu;
    return true;
}

bool TunnelFlowPlane::ParseIpv4Cidr(const char* text, std::array<std::uint8_t, 4>* out_address, std::uint8_t* out_prefix) {
    if (text == nullptr || out_address == nullptr || out_prefix == nullptr) {
        return false;
    }
    std::array<std::uint8_t, 4> address{};
    const char* cursor = text;
    for (std::size_t index = 0; index < address.size(); ++index) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
        unsigned int value = 0;
        do {
            value = (value * 10U) + static_cast<unsigned int>(*cursor - '0');
            if (value > 255U) {
                return false;
            }
            ++cursor;
        } while (*cursor >= '0' && *cursor <= '9');
        address[index] = static_cast<std::uint8_t>(value);
        if (index + 1 < address.size()) {
            if (*cursor != '.') {
                return false;
            }
            ++cursor;
        }
    }
    if (*cursor != '/') {
        return false;
    }
    ++cursor;
    if (*cursor < '0' || *cursor > '9') {
        return false;
    }
    unsigned int prefix = 0;
    do {
        prefix = (prefix * 10U) + static_cast<unsigned int>(*cursor - '0');
        if (prefix > 32U) {
            return false;
        }
        ++cursor;
    } while (*cursor >= '0' && *cursor <= '9');
    while (*cursor == ' ' || *cursor == '\t') {
        ++cursor;
    }
    if (*cursor != '\0') {
        return false;
    }
    *out_address = address;
    *out_prefix = static_cast<std::uint8_t>(prefix);
    return true;
}

bool TunnelFlowPlane::RouteMatches(const NormalizedRoute& route, const std::uint8_t address[4]) {
    for (std::size_t byte = 0; byte < route.network.size(); ++byte) {
        const std::size_t bits_before = byte * 8U;
        const std::uint8_t mask = route.prefix_length >= bits_before + 8U ? 0xFFU
                                  : route.prefix_length <= bits_before
                                      ? 0U
                                      : static_cast<std::uint8_t>(0xFFU << (8U - (route.prefix_length - bits_before)));
        if ((route.network[byte] & mask) != (address[byte] & mask)) {
            return false;
        }
    }
    return true;
}

const TunnelFlowPlane::NormalizedRoute* TunnelFlowPlane::SelectRoute(const wgnx::tunnel::Ipv4Endpoint& remote) const {
    if (!m_policy_available) {
        return nullptr;
    }
    for (std::size_t index = 0; index < m_route_count; ++index) {
        if (RouteMatches(m_routes[index], remote.address)) {
            return &m_routes[index];
        }
    }
    return nullptr;
}

} // namespace wgnx::sysmodule::runtime
