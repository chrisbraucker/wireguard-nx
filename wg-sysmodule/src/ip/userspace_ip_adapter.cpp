#include "ip/userspace_ip_adapter.hpp"

extern "C" {
#include <lwip/init.h>
#include <lwip/ip4.h>
#include <lwip/ip4_frag.h>
#include <lwip/pbuf.h>
#include <lwip/stats.h>
#include <lwip/timeouts.h>
}

#include <algorithm>

namespace wgnx::sysmodule::ip {

namespace {

bool g_lwip_initialized{};
std::uint32_t g_lwip_initialization_count{};
UserspaceIpAdapter* g_lwip_owner{};

void SetAddress(ip4_addr_t* destination, const std::uint8_t address[4]) {
    IP4_ADDR(destination, address[0], address[1], address[2], address[3]);
}

} // namespace

UserspaceIpAdapter::~UserspaceIpAdapter() {
    Reset();
}

bool UserspaceIpAdapter::Initialize(const std::array<std::uint8_t, 4>& local_address, std::uint16_t mtu) {
    if (m_netif_added || g_lwip_owner != nullptr || mtu < wgnx::tunnel::MinimumEffectiveInnerMtu ||
        mtu > wgnx::tunnel::MaximumEffectiveInnerMtu) {
        return false;
    }
    if (!g_lwip_initialized) {
        lwip_init();
        g_lwip_initialized = true;
        ++g_lwip_initialization_count;
    }

    m_local_address = local_address;
    m_mtu = mtu;
    ip4_addr_t address{};
    ip4_addr_t netmask{};
    ip4_addr_t gateway{};
    SetAddress(&address, m_local_address.data());
    IP4_ADDR(&netmask, 255, 255, 255, 0);
    IP4_ADDR(&gateway, 0, 0, 0, 0);
    if (netif_add(&m_netif, &address, &netmask, &gateway, this, InitializeNetif, ip4_input) == nullptr) {
        return false;
    }
    g_lwip_owner = this;
    m_netif_added = true;
    netif_set_default(&m_netif);
    netif_set_up(&m_netif);
    netif_set_link_up(&m_netif);
    ++m_epoch;
    return true;
}

void UserspaceIpAdapter::Reset() {
    ++m_statistics.resets;
    if (m_pending_inbound_fragment) {
        ++m_statistics.collateral_fragment_resets;
    }
    for (FlowSlot& flow : m_flows) {
        if (flow.pcb != nullptr) {
            udp_recv(flow.pcb, nullptr, nullptr);
            udp_remove(flow.pcb);
        }
        flow = {};
    }
    m_statistics.active_flows = 0;
    if (m_netif_added) {
        netif_set_down(&m_netif);
        netif_set_link_down(&m_netif);
        netif_remove(&m_netif);
        m_netif = {};
        m_netif_added = false;
    }
    if (g_lwip_initialized) {
        ClearReassembly();
        sys_timeouts_init();
    }
    ClearOutboundPackets();
    ClearInboundDatagrams();
    if (g_lwip_owner == this) {
        g_lwip_owner = nullptr;
    }
    ++m_epoch;
}

bool UserspaceIpAdapter::SetMtu(std::uint16_t mtu) {
    if (!m_netif_added || mtu < wgnx::tunnel::MinimumEffectiveInnerMtu || mtu > wgnx::tunnel::MaximumEffectiveInnerMtu) {
        return false;
    }
    m_mtu = mtu;
    m_netif.mtu = mtu;
    return true;
}

UserspaceIpResult UserspaceIpAdapter::OpenFlow(const UserspaceIpFlow& flow) {
    if (!m_netif_added) {
        return UserspaceIpResult::NotInitialized;
    }
    if (flow.token == 0 || flow.local.port == 0 || flow.remote.port == 0 ||
        !std::equal(std::begin(flow.local.address), std::end(flow.local.address), m_local_address.begin())) {
        return UserspaceIpResult::InvalidArgument;
    }
    if (FindFlow(flow.token) != nullptr) {
        return UserspaceIpResult::InvalidArgument;
    }
    const auto slot = std::find_if(m_flows.begin(), m_flows.end(), [](const FlowSlot& candidate) { return !candidate.active; });
    if (slot == m_flows.end()) {
        RecordRejection(UserspaceIpRejection::PbufAllocation);
        return UserspaceIpResult::FlowQuotaExhausted;
    }

    udp_pcb* pcb = udp_new_ip_type(IPADDR_TYPE_V4);
    if (pcb == nullptr) {
        RecordRejection(UserspaceIpRejection::PbufAllocation);
        return UserspaceIpResult::FlowQuotaExhausted;
    }
    ip_addr_t local{};
    ip_addr_t remote{};
    ip4_addr_t local_ipv4{};
    ip4_addr_t remote_ipv4{};
    SetAddress(&local_ipv4, flow.local.address);
    SetAddress(&remote_ipv4, flow.remote.address);
    ip_addr_copy_from_ip4(local, local_ipv4);
    ip_addr_copy_from_ip4(remote, remote_ipv4);
    if (udp_bind(pcb, &local, flow.local.port) != ERR_OK || udp_connect(pcb, &remote, flow.remote.port) != ERR_OK) {
        udp_remove(pcb);
        return UserspaceIpResult::TransportError;
    }
    udp_bind_netif(pcb, &m_netif);
    *slot = {
        .owner = this,
        .pcb = pcb,
        .token = flow.token,
        .active = true,
    };
    udp_recv(pcb, Receive, std::addressof(*slot));
    ++m_statistics.active_flows;
    m_statistics.flow_high_water = std::max(m_statistics.flow_high_water, m_statistics.active_flows);
    return UserspaceIpResult::Success;
}

void UserspaceIpAdapter::CloseFlow(std::uint64_t token) {
    FlowSlot* flow = FindFlow(token);
    if (flow == nullptr) {
        return;
    }
    udp_recv(flow->pcb, nullptr, nullptr);
    udp_remove(flow->pcb);
    *flow = {};
    --m_statistics.active_flows;
}

UserspaceIpResult UserspaceIpAdapter::Send(std::uint64_t token, std::span<const std::uint8_t> payload) {
    FlowSlot* flow = FindFlow(token);
    if (flow == nullptr) {
        return m_netif_added ? UserspaceIpResult::InvalidArgument : UserspaceIpResult::NotInitialized;
    }
    if (payload.size() > wgnx::tunnel::MaximumUdpPayloadStorageBytes) {
        return UserspaceIpResult::InvalidArgument;
    }
    pbuf* packet = pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(payload.size()), PBUF_RAM);
    if (packet == nullptr) {
        ++m_statistics.pbuf_rejections;
        RecordRejection(UserspaceIpRejection::PbufAllocation);
        return UserspaceIpResult::QueueFull;
    }
    const err_t copied = pbuf_take(packet, payload.data(), static_cast<u16_t>(payload.size()));
    const err_t sent = copied == ERR_OK ? udp_send(flow->pcb, packet) : copied;
    pbuf_free(packet);
    if (sent == ERR_OK) {
        return UserspaceIpResult::Success;
    }
    return sent == ERR_MEM || sent == ERR_BUF ? UserspaceIpResult::QueueFull : UserspaceIpResult::TransportError;
}

UserspaceIpResult UserspaceIpAdapter::Input(std::span<const std::uint8_t> packet) {
    if (!m_netif_added) {
        return UserspaceIpResult::NotInitialized;
    }
    if (packet.empty() || packet.size() > wgnx::MaxInnerIpv4PacketSize) {
        return UserspaceIpResult::InvalidArgument;
    }
    pbuf* input = pbuf_alloc(PBUF_RAW, static_cast<u16_t>(packet.size()), PBUF_RAM);
    if (input == nullptr) {
        ++m_statistics.pbuf_rejections;
        RecordRejection(UserspaceIpRejection::PbufAllocation);
        return UserspaceIpResult::QueueFull;
    }
    if (pbuf_take(input, packet.data(), static_cast<u16_t>(packet.size())) != ERR_OK) {
        pbuf_free(input);
        ++m_statistics.pbuf_rejections;
        RecordRejection(UserspaceIpRejection::PbufAllocation);
        return UserspaceIpResult::QueueFull;
    }
    ++m_statistics.input_packets;
    const std::uint8_t previous_inbound_count = m_inbound_datagram_count;
    const u32_t previous_fragment_receives = lwip_stats.ip_frag.recv;
    const u32_t previous_ip_errors = lwip_stats.ip.err;
    const u32_t previous_ip_length_errors = lwip_stats.ip.lenerr;
    const u32_t previous_ip_checksum_errors = lwip_stats.ip.chkerr;
    const u32_t previous_ip_option_errors = lwip_stats.ip.opterr;
    const u32_t previous_udp_length_errors = lwip_stats.udp.lenerr;
    const u32_t previous_udp_checksum_errors = lwip_stats.udp.chkerr;
    const err_t delivered = m_netif.input(input, &m_netif);
    m_input_rejected = lwip_stats.ip.err != previous_ip_errors || lwip_stats.ip.lenerr != previous_ip_length_errors ||
                       lwip_stats.ip.chkerr != previous_ip_checksum_errors || lwip_stats.ip.opterr != previous_ip_option_errors ||
                       lwip_stats.udp.lenerr != previous_udp_length_errors || lwip_stats.udp.chkerr != previous_udp_checksum_errors;
    m_pending_inbound_fragment =
        !m_input_rejected && lwip_stats.ip_frag.recv != previous_fragment_receives && m_inbound_datagram_count == 0;
    if (lwip_stats.ip_frag.recv != previous_fragment_receives) {
        ++m_statistics.fragment_inputs;
    }
    if (m_inbound_datagram_count > previous_inbound_count) {
        m_statistics.reassembly_successes += lwip_stats.ip_frag.recv != previous_fragment_receives ? 1U : 0U;
    }
    if (m_input_rejected) {
        ++m_statistics.input_rejections;
        RecordRejection(UserspaceIpRejection::InputValidation);
    }
    if (delivered == ERR_OK) {
        return UserspaceIpResult::Success;
    }
    pbuf_free(input);
    return delivered == ERR_MEM || delivered == ERR_BUF ? UserspaceIpResult::QueueFull : UserspaceIpResult::TransportError;
}

void UserspaceIpAdapter::RunTimeouts() {
    if (m_netif_added) {
        ++m_statistics.timeout_runs;
        sys_check_timeouts();
    }
}

std::uint32_t UserspaceIpAdapter::NextTimeoutDelayMs() const {
    return m_netif_added ? sys_timeouts_sleeptime() : SYS_TIMEOUTS_SLEEPTIME_INFINITE;
}

void UserspaceIpAdapter::ClearOutboundPackets() {
    m_outbound_packet_count = 0;
}

void UserspaceIpAdapter::ClearInboundDatagrams() {
    m_inbound_datagram_count = 0;
    m_inbound_datagram_rejected = false;
    m_input_rejected = false;
    m_pending_inbound_fragment = false;
}

std::span<const UserspaceIpPacket> UserspaceIpAdapter::OutboundPackets() const {
    return std::span<const UserspaceIpPacket>(m_outbound_packets).first(m_outbound_packet_count);
}

std::span<const UserspaceIpDatagram> UserspaceIpAdapter::InboundDatagrams() const {
    return std::span<const UserspaceIpDatagram>(m_inbound_datagrams).first(m_inbound_datagram_count);
}

bool UserspaceIpAdapter::HadInboundDatagramRejection() const {
    return m_inbound_datagram_rejected;
}

bool UserspaceIpAdapter::HadInputRejection() const {
    return m_input_rejected;
}

bool UserspaceIpAdapter::HasPendingInboundFragment() const {
    return m_pending_inbound_fragment;
}

const UserspaceIpStatistics& UserspaceIpAdapter::Statistics() const {
    return m_statistics;
}

bool UserspaceIpAdapter::IsInitialized() const {
    return m_netif_added;
}

std::uint32_t UserspaceIpAdapter::Epoch() const {
    return m_epoch;
}

std::uint32_t UserspaceIpAdapter::InitializationCountForTests() {
    return g_lwip_initialization_count;
}

UserspaceIpAdapter::FlowSlot* UserspaceIpAdapter::FindFlow(std::uint64_t token) {
    const auto flow = std::find_if(m_flows.begin(), m_flows.end(), [token](const FlowSlot& candidate) {
        return candidate.active && candidate.token == token;
    });
    return flow == m_flows.end() ? nullptr : std::addressof(*flow);
}

err_t UserspaceIpAdapter::InitializeNetif(netif* netif) {
    auto* adapter = static_cast<UserspaceIpAdapter*>(netif->state);
    if (adapter == nullptr) {
        return ERR_ARG;
    }
    netif->name[0] = 'w';
    netif->name[1] = 'g';
    netif->output = Output;
    netif->mtu = adapter->m_mtu;
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

err_t UserspaceIpAdapter::Output(netif* netif, pbuf* packet, const ip4_addr_t*) {
    auto* adapter = static_cast<UserspaceIpAdapter*>(netif->state);
    if (adapter == nullptr || packet == nullptr || packet->tot_len > wgnx::MaxInnerIpv4PacketSize ||
        adapter->m_outbound_packet_count == adapter->m_outbound_packets.size()) {
        if (adapter != nullptr) {
            ++adapter->m_statistics.outbound_collector_rejections;
            adapter->RecordRejection(UserspaceIpRejection::OutboundCollector);
        }
        return ERR_BUF;
    }
    UserspaceIpPacket& output = adapter->m_outbound_packets[adapter->m_outbound_packet_count];
    if (pbuf_copy_partial(packet, output.bytes.data(), packet->tot_len, 0) != packet->tot_len) {
        return ERR_BUF;
    }
    output.size = packet->tot_len;
    ++adapter->m_outbound_packet_count;
    return ERR_OK;
}

void UserspaceIpAdapter::Receive(void* context, udp_pcb*, pbuf* packet, const ip_addr_t* remote, u16_t remote_port) {
    auto* flow = static_cast<FlowSlot*>(context);
    if (flow != nullptr && flow->owner != nullptr && flow->active && packet != nullptr && remote != nullptr) {
        UserspaceIpAdapter& adapter = *flow->owner;
        if (packet->tot_len > wgnx::tunnel::MaximumUdpPayloadStorageBytes ||
            adapter.m_inbound_datagram_count == adapter.m_inbound_datagrams.size()) {
            adapter.m_inbound_datagram_rejected = true;
            ++adapter.m_statistics.callback_rejections;
            adapter.RecordRejection(UserspaceIpRejection::InboundCollector);
        } else {
            UserspaceIpDatagram& datagram = adapter.m_inbound_datagrams[adapter.m_inbound_datagram_count];
            if (pbuf_copy_partial(packet, datagram.payload.data(), packet->tot_len, 0) == packet->tot_len) {
                datagram.token = flow->token;
                datagram.remote = {
                    .address =
                        {
                            ip4_addr1(ip_2_ip4(remote)),
                            ip4_addr2(ip_2_ip4(remote)),
                            ip4_addr3(ip_2_ip4(remote)),
                            ip4_addr4(ip_2_ip4(remote)),
                        },
                    .port = remote_port,
                    .reserved = 0,
                };
                datagram.size = packet->tot_len;
                ++adapter.m_inbound_datagram_count;
                ++adapter.m_statistics.callback_deliveries;
                adapter.m_statistics.inbound_high_water =
                    std::max<std::uint32_t>(adapter.m_statistics.inbound_high_water, adapter.m_inbound_datagram_count);
            } else {
                adapter.m_inbound_datagram_rejected = true;
                ++adapter.m_statistics.callback_rejections;
                adapter.RecordRejection(UserspaceIpRejection::InboundCollector);
            }
        }
    }
    if (packet != nullptr) {
        pbuf_free(packet);
    }
}

void UserspaceIpAdapter::ClearReassembly() {
    for (std::size_t index = 0; index <= IP_REASS_MAXAGE; ++index) {
        ip_reass_tmr();
    }
}

void UserspaceIpAdapter::RecordRejection(UserspaceIpRejection rejection) {
    if (m_statistics.first_rejection == UserspaceIpRejection::None) {
        m_statistics.first_rejection = rejection;
    }
}

} // namespace wgnx::sysmodule::ip
