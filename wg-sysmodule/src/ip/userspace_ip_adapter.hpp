#pragma once

#include "wgnx/protocol.hpp"
#include "wgnx/tunnel_protocol.hpp"

extern "C" {
#include <lwip/netif.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>
}

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace wgnx::sysmodule::ip {

enum class UserspaceIpResult : std::uint8_t {
    Success = 0,
    NotInitialized,
    InvalidArgument,
    FlowQuotaExhausted,
    QueueFull,
    Stale,
    TransportError,
};

enum class UserspaceIpRejection : std::uint8_t {
    None = 0,
    PbufAllocation,
    OutboundCollector,
    InputValidation,
    InboundCollector,
};

struct UserspaceIpStatistics {
    std::uint32_t active_flows{};
    std::uint32_t flow_high_water{};
    std::uint32_t inbound_high_water{};
    std::uint64_t input_packets{};
    std::uint64_t input_rejections{};
    std::uint64_t fragment_inputs{};
    std::uint64_t reassembly_successes{};
    std::uint64_t callback_deliveries{};
    std::uint64_t callback_rejections{};
    std::uint64_t pbuf_rejections{};
    std::uint64_t outbound_collector_rejections{};
    std::uint64_t resets{};
    std::uint64_t collateral_fragment_resets{};
    std::uint64_t timeout_runs{};
    UserspaceIpRejection first_rejection{UserspaceIpRejection::None};
};

struct UserspaceIpFlow {
    std::uint64_t token{};
    wgnx::tunnel::Ipv4Endpoint local{};
    wgnx::tunnel::Ipv4Endpoint remote{};
};

enum class UserspaceIpFlowKind : std::uint8_t {
    Udp = 0,
    Tcp,
};

enum class UserspaceIpTcpEventType : std::uint8_t {
    Connected = 0,
    Writable,
    RemoteWriteClosed,
    Reset,
};

struct UserspaceIpTcpEvent {
    std::uint64_t token{};
    UserspaceIpTcpEventType type{};
    UserspaceIpResult result{};
};

struct UserspaceIpStreamData {
    std::uint64_t token{};
    std::array<std::uint8_t, wgnx::tunnel::MaximumTcpWriteStorageBytes> payload{};
    std::uint16_t size{};
};

struct UserspaceIpTcpReceiveAcknowledgement {
    std::uint64_t token{};
    std::uint16_t bytes{};
};

struct UserspaceIpPacket {
    std::array<std::uint8_t, wgnx::MaxInnerIpv4PacketSize> bytes{};
    std::uint16_t size{};
};

struct UserspaceIpDatagram {
    std::uint64_t token{};
    wgnx::tunnel::Ipv4Endpoint remote{};
    std::array<std::uint8_t, wgnx::tunnel::MaximumUdpPayloadStorageBytes> payload{};
    std::uint16_t size{};
};

class UserspaceIpAdapter {
  public:
    static constexpr std::size_t MaximumFlows = 16;
    static constexpr std::size_t OutboundPacketCapacity = 4;
    static constexpr std::size_t InboundDatagramCapacity = 4;
    static constexpr std::size_t InboundStreamCapacity = 4;
    static constexpr std::size_t TcpEventCapacity = 4;

    ~UserspaceIpAdapter();

    [[nodiscard]] bool Initialize(const std::array<std::uint8_t, 4>& local_address, std::uint16_t mtu);
    void Reset();
    [[nodiscard]] bool SetMtu(std::uint16_t mtu);
    [[nodiscard]] UserspaceIpResult OpenFlow(const UserspaceIpFlow& flow);
    [[nodiscard]] UserspaceIpResult OpenTcpFlow(const UserspaceIpFlow& flow);
    void CloseFlow(std::uint64_t token);
    [[nodiscard]] UserspaceIpResult Send(std::uint64_t token, std::span<const std::uint8_t> payload);
    [[nodiscard]] UserspaceIpResult WriteTcp(std::uint64_t token, std::span<const std::uint8_t> payload);
    [[nodiscard]] UserspaceIpResult ShutdownTcpWrite(std::uint64_t token);
    [[nodiscard]] UserspaceIpResult AcknowledgeTcpReceive(std::span<const UserspaceIpTcpReceiveAcknowledgement> acknowledgements);
    [[nodiscard]] UserspaceIpResult Input(std::span<const std::uint8_t> packet);
    void RunTimeouts();
    [[nodiscard]] std::uint32_t NextTimeoutDelayMs() const;

    void ClearOutboundPackets();
    void ClearInboundDatagrams();
    void ClearInboundStreams();
    void ClearTcpEvents();
    [[nodiscard]] std::span<const UserspaceIpPacket> OutboundPackets() const;
    [[nodiscard]] std::span<const UserspaceIpDatagram> InboundDatagrams() const;
    [[nodiscard]] std::span<const UserspaceIpStreamData> InboundStreams() const;
    [[nodiscard]] std::span<const UserspaceIpTcpEvent> TcpEvents() const;
    [[nodiscard]] bool HadInboundDatagramRejection() const;
    [[nodiscard]] bool HadInputRejection() const;
    [[nodiscard]] bool HasPendingInboundFragment() const;
    [[nodiscard]] const UserspaceIpStatistics& Statistics() const;
    [[nodiscard]] bool IsInitialized() const;
    [[nodiscard]] std::uint32_t Epoch() const;
    [[nodiscard]] static std::uint32_t InitializationCountForTests();

  private:
    struct FlowSlot {
        UserspaceIpAdapter* owner{};
        udp_pcb* pcb{};
        tcp_pcb* tcp{};
        std::uint64_t token{};
        UserspaceIpFlowKind kind{};
        bool tcp_connected{};
        bool tcp_local_write_closed{};
        bool active{};
    };

    [[nodiscard]] FlowSlot* FindFlow(std::uint64_t token);
    [[nodiscard]] bool PushTcpEvent(FlowSlot& flow, UserspaceIpTcpEventType type, UserspaceIpResult result);
    [[nodiscard]] static err_t InitializeNetif(netif* netif);
    [[nodiscard]] static err_t Output(netif* netif, pbuf* packet, const ip4_addr_t* destination);
    static void Receive(void* context, udp_pcb* pcb, pbuf* packet, const ip_addr_t* remote, u16_t remote_port);
    static err_t TcpConnected(void* context, tcp_pcb* pcb, err_t error);
    static err_t TcpReceive(void* context, tcp_pcb* pcb, pbuf* packet, err_t error);
    static err_t TcpSent(void* context, tcp_pcb* pcb, u16_t length);
    static err_t TcpPoll(void* context, tcp_pcb* pcb);
    static void TcpError(void* context, err_t error);
    void ClearReassembly();
    void RecordRejection(UserspaceIpRejection rejection);

    netif m_netif{};
    std::array<FlowSlot, MaximumFlows> m_flows{};
    std::array<UserspaceIpPacket, OutboundPacketCapacity> m_outbound_packets{};
    std::array<UserspaceIpDatagram, InboundDatagramCapacity> m_inbound_datagrams{};
    std::array<UserspaceIpStreamData, InboundStreamCapacity> m_inbound_streams{};
    std::array<UserspaceIpTcpEvent, TcpEventCapacity> m_tcp_events{};
    std::array<std::uint8_t, 4> m_local_address{};
    std::uint16_t m_mtu{};
    std::uint8_t m_outbound_packet_count{};
    std::uint8_t m_inbound_datagram_count{};
    std::uint8_t m_inbound_stream_count{};
    std::uint8_t m_tcp_event_count{};
    std::uint32_t m_epoch{};
    UserspaceIpStatistics m_statistics{};
    bool m_inbound_datagram_rejected{};
    bool m_input_rejected{};
    bool m_pending_inbound_fragment{};
    bool m_netif_added{};
};

} // namespace wgnx::sysmodule::ip
