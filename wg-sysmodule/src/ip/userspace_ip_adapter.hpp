#pragma once

#include "wgnx/protocol.hpp"
#include "wgnx/tunnel_protocol.hpp"

extern "C" {
#include <lwip/netif.h>
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
    TransportError,
};

struct UserspaceIpFlow {
    std::uint32_t token{};
    wgnx::tunnel::Ipv4Endpoint local{};
    wgnx::tunnel::Ipv4Endpoint remote{};
};

struct UserspaceIpPacket {
    std::array<std::uint8_t, wgnx::MaxInnerIpv4PacketSize> bytes{};
    std::uint16_t size{};
};

struct UserspaceIpDatagram {
    std::uint32_t token{};
    wgnx::tunnel::Ipv4Endpoint remote{};
    std::array<std::uint8_t, wgnx::tunnel::MaximumUdpPayloadStorageBytes> payload{};
    std::uint16_t size{};
};

class UserspaceIpAdapter {
  public:
    static constexpr std::size_t MaximumFlows = 16;
    static constexpr std::size_t OutboundPacketCapacity = 4;
    static constexpr std::size_t InboundDatagramCapacity = 4;

    ~UserspaceIpAdapter();

    [[nodiscard]] bool Initialize(const std::array<std::uint8_t, 4>& local_address, std::uint16_t mtu);
    void Reset();
    [[nodiscard]] bool SetMtu(std::uint16_t mtu);
    [[nodiscard]] UserspaceIpResult OpenFlow(const UserspaceIpFlow& flow);
    void CloseFlow(std::uint32_t token);
    [[nodiscard]] UserspaceIpResult Send(std::uint32_t token, std::span<const std::uint8_t> payload);
    [[nodiscard]] UserspaceIpResult Input(std::span<const std::uint8_t> packet);
    void RunTimeouts();

    void ClearOutboundPackets();
    void ClearInboundDatagrams();
    [[nodiscard]] std::span<const UserspaceIpPacket> OutboundPackets() const;
    [[nodiscard]] std::span<const UserspaceIpDatagram> InboundDatagrams() const;
    [[nodiscard]] bool IsInitialized() const;
    [[nodiscard]] std::uint32_t Epoch() const;
    [[nodiscard]] static std::uint32_t InitializationCountForTests();

  private:
    struct FlowSlot {
        UserspaceIpAdapter* owner{};
        udp_pcb* pcb{};
        std::uint32_t token{};
        bool active{};
    };

    [[nodiscard]] FlowSlot* FindFlow(std::uint32_t token);
    [[nodiscard]] static err_t InitializeNetif(netif* netif);
    [[nodiscard]] static err_t Output(netif* netif, pbuf* packet, const ip4_addr_t* destination);
    static void Receive(void* context, udp_pcb* pcb, pbuf* packet, const ip_addr_t* remote, u16_t remote_port);
    void ClearReassembly();

    netif m_netif{};
    std::array<FlowSlot, MaximumFlows> m_flows{};
    std::array<UserspaceIpPacket, OutboundPacketCapacity> m_outbound_packets{};
    std::array<UserspaceIpDatagram, InboundDatagramCapacity> m_inbound_datagrams{};
    std::array<std::uint8_t, 4> m_local_address{};
    std::uint16_t m_mtu{};
    std::uint8_t m_outbound_packet_count{};
    std::uint8_t m_inbound_datagram_count{};
    std::uint32_t m_epoch{};
    bool m_netif_added{};
};

} // namespace wgnx::sysmodule::ip
