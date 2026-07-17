#pragma once

#include "wireguard/inner_packet.hpp"

#include <cstddef>
#include <cstdint>

namespace wgnx::sysmodule::runtime {

using PacketConsumerId = std::uint64_t;

class PacketTransport {
public:
    virtual ~PacketTransport() = default;

    virtual PacketConsumerId ConsumerId() const = 0;
    virtual bool AcceptsDelivery(wireguard::InnerIpVersion version) const = 0;
    virtual bool IsOwnedBy(PacketConsumerId consumer_id) const = 0;
    virtual std::size_t Claim(PacketConsumerId consumer_id) = 0;
    virtual std::size_t Release() = 0;

    virtual wireguard::QueuePushResult PushReceived(
        const wireguard::InnerPacketRecord &record) = 0;
    virtual const wireguard::InnerPacketRecord *FrontReceived() const = 0;
    virtual bool PopReceived(
        wireguard::InnerPacketRecord *out,
        wireguard::QueueDisposition disposition) = 0;

    virtual std::size_t ReceivedSize() const = 0;
    virtual std::size_t ReceivedCapacity() const = 0;
    virtual const wireguard::QueueStatistics &Statistics() const = 0;
};

} // namespace wgnx::sysmodule::runtime
