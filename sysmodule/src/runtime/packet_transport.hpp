#pragma once

#include "runtime/domain_types.hpp"
#include "wireguard/inner_packet.hpp"

#include <cstddef>
#include <cstdint>

namespace wgnx::sysmodule::runtime {

class PacketTransport {
public:
    virtual ~PacketTransport() = default;

    [[nodiscard]] virtual ProcessId ConsumerId() const = 0;
    virtual bool AcceptsDelivery(wireguard::InnerIpVersion version) const = 0;
    [[nodiscard]] virtual bool IsOwnedBy(ProcessId consumer_id) const = 0;
    [[nodiscard]] virtual std::size_t Claim(ProcessId consumer_id) = 0;
    [[nodiscard]] virtual std::size_t Release() = 0;

    [[nodiscard]] virtual wireguard::QueuePushResult PushReceived(
        const wireguard::InnerPacketRecord &record) = 0;
    [[nodiscard]] virtual const wireguard::InnerPacketRecord *FrontReceived() const = 0;
    [[nodiscard]] virtual bool PopReceived(
        wireguard::InnerPacketRecord *out,
        wireguard::QueueDisposition disposition) = 0;

    [[nodiscard]] virtual std::size_t ReceivedSize() const = 0;
    [[nodiscard]] virtual std::size_t ReceivedCapacity() const = 0;
    virtual const wireguard::QueueStatistics &Statistics() const = 0;
};

} // namespace wgnx::sysmodule::runtime
