#pragma once

#include "runtime/domain_types.hpp"
#include "runtime/resource_observability.hpp"
#include "wgnx/platform/udp.hpp"
#include "wgnx/resource_budget.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace wgnx::sysmodule::runtime {

struct UdpRebindRequest {
    PeerIndex peer_index{};
    ActivationGeneration activation_generation{};
};

enum class UdpRebindQueueResult : std::uint8_t {
    Scheduled = 0,
    Replaced,
};

class UdpRebindQueue {
public:
    static constexpr std::size_t RequestCapacity =
        wgnx::resource_budget::UdpRebindRequestSlots;

    [[nodiscard]] UdpRebindQueueResult Queue(const UdpRebindRequest &request) {
        const bool scheduled = !m_pending;
        m_accounting.RecordAdmission(m_pending);
        m_request = request;
        m_pending = true;
        return scheduled
            ? UdpRebindQueueResult::Scheduled
            : UdpRebindQueueResult::Replaced;
    }

    [[nodiscard]] std::optional<UdpRebindRequest> Take() {
        if (!m_pending) {
            return std::nullopt;
        }
        m_pending = false;
        m_accounting.RecordTake();
        return m_request;
    }

    bool IsPending(const UdpRebindRequest &request) const {
        return m_pending && m_request.peer_index == request.peer_index &&
               m_request.activation_generation == request.activation_generation;
    }

    const PendingSlotStatistics &Statistics() const {
        return m_accounting.Statistics();
    }

private:
    static_assert(RequestCapacity == PendingSlotStatistics::Capacity);

    UdpRebindRequest m_request{};
    PendingSlotAccounting m_accounting{};
    bool m_pending{false};
};

class UdpBinding {
public:
    struct Snapshot {
        wgnx::platform::endpoint endpoint{};
        std::array<char, 64> endpoint_text{};
        wgnx::platform::socket_handle socket{wgnx::platform::InvalidSocket};
        SocketGeneration generation{};
        bool has_endpoint{false};
        bool suspended{false};

        bool IsOpen() const { return socket != wgnx::platform::InvalidSocket; }
        bool Matches(
            SocketGeneration expected_generation,
            wgnx::platform::socket_handle expected_socket) const {
            return generation == expected_generation && socket == expected_socket;
        }
    };

    constexpr UdpBinding() = default;
    ~UdpBinding() = default;

    UdpBinding(const UdpBinding &) = delete;
    UdpBinding &operator=(const UdpBinding &) = delete;
    UdpBinding(UdpBinding &&) = delete;
    UdpBinding &operator=(UdpBinding &&) = delete;

    void SetEndpoint(const wgnx::platform::endpoint &endpoint, const char *text);
    void ClearEndpoint();
    void AdoptOpenSocket(
        const wgnx::platform::endpoint &endpoint,
        const char *text,
        SocketGeneration generation,
        wgnx::platform::socket_handle socket);
    wgnx::platform::socket_handle ReleaseAndSuspend();
    wgnx::platform::socket_handle ReleaseSocket();

    bool HasEndpoint() const { return m_has_endpoint; }
    bool IsOpen() const { return m_socket != wgnx::platform::InvalidSocket; }
    bool IsSuspended() const { return m_suspended; }
    bool Matches(SocketGeneration generation, wgnx::platform::socket_handle socket) const {
        return m_generation == generation && m_socket == socket;
    }

    const wgnx::platform::endpoint &Endpoint() const { return m_endpoint; }
    const char *EndpointText() const { return m_endpoint_text; }
    wgnx::platform::socket_handle Socket() const { return m_socket; }
    SocketGeneration Generation() const { return m_generation; }

    struct SendSnapshot {
        wgnx::platform::endpoint endpoint{};
        wgnx::platform::socket_handle socket{wgnx::platform::InvalidSocket};
        SocketGeneration generation{};
    };

    [[nodiscard]] bool SnapshotForSend(SendSnapshot &out) const;
    Snapshot StateSnapshot() const;

private:
    wgnx::platform::endpoint m_endpoint{};
    char m_endpoint_text[64]{};
    wgnx::platform::socket_handle m_socket{wgnx::platform::InvalidSocket};
    SocketGeneration m_generation{};
    bool m_has_endpoint{false};
    bool m_suspended{false};
};

static_assert(
    sizeof(UdpRebindQueue) <=
    wgnx::resource_budget::MaximumUdpRebindQueueBytes);

} // namespace wgnx::sysmodule::runtime
