#pragma once

#include <compare>
#include <concepts>
#include <cstdint>
#include <type_traits>

namespace wgnx::sysmodule::runtime {

template<typename Tag, std::unsigned_integral Representation>
class DomainId {
public:
    using representation_type = Representation;

    constexpr DomainId() = default;
    explicit constexpr DomainId(Representation value) : m_value(value) {}

    constexpr Representation Value() const { return m_value; }
    constexpr bool IsZero() const { return m_value == 0; }

    friend constexpr bool operator==(DomainId, DomainId) = default;
    friend constexpr auto operator<=>(DomainId, DomainId) = default;

private:
    Representation m_value{0};
};

struct PeerIndexTag;
struct ActivationGenerationTag;
struct SocketGenerationTag;
struct DatagramGenerationTag;
struct PacketGenerationTag;
struct PacketIdTag;
struct ProcessIdTag;
struct AutoStartRequestGenerationTag;

using PeerIndex = DomainId<PeerIndexTag, std::uint32_t>;
using ActivationGeneration = DomainId<ActivationGenerationTag, std::uint32_t>;
using SocketGeneration = DomainId<SocketGenerationTag, std::uint32_t>;
using DatagramGeneration = DomainId<DatagramGenerationTag, std::uint32_t>;
using PacketGeneration = DomainId<PacketGenerationTag, std::uint32_t>;
using PacketId = DomainId<PacketIdTag, std::uint64_t>;
using ProcessId = DomainId<ProcessIdTag, std::uint64_t>;
using AutoStartRequestGeneration = DomainId<AutoStartRequestGenerationTag, std::uint32_t>;

template<typename Id>
concept DomainIdentity =
    std::same_as<Id, PeerIndex> ||
    std::same_as<Id, ActivationGeneration> ||
    std::same_as<Id, SocketGeneration> ||
    std::same_as<Id, DatagramGeneration> ||
    std::same_as<Id, PacketGeneration> ||
    std::same_as<Id, PacketId> ||
    std::same_as<Id, ProcessId> ||
    std::same_as<Id, AutoStartRequestGeneration>;

template<typename Id>
concept MonotonicIdentity =
    std::same_as<Id, ActivationGeneration> ||
    std::same_as<Id, SocketGeneration> ||
    std::same_as<Id, DatagramGeneration> ||
    std::same_as<Id, PacketGeneration> ||
    std::same_as<Id, PacketId> ||
    std::same_as<Id, AutoStartRequestGeneration>;

template<MonotonicIdentity Id>
constexpr Id AllocateGeneration(Id &next) {
    using Representation = typename Id::representation_type;
    const Id allocated = next;
    Representation following = static_cast<Representation>(next.Value() + 1);
    if (following == 0) {
        following = 1;
    }
    next = Id{following};
    return allocated;
}

static_assert(std::is_trivially_copyable_v<PeerIndex>);
static_assert(std::is_trivially_copyable_v<ActivationGeneration>);
static_assert(std::is_trivially_copyable_v<SocketGeneration>);
static_assert(std::is_trivially_copyable_v<DatagramGeneration>);
static_assert(std::is_trivially_copyable_v<PacketGeneration>);
static_assert(std::is_trivially_copyable_v<PacketId>);
static_assert(std::is_trivially_copyable_v<ProcessId>);
static_assert(std::is_trivially_copyable_v<AutoStartRequestGeneration>);
static_assert(sizeof(PeerIndex) == sizeof(std::uint32_t));
static_assert(sizeof(PacketId) == sizeof(std::uint64_t));

} // namespace wgnx::sysmodule::runtime
