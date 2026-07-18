#include "runtime/network_path_observer.hpp"

#include "development_config.hpp"
#include "logger.hpp"

#include <cstdio>

namespace wgnx::sysmodule::runtime {

namespace {

void FormatIpv4(std::uint32_t address, char *out, std::size_t out_size) {
    std::snprintf(
        out,
        out_size,
        "%u.%u.%u.%u",
        address & 0xffU,
        (address >> 8U) & 0xffU,
        (address >> 16U) & 0xffU,
        (address >> 24U) & 0xffU);
}

} // namespace

std::uint64_t NetworkPathObserver::BeginObservation() {
    const std::uint64_t sequence = m_next_sequence++;
    if (m_next_sequence == 0) {
        m_next_sequence = 1;
    }
    return sequence;
}

NetworkPathObservationOutcome NetworkPathObserver::Commit(
    const NetworkPathObservedEvent &event) {
    const bool changed = !m_has_last || event.snapshot != m_last;
    if (changed) {
        m_last = event.snapshot;
        m_has_last = true;

        char address[16]{};
        char subnet[16]{};
        char gateway[16]{};
        char primary_dns[16]{};
        char secondary_dns[16]{};
        FormatIpv4(m_last.current_address, address, sizeof(address));
        FormatIpv4(m_last.subnet_mask, subnet, sizeof(subnet));
        FormatIpv4(m_last.gateway, gateway, sizeof(gateway));
        FormatIpv4(m_last.primary_dns, primary_dns, sizeof(primary_dns));
        FormatIpv4(m_last.secondary_dns, secondary_dns, sizeof(secondary_dns));
        logger::Log(
            "NIFM path changed sequence=%llu init_rc=0x%08x status_rc=0x%08x type=%u status=%u strength=%u config_rc=0x%08x address=%s subnet=%s gateway=%s dns=%s,%s",
            static_cast<unsigned long long>(event.sequence),
            m_last.initialization_result,
            m_last.internet_status_result,
            m_last.connection_type,
            m_last.connection_status,
            m_last.wifi_strength,
            m_last.ip_config_result,
            address,
            subnet,
            gateway,
            primary_dns,
            secondary_dns);
    }
    if constexpr (development_config::VerboseHeartbeatLogging) {
        logger::Log(
            "NIFM observer commit sequence=%llu changed=%u",
            static_cast<unsigned long long>(event.sequence),
            changed ? 1U : 0U);
    }
    return {.sequence = event.sequence, .changed = changed};
}

} // namespace wgnx::sysmodule::runtime
