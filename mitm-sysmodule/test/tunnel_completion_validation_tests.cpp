#include "tunnel_completion_validation.hpp"
#include "tunnel_completion_validation_tests.hpp"

#include <array>
#include <cstdio>

namespace {

bool Check(const bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "failure: %s\n", message);
    }
    return condition;
}

} // namespace

bool RunTunnelCompletionValidationTests() {
    using namespace wgnx::mitm;

    constexpr std::size_t PayloadCapacity = 16;
    std::array<wgnx::tunnel::CompletionRecord, 2> records{};
    records[0].type = wgnx::tunnel::CompletionType::InboundUdpDatagram;
    records[0].payload_offset = 4;
    records[0].payload_size = 12;
    const bool valid = ValidateTunnelCompletionDrain(1, records.size(), records, PayloadCapacity);
    const bool invalid_count = !ValidateTunnelCompletionDrain(3, records.size(), records, PayloadCapacity);

    records[0].payload_offset = PayloadCapacity + 1;
    const bool invalid_offset = !ValidateTunnelCompletionDrain(1, records.size(), records, PayloadCapacity);
    records[0].payload_offset = 8;
    records[0].payload_size = 9;
    const bool invalid_range = !ValidateTunnelCompletionDrain(1, records.size(), records, PayloadCapacity);
    records[0].payload_offset = 0;
    records[0].payload_size = static_cast<std::uint32_t>(wgnx::tunnel::MaximumUdpPayloadStorageBytes + 1);
    const bool invalid_datagram_size =
        !ValidateTunnelCompletionDrain(1, records.size(), records, wgnx::tunnel::MaximumUdpPayloadStorageBytes + 1);

    return Check(valid, "valid tunnel completion response was rejected") &&
           Check(invalid_count, "oversized tunnel completion count was accepted") &&
           Check(invalid_offset, "out-of-range tunnel completion offset was accepted") &&
           Check(invalid_range, "out-of-range tunnel completion payload was accepted") &&
           Check(invalid_datagram_size, "oversized tunnel completion datagram was accepted");
}
