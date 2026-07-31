#include "tunnel_datagram_receive.hpp"
#include "tunnel_datagram_receive_tests.hpp"

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

bool RunTunnelDatagramReceiveTests() {
    using namespace wgnx::mitm;

    bool first_occupied = true;
    constexpr std::array<std::uint8_t, 4> first = {'f', 'i', 'r', 's'};
    std::array<std::uint8_t, 2> short_output{};
    const auto truncated = ReceiveTunneledDatagram(&first_occupied, short_output, first);

    bool second_occupied = true;
    constexpr std::array<std::uint8_t, 2> second = {'o', 'k'};
    std::array<std::uint8_t, 2> full_output{};
    const auto full = ReceiveTunneledDatagram(&second_occupied, full_output, second);

    return Check(truncated.truncated && truncated.size == short_output.size() && !first_occupied && short_output[0] == 'f' && short_output[1] == 'i',
                 "short UDP receive did not consume the datagram after copying its prefix") &&
           Check(!full.truncated && full.size == second.size() && !second_occupied && full_output == second,
                 "a truncated UDP receive wedged the following datagram");
}
