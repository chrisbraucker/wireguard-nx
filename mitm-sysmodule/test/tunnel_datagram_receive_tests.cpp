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

    bool stream_occupied = true;
    std::size_t stream_offset = 0;
    constexpr std::array<std::uint8_t, 4> stream = {'t', 'c', 'p', '!'};
    std::array<std::uint8_t, 2> stream_first{};
    const auto stream_prefix = ReceiveTunneledStream(&stream_occupied, &stream_offset, stream_first, stream);
    std::array<std::uint8_t, 2> stream_second{};
    const auto stream_suffix = ReceiveTunneledStream(&stream_occupied, &stream_offset, stream_second, stream);

    return Check(
               truncated.truncated && truncated.size == short_output.size() && !first_occupied && short_output[0] == 'f' &&
                   short_output[1] == 'i',
               "short UDP receive did not consume the datagram after copying its prefix"
           ) &&
           Check(
               !full.truncated && full.size == second.size() && !second_occupied && full_output == second,
               "a truncated UDP receive wedged the following datagram"
           ) &&
           Check(
               !stream_prefix.complete && stream_prefix.size == stream_first.size() && stream_first[0] == 't' && stream_first[1] == 'c' &&
                   stream_suffix.complete && stream_suffix.size == stream_second.size() && stream_second[0] == 'p' &&
                   stream_second[1] == '!' && !stream_occupied,
               "short TCP stream reads did not retain the unread suffix"
           );
}
