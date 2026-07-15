#include "protocol_tests.hpp"

#include "test_framework.hpp"
#include "test_runtime.hpp"

#include "wireguard/data.hpp"
#include "wireguard/device.hpp"
#include "wireguard/handshake.hpp"
#include "wireguard/inner_packet.hpp"
#include "wireguard/messages.hpp"
#include "wireguard/peer_controller.hpp"
#include "wireguard/timer_coordinator.hpp"
#include "wireguard/timers.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>

namespace wgnx::test {

namespace {

constexpr char InitiatorPrivateKey[] = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
constexpr char InitiatorPublicKey[] = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=";
constexpr char ResponderPrivateKey[] = "ZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4Q=";
constexpr char ResponderPublicKey[] = "VxR2nRFr92Q2rnS8eT0sMK0ZA8WaxSc4BcfiaYtBDDY=";
constexpr char PresharedKey[] = "ycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+g=";
constexpr char ZeroKey[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

constexpr std::uint32_t InitiatorIndex = 0x01020304U;
constexpr std::uint32_t ResponderIndex = 0xA1A2A3A4U;
constexpr wgnx::platform::ktime_t InitialMonotonicTime = 2 * wgnx::platform::NSEC_PER_SEC;
constexpr wgnx::platform::ktime_t SessionBirthTime = 9 * wgnx::platform::NSEC_PER_SEC;
constexpr std::uint64_t RandomSeed = 0x57474E582D544553ULL;

constexpr runtime::State InitialRuntimeState = {
    .monotonic_time_ns = InitialMonotonicTime,
    .realtime = {
        .tv_sec = 1'700'000'000,
        .tv_nsec = 123'456'789,
    },
    .random_state = RandomSeed,
    .random_bytes_generated = 0,
};

class InMemoryDatagramLink {
public:
    static constexpr std::size_t Capacity = 8;
    static constexpr std::size_t MaximumPacketSize = 2048;

    bool Send(std::span<const std::uint8_t> packet) {
        if (m_count == Capacity || packet.size() > MaximumPacketSize) {
            return false;
        }

        Datagram &datagram = m_datagrams[(m_head + m_count) % Capacity];
        std::ranges::copy(packet, datagram.bytes.begin());
        datagram.size = packet.size();
        ++m_count;
        ++m_total_sent;
        return true;
    }

    bool Receive(std::span<const std::uint8_t> &out_packet) {
        if (m_count == 0) {
            return false;
        }

        Datagram &datagram = m_datagrams[m_head];
        out_packet = std::span<const std::uint8_t>(datagram.bytes.data(), datagram.size);
        m_head = (m_head + 1) % Capacity;
        --m_count;
        return true;
    }

    std::size_t Pending() const {
        return m_count;
    }

    std::size_t TotalSent() const {
        return m_total_sent;
    }

private:
    struct Datagram {
        std::array<std::uint8_t, MaximumPacketSize> bytes{};
        std::size_t size{0};
    };

    std::array<Datagram, Capacity> m_datagrams{};
    std::size_t m_head{0};
    std::size_t m_count{0};
    std::size_t m_total_sent{0};
};

void FillConfig(
    wgnx::PeerConfigEntry *config,
    const char *name,
    const char *address,
    const char *private_key,
    const char *remote_public_key) {
    *config = {};
    std::snprintf(config->name.data(), config->name.size(), "%s", name);
    std::snprintf(config->address.data(), config->address.size(), "%s", address);
    std::snprintf(config->endpoint.data(), config->endpoint.size(), "%s", "peer.test:51820");
    std::snprintf(config->private_key.data(), config->private_key.size(), "%s", private_key);
    std::snprintf(config->public_key.data(), config->public_key.size(), "%s", remote_public_key);
    std::snprintf(config->preshared_key.data(), config->preshared_key.size(), "%s", PresharedKey);
    std::snprintf(config->allowed_ips.data(), config->allowed_ips.size(), "%s", "0.0.0.0/0");
    config->persistent_keepalive = 20;
    config->mtu = 1420;
}

bool CheckHandshakeState(
    TestContext &context,
    const wgnx::wireguard::wg_peer &peer,
    wgnx::wireguard::HandshakeState expected_state,
    std::uint32_t expected_transitions,
    const char *phase) {
    if (peer.handshake.state == expected_state &&
        peer.handshake.transition_count == expected_transitions) {
        return true;
    }

    char detail[256]{};
    std::snprintf(
        detail,
        sizeof(detail),
        "peer=%s phase=%s state=%s expected=%s transitions=%u expected_transitions=%u",
        peer.name,
        phase,
        wgnx::wireguard::GetHandshakeStateName(peer.handshake.state),
        wgnx::wireguard::GetHandshakeStateName(expected_state),
        peer.handshake.transition_count,
        expected_transitions);
    context.Fail("handshake state", __FILE__, __LINE__, detail);
    return false;
}

struct ProtocolPair {
    wgnx::PeerConfigEntry initiator_config{};
    wgnx::PeerConfigEntry responder_config{};
    wgnx::wireguard::wg_device initiator_device{};
    wgnx::wireguard::wg_device responder_device{};
    wgnx::wireguard::wg_peer *initiator{nullptr};
    wgnx::wireguard::wg_peer *responder{nullptr};
    InMemoryDatagramLink initiator_to_responder{};
    InMemoryDatagramLink responder_to_initiator{};

    bool Initialize() {
        FillConfig(
            &initiator_config,
            "initiator",
            "10.66.66.2/32",
            InitiatorPrivateKey,
            ResponderPublicKey);
        FillConfig(
            &responder_config,
            "responder",
            "10.66.66.1/32",
            ResponderPrivateKey,
            InitiatorPublicKey);

        if (!wgnx::wireguard::wg_device_init_from_config_entry(&initiator_device, initiator_config) ||
            !wgnx::wireguard::wg_device_init_from_config_entry(&responder_device, responder_config)) {
            return false;
        }

        initiator = wgnx::wireguard::wg_device_first_peer(&initiator_device);
        responder = wgnx::wireguard::wg_device_first_peer(&responder_device);
        if (initiator == nullptr || responder == nullptr) {
            return false;
        }

        wgnx::wireguard::noise_handshake_set_local_index(&initiator->handshake, InitiatorIndex);
        wgnx::wireguard::noise_handshake_set_local_index(&responder->handshake, ResponderIndex);
        wgnx::wireguard::wg_device_register_handshake_index(&initiator_device, InitiatorIndex);
        wgnx::wireguard::wg_device_register_handshake_index(&responder_device, ResponderIndex);
        return true;
    }

    bool CreateAndSendInitiation(std::array<std::uint8_t, wgnx::wireguard::HandshakeInitiationSize> *out_bytes = nullptr) {
        wgnx::wireguard::message_handshake_initiation initiation{};
        const bool created = initiator->handshake.local_index == 0
            ? wgnx::wireguard::wg_device_create_handshake_initiation(
                  &initiator_device,
                  &initiation)
            : wgnx::wireguard::noise_handshake_create_initiation(&initiation, initiator);
        if (!created) {
            return false;
        }

        std::array<std::uint8_t, wgnx::wireguard::HandshakeInitiationSize> packet{};
        if (wgnx::wireguard::SerializeHandshakeInitiation(packet, initiation) !=
            wgnx::wireguard::ParseError::None) {
            return false;
        }
        if (out_bytes != nullptr) {
            *out_bytes = packet;
        }
        return initiator_to_responder.Send(packet);
    }

    bool ReceiveInitiationAndSendResponse() {
        std::span<const std::uint8_t> incoming{};
        if (!initiator_to_responder.Receive(incoming)) {
            return false;
        }

        wgnx::wireguard::message_handshake_initiation initiation{};
        if (responder->handshake.local_index == 0) {
            const std::uint32_t local_index =
                wgnx::wireguard::wg_device_allocate_index(&responder_device);
            wgnx::wireguard::noise_handshake_set_local_index(
                &responder->handshake,
                local_index);
            wgnx::wireguard::wg_device_register_handshake_index(
                &responder_device,
                local_index);
        }
        if (!wgnx::wireguard::ParseHandshakeInitiation(incoming, initiation).success ||
            !wgnx::wireguard::noise_handshake_consume_initiation(&initiation, responder)) {
            return false;
        }

        wgnx::wireguard::message_handshake_response response{};
        if (!wgnx::wireguard::noise_handshake_create_response(&response, responder)) {
            return false;
        }

        std::array<std::uint8_t, wgnx::wireguard::HandshakeResponseSize> packet{};
        if (wgnx::wireguard::SerializeHandshakeResponse(packet, response) !=
            wgnx::wireguard::ParseError::None) {
            return false;
        }
        return responder_to_initiator.Send(packet);
    }

    bool ReceiveResponseAndDeriveSession() {
        std::span<const std::uint8_t> incoming{};
        if (!responder_to_initiator.Receive(incoming)) {
            return false;
        }
        if (wgnx::wireguard::noise_handshake_consume_incoming_packet(
                incoming,
                &initiator_device,
                initiator) != wgnx::wireguard::HandshakePacketOutcome::ResponseConsumed) {
            return false;
        }

        runtime::SetMonotonicTime(SessionBirthTime);
        return wgnx::wireguard::noise_handshake_begin_session(&initiator_device, initiator) &&
               wgnx::wireguard::noise_handshake_begin_session(&responder_device, responder);
    }

};

bool CheckSessionKeys(TestContext &context, const ProtocolPair &pair) {
    const auto &initiator_keypair = pair.initiator->current_keypair;
    const auto &responder_keypair = pair.responder->current_keypair.IsValid()
        ? pair.responder->current_keypair
        : pair.responder->next_keypair;
    if (!initiator_keypair.IsValid()) {
        context.Fail("initiator_keypair.valid", __FILE__, __LINE__, "initiator current keypair is invalid");
        return false;
    }
    if (!responder_keypair.IsValid()) {
        context.Fail("responder_keypair.valid", __FILE__, __LINE__, "responder current keypair is invalid");
        return false;
    }
    const wgnx::wireguard::MonotonicTimePoint expected_birth{
        wgnx::wireguard::MonotonicDuration{SessionBirthTime}};
    if (initiator_keypair.BirthTime() != expected_birth ||
        responder_keypair.BirthTime() != expected_birth) {
        context.Fail("keypair birth time", __FILE__, __LINE__, "controlled monotonic time was not used");
        return false;
    }
    if (std::memcmp(
            initiator_keypair.SendingKey().bytes.data(),
            responder_keypair.ReceivingKey().bytes.data(),
            initiator_keypair.SendingKey().bytes.size()) != 0) {
        context.Fail("session keys", __FILE__, __LINE__, "initiator sending key does not match responder receiving key");
        return false;
    }
    if (std::memcmp(
            responder_keypair.SendingKey().bytes.data(),
            initiator_keypair.ReceivingKey().bytes.data(),
            responder_keypair.SendingKey().bytes.size()) != 0) {
        context.Fail("session keys", __FILE__, __LINE__, "responder sending key does not match initiator receiving key");
        return false;
    }
    return true;
}

struct TransportResult {
    wgnx::wireguard::TransportDataError error{wgnx::wireguard::TransportDataError::InvalidArgument};
    wgnx::wireguard::TransportDataDecryptResult decrypt{};
    std::array<std::uint8_t, 256> plaintext{};
    std::array<std::uint8_t, 2048> wire_packet{};
    std::size_t wire_packet_size{0};
};

TransportResult SendTransport(
    wgnx::wireguard::noise_keypair *sender,
    wgnx::wireguard::wg_device *receiver_device,
    wgnx::wireguard::wg_peer *receiver,
    std::span<const std::uint8_t> payload,
    InMemoryDatagramLink *link) {
    TransportResult result{};
    std::array<std::uint8_t, 2048> outgoing{};
    const auto create_result = wgnx::wireguard::noise_create_transport_data_packet(
        outgoing,
        *sender,
        payload);
    result.error = create_result.error;
    if (result.error != wgnx::wireguard::TransportDataError::None) {
        return result;
    }
    const auto wire_packet = std::span<const std::uint8_t>(outgoing).first(create_result.packet_size);
    if (!link->Send(wire_packet)) {
        result.error = wgnx::wireguard::TransportDataError::InvalidPacket;
        return result;
    }

    std::ranges::copy(wire_packet, result.wire_packet.begin());
    result.wire_packet_size = wire_packet.size();

    std::span<const std::uint8_t> incoming{};
    if (!link->Receive(incoming)) {
        result.error = wgnx::wireguard::TransportDataError::InvalidPacket;
        return result;
    }
    wgnx::wireguard::IncomingTransportDataResult incoming_result{};
    result.error = wgnx::wireguard::noise_consume_incoming_transport_data_packet(
        incoming,
        *receiver_device,
        *receiver,
        result.plaintext,
        incoming_result);
    result.decrypt = incoming_result.decrypt;
    return result;
}

bool BuildDeterministicInitiation(
    std::array<std::uint8_t, wgnx::wireguard::HandshakeInitiationSize> *out,
    wgnx::wireguard::HandshakeState *out_state,
    std::uint32_t *out_transition_count,
    wgnx::wireguard::MonotonicTimePoint *out_transition_time) {
    runtime::Reset(InitialRuntimeState);
    ProtocolPair pair{};
    if (!pair.Initialize() || !pair.CreateAndSendInitiation(out)) {
        return false;
    }

    *out_state = pair.initiator->handshake.state;
    *out_transition_count = pair.initiator->handshake.transition_count;
    *out_transition_time = pair.initiator->handshake.last_transition;
    return true;
}

} // namespace

void TestDeterministicHandshake(TestContext &context) {
    std::array<std::uint8_t, wgnx::wireguard::HandshakeInitiationSize> first{};
    std::array<std::uint8_t, wgnx::wireguard::HandshakeInitiationSize> second{};
    wgnx::wireguard::HandshakeState first_state{};
    wgnx::wireguard::HandshakeState second_state{};
    std::uint32_t first_transitions = 0;
    std::uint32_t second_transitions = 0;
    wgnx::wireguard::MonotonicTimePoint first_transition_time{};
    wgnx::wireguard::MonotonicTimePoint second_transition_time{};

    WGNX_TEST_CHECK(
        context,
        BuildDeterministicInitiation(
            &first,
            &first_state,
            &first_transitions,
            &first_transition_time));
    const runtime::State first_runtime = runtime::GetState();
    WGNX_TEST_CHECK(
        context,
        BuildDeterministicInitiation(
            &second,
            &second_state,
            &second_transitions,
            &second_transition_time));
    const runtime::State second_runtime = runtime::GetState();

    WGNX_TEST_REQUIRE(
        context,
        first == second,
        "same clock and random seed produced different initiation packets");
    WGNX_TEST_REQUIRE(
        context,
        first_state == wgnx::wireguard::HandshakeState::InitiationCreated &&
            second_state == first_state &&
            first_transitions == 1 &&
            second_transitions == first_transitions,
        "initiation state transition was not deterministic");
    WGNX_TEST_REQUIRE(
        context,
        first_transition_time == wgnx::wireguard::MonotonicTimePoint{
                                     wgnx::wireguard::MonotonicDuration{InitialMonotonicTime}} &&
            second_transition_time == first_transition_time,
        "handshake transition did not use the controlled monotonic clock");
    WGNX_TEST_REQUIRE(
        context,
        first_runtime.random_bytes_generated == wgnx::wireguard::NoisePublicKeySize &&
            second_runtime.random_bytes_generated == first_runtime.random_bytes_generated,
        "initiation consumed an unexpected amount of random input");
}

void TestBidirectionalTransport(TestContext &context) {
    runtime::Reset(InitialRuntimeState);
    ProtocolPair pair{};
    WGNX_TEST_REQUIRE(context, pair.Initialize(), "protocol pair initialization failed");
    WGNX_TEST_REQUIRE(context, pair.CreateAndSendInitiation(), "initiation creation or serialization failed");
    if (!CheckHandshakeState(
            context,
            *pair.initiator,
            wgnx::wireguard::HandshakeState::InitiationCreated,
            1,
            "initiation sent")) {
        return;
    }
    WGNX_TEST_REQUIRE(
        context,
        pair.ReceiveInitiationAndSendResponse(),
        "initiation consumption or response serialization failed");
    if (!CheckHandshakeState(
            context,
            *pair.responder,
            wgnx::wireguard::HandshakeState::ResponseCreated,
            2,
            "response sent")) {
        return;
    }
    WGNX_TEST_REQUIRE(
        context,
        pair.ReceiveResponseAndDeriveSession(),
        "response consumption or session derivation failed");
    if (!CheckHandshakeState(
            context,
            *pair.initiator,
            wgnx::wireguard::HandshakeState::SessionDerived,
            3,
            "session established")) {
        return;
    }
    if (!CheckHandshakeState(
            context,
            *pair.responder,
            wgnx::wireguard::HandshakeState::SessionDerived,
            3,
            "session established")) {
        return;
    }
    if (!CheckSessionKeys(context, pair)) {
        return;
    }

    constexpr std::array<std::uint8_t, 16> InitiatorPayload = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };
    constexpr std::array<std::uint8_t, 16> ResponderPayload = {
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    };

    const TransportResult first = SendTransport(
        &pair.initiator->current_keypair,
        &pair.responder_device,
        pair.responder,
        InitiatorPayload,
        &pair.initiator_to_responder);
    WGNX_TEST_REQUIRE(
        context,
        first.error == wgnx::wireguard::TransportDataError::None,
        wgnx::wireguard::GetTransportDataErrorName(first.error));
    WGNX_TEST_REQUIRE(
        context,
        first.decrypt.header.counter == 0 &&
            first.decrypt.payload_size == InitiatorPayload.size() &&
            std::memcmp(first.plaintext.data(), InitiatorPayload.data(), InitiatorPayload.size()) == 0,
        "initiator-to-responder packet content or counter diverged");

    const TransportResult reverse = SendTransport(
        &pair.responder->current_keypair,
        &pair.initiator_device,
        pair.initiator,
        ResponderPayload,
        &pair.responder_to_initiator);
    WGNX_TEST_REQUIRE(
        context,
        reverse.error == wgnx::wireguard::TransportDataError::None,
        wgnx::wireguard::GetTransportDataErrorName(reverse.error));
    WGNX_TEST_REQUIRE(
        context,
        reverse.decrypt.header.counter == 0 &&
            reverse.decrypt.payload_size == ResponderPayload.size() &&
            std::memcmp(reverse.plaintext.data(), ResponderPayload.data(), ResponderPayload.size()) == 0,
        "responder-to-initiator packet content or counter diverged");

    const TransportResult second = SendTransport(
        &pair.initiator->current_keypair,
        &pair.responder_device,
        pair.responder,
        InitiatorPayload,
        &pair.initiator_to_responder);
    WGNX_TEST_REQUIRE(
        context,
        second.error == wgnx::wireguard::TransportDataError::None &&
            second.decrypt.header.counter == 1,
        "second initiator packet did not advance the send counter");

    const auto replay = std::span<const std::uint8_t>(second.wire_packet).first(second.wire_packet_size);
    std::array<std::uint8_t, 256> replay_plaintext{};
    wgnx::wireguard::TransportDataDecryptResult replay_result{};
    const auto replay_error = wgnx::wireguard::noise_consume_transport_data_packet(
        replay,
        pair.responder->current_keypair,
        replay_plaintext,
        replay_result);
    WGNX_TEST_REQUIRE(
        context,
        replay_error == wgnx::wireguard::TransportDataError::ReplayRejected,
        wgnx::wireguard::GetTransportDataErrorName(replay_error));
    WGNX_TEST_REQUIRE(
        context,
        pair.initiator->current_keypair.SendCounter() == 2 &&
            pair.responder->current_keypair.SendCounter() == 1 &&
            pair.initiator->current_keypair.ReceiveReplayWindow().HighestCounter() == 0 &&
            pair.responder->current_keypair.ReceiveReplayWindow().HighestCounter() == 1,
        "final send or receive counter state diverged");
    WGNX_TEST_REQUIRE(
        context,
        pair.initiator_to_responder.Pending() == 0 &&
            pair.responder_to_initiator.Pending() == 0 &&
            pair.initiator_to_responder.TotalSent() == 3 &&
            pair.responder_to_initiator.TotalSent() == 2,
        "in-memory transport did not drain deterministically");
}

void TestTimerIntent(TestContext &context) {
    runtime::Reset(InitialRuntimeState);
    ProtocolPair pair{};
    WGNX_TEST_REQUIRE(context, pair.Initialize(), "protocol pair initialization failed");

    auto &timers = pair.initiator->timers;
    WGNX_TEST_REQUIRE(context, !wgnx::wireguard::wg_timers_any_pending(timers), "new peer has pending timers");
    wgnx::wireguard::wg_timers_schedule(
        &timers,
        wgnx::wireguard::TimerHook::RetransmitHandshake,
        wgnx::wireguard::TimerDeadlineFromJiffies(5'000),
        pair.initiator->name);
    wgnx::wireguard::wg_timers_schedule(
        &timers,
        wgnx::wireguard::TimerHook::Rekey,
        wgnx::wireguard::TimerDeadlineFromJiffies(120'000),
        pair.initiator->name);
    WGNX_TEST_REQUIRE(
        context,
        timers.retransmit_handshake.pending &&
            timers.retransmit_handshake.deadline ==
                wgnx::wireguard::TimerDeadlineFromJiffies(5'000) &&
            timers.rekey.pending &&
            timers.rekey.deadline == wgnx::wireguard::TimerDeadlineFromJiffies(120'000),
        "timer schedule state or deadline diverged");

    wgnx::wireguard::wg_timers_schedule(
        &timers,
        wgnx::wireguard::TimerHook::RetransmitHandshake,
        wgnx::wireguard::TimerDeadlineFromJiffies(7'500),
        pair.initiator->name);
    WGNX_TEST_REQUIRE(
        context,
        timers.retransmit_handshake.pending &&
            timers.retransmit_handshake.deadline ==
                wgnx::wireguard::TimerDeadlineFromJiffies(7'500),
        "rescheduling did not replace the timer deadline");

    wgnx::wireguard::wg_timers_cancel(
        &timers,
        wgnx::wireguard::TimerHook::RetransmitHandshake,
        pair.initiator->name);
    WGNX_TEST_REQUIRE(
        context,
        !timers.retransmit_handshake.pending &&
            timers.retransmit_handshake.deadline == wgnx::wireguard::TimerDeadline{} &&
            timers.rekey.pending,
        "single timer cancellation changed the wrong timer state");
    wgnx::wireguard::wg_timers_cancel_all(&timers, pair.initiator->name);
    WGNX_TEST_REQUIRE(context, !wgnx::wireguard::wg_timers_any_pending(timers), "cancel-all left timer intent pending");
}

void TestTypedMessageBoundaries(TestContext &context) {
    using namespace wgnx::wireguard;

    message_handshake_initiation initiation{};
    SetMessageType(initiation.type, MessageType::HandshakeInitiation);
    initiation.sender_index = InitiatorIndex;
    std::array<std::uint8_t, HandshakeInitiationSize> initiation_bytes{};
    WGNX_TEST_REQUIRE(
        context,
        SerializeHandshakeInitiation(initiation_bytes, initiation) == ParseError::None,
        "valid initiation serialization failed");

    for (std::size_t size = 0; size < HandshakeInitiationSize; ++size) {
        message_handshake_initiation parsed{};
        const ParseResult result = ParseHandshakeInitiation(
            std::span<const std::uint8_t>(initiation_bytes).first(size),
            parsed);
        if (result.success) {
            context.Fail("undersized initiation rejected", __FILE__, __LINE__, "parser accepted truncated input");
            return;
        }
    }

    std::array<std::uint8_t, HandshakeInitiationSize + 1> oversized{};
    std::ranges::copy(initiation_bytes, oversized.begin());
    message_handshake_initiation parsed_oversized{};
    const ParseResult oversized_result = ParseHandshakeInitiation(oversized, parsed_oversized);
    WGNX_TEST_REQUIRE(
        context,
        !oversized_result.success && oversized_result.error == ParseError::InvalidLength,
        "fixed-size initiation parser accepted trailing bytes");

    std::array<std::uint8_t, HandshakeInitiationSize - 1> short_output{};
    WGNX_TEST_REQUIRE(
        context,
        SerializeHandshakeInitiation(short_output, initiation) == ParseError::InsufficientCapacity,
        "serializer did not reject an undersized destination");

    message_transport_data transport{};
    SetMessageType(transport.type, MessageType::TransportData);
    transport.receiver_index = ResponderIndex;
    transport.counter = 7;
    std::array<std::uint8_t, TransportDataHeaderSize + NoiseTagSize> transport_bytes{};
    WGNX_TEST_REQUIRE(
        context,
        SerializeTransportDataHeader(transport_bytes, transport) == ParseError::None,
        "valid transport header serialization failed");
    message_transport_data parsed_transport{};
    WGNX_TEST_REQUIRE(
        context,
        ParseTransportDataHeader(transport_bytes, parsed_transport).success &&
            parsed_transport.receiver_index == transport.receiver_index &&
            parsed_transport.counter == transport.counter,
        "transport parser rejected a checked variable-length packet");
    WGNX_TEST_REQUIRE(
        context,
        !ParseTransportDataHeader(
             std::span<const std::uint8_t>(transport_bytes).first(TransportDataHeaderSize - 1),
             parsed_transport)
             .success,
        "transport parser accepted an undersized header");
}

void TestPrivateKeyParsing(TestContext &context) {
    using namespace wgnx::wireguard;

    noise_private_key key{};
    key.valid = true;
    std::ranges::fill(key.bytes, 0xA5);

    WGNX_TEST_REQUIRE(
        context,
        noise_is_valid_encoded_key(ZeroKey),
        "all-zero key encoding was rejected as malformed base64");
    WGNX_TEST_REQUIRE(
        context,
        !noise_parse_private_key(&key, ZeroKey),
        "all-zero private key was accepted after X25519 clamping");
    WGNX_TEST_REQUIRE(
        context,
        key.valid && std::ranges::all_of(key.bytes, [](std::uint8_t byte) { return byte == 0xA5; }),
        "failed private-key parsing modified the caller's key");

    WGNX_TEST_REQUIRE(
        context,
        noise_parse_private_key(&key, InitiatorPrivateKey),
        "valid private key was rejected");
    WGNX_TEST_REQUIRE(
        context,
        key.valid &&
            (key.bytes.front() & 0x07U) == 0 &&
            (key.bytes.back() & 0x80U) == 0 &&
            (key.bytes.back() & 0x40U) != 0,
        "valid private key was not clamped for X25519");
}

void TestKeypairLifetime(TestContext &context) {
    using namespace wgnx::wireguard;

    noise_symmetric_key sending_key{};
    noise_symmetric_key receiving_key{};
    sending_key.valid = true;
    receiving_key.valid = true;
    std::ranges::fill(sending_key.bytes, 0x11);
    std::ranges::fill(receiving_key.bytes, 0x22);

    noise_keypair keypair{};
    const MonotonicTimePoint birth_time{std::chrono::seconds{9}};
    keypair.Establish(InitiatorIndex, ResponderIndex, birth_time, sending_key, receiving_key);
    WGNX_TEST_REQUIRE(
        context,
        keypair.IsValid() && keypair.CanSendAt(birth_time) && keypair.CanReceiveAt(birth_time) &&
            keypair.State() == KeypairState::Established,
        "established keypair did not expose a coherent validity state");

    const KeypairAgeResult before_birth = keypair.AgeAt(birth_time - std::chrono::nanoseconds{1});
    const KeypairAgeResult at_birth = keypair.AgeAt(birth_time);
    const KeypairAgeResult after_birth = keypair.AgeAt(birth_time + std::chrono::seconds{3});
    WGNX_TEST_REQUIRE(
        context,
        !before_birth.valid &&
            at_birth.valid && at_birth.age == MonotonicDuration::zero() &&
            after_birth.valid && after_birth.age == std::chrono::seconds{3},
        "keypair age evaluation depends on invalid or implicit clock state");

    keypair.Reset();
    WGNX_TEST_REQUIRE(
        context,
        !keypair.IsValid() && keypair.State() == KeypairState::Empty &&
            !keypair.SendingKey().valid && !keypair.ReceivingKey().valid &&
            std::ranges::all_of(keypair.SendingKey().bytes, [](std::uint8_t byte) { return byte == 0; }) &&
            std::ranges::all_of(keypair.ReceivingKey().bytes, [](std::uint8_t byte) { return byte == 0; }),
        "keypair reset retained validity or session key material");

    keypair.Establish(0, ResponderIndex, birth_time, sending_key, receiving_key);
    WGNX_TEST_REQUIRE(context, !keypair.IsValid(), "zero-index keypair establishment succeeded");
}

void TestBoundedQueueObservability(TestContext &context) {
    using namespace wgnx::wireguard;

    InnerPacketQueue<2> queue{};
    InnerPacketRecord first{.packet_id = 1};
    InnerPacketRecord second{.packet_id = 2};
    InnerPacketRecord overflow{.packet_id = 3};
    WGNX_TEST_REQUIRE(
        context,
        queue.Push(first) == QueuePushResult::Pushed &&
            queue.Push(second) == QueuePushResult::Pushed &&
            queue.Push(overflow) == QueuePushResult::Full,
        "bounded queue did not expose its overflow policy");

    const QueueStatistics full_statistics = queue.Statistics();
    WGNX_TEST_REQUIRE(
        context,
        full_statistics.pushed == 2 &&
            full_statistics.popped == 0 &&
            full_statistics.rejected_full == 1 &&
            full_statistics.high_watermark == 2,
        "bounded queue statistics diverged at capacity");

    InnerPacketRecord popped{};
    WGNX_TEST_REQUIRE(
        context,
        queue.Pop(&popped, QueueDisposition::Delivered) && popped.packet_id == first.packet_id &&
            queue.Statistics().popped == 1 &&
            queue.Statistics().delivered == 1,
        "bounded queue pop statistics diverged");

    WGNX_TEST_REQUIRE(
        context,
        queue.Clear(QueueDisposition::Cleared) == 1 &&
            queue.Size() == 0 &&
            queue.Statistics().pushed == queue.Statistics().popped &&
            queue.Statistics().cleared == 1,
        "queue clearing did not preserve depth or disposition accounting");
}

void TestReplayWindowParity(TestContext &context) {
    using namespace wgnx::wireguard;

    ReplayWindow replay{};
    WGNX_TEST_REQUIRE(
        context,
        replay.TryAdvance(0) && !replay.TryAdvance(0),
        "replay filter did not reject a duplicate initial counter");

    constexpr std::uint64_t Highest = 10'000;
    constexpr std::uint64_t OldestAccepted = Highest - ReplayWindow::WindowSize;
    WGNX_TEST_REQUIRE(
        context,
        replay.TryAdvance(Highest) &&
            replay.TryAdvance(OldestAccepted) &&
            !replay.TryAdvance(OldestAccepted) &&
            !replay.TryAdvance(OldestAccepted - 1),
        "replay filter diverged at the upstream 8,128-packet window boundary");

    replay.Reset();
    WGNX_TEST_REQUIRE(
        context,
        replay.TryAdvance(64) && replay.TryAdvance(0) && !replay.TryAdvance(64),
        "replay filter did not preserve independent ring blocks after reset");
}

void TestTimerCoordinator(TestContext &context) {
    using namespace wgnx::wireguard;

    TimerCoordinator coordinator{};
    const TimerOwner first_owner{
        .peer_index = 1,
        .activation_generation = 7,
        .protocol_sequence = 3,
    };
    const TimerToken first = coordinator.Arm(TimerHook::ZeroKeyMaterial, first_owner);
    WGNX_TEST_REQUIRE(
        context,
        first.IsValid() && coordinator.IsCurrent(first, first_owner),
        "new timer token was not current for its owner");

    const TimerToken replacement = coordinator.Arm(TimerHook::ZeroKeyMaterial, first_owner);
    WGNX_TEST_REQUIRE(
        context,
        replacement.generation != first.generation &&
            !coordinator.IsCurrent(first, first_owner) &&
            coordinator.IsCurrent(replacement, first_owner),
        "rearming did not invalidate queued work from the previous timer");

    const TimerOwner next_activation{
        .peer_index = first_owner.peer_index,
        .activation_generation = first_owner.activation_generation + 1,
        .protocol_sequence = first_owner.protocol_sequence,
    };
    WGNX_TEST_REQUIRE(
        context,
        !coordinator.IsCurrent(replacement, next_activation),
        "timer token crossed an activation boundary");

    coordinator.Cancel(TimerHook::ZeroKeyMaterial);
    WGNX_TEST_REQUIRE(
        context,
        !coordinator.IsCurrent(replacement, first_owner) &&
            !coordinator.IsArmed(TimerHook::ZeroKeyMaterial),
        "timer cancellation left queued work actionable");

    const TimerToken retry = coordinator.Arm(
        TimerHook::RetransmitHandshake,
        first_owner);
    const TimerOwner next_sequence{
        .peer_index = first_owner.peer_index,
        .activation_generation = first_owner.activation_generation,
        .protocol_sequence = first_owner.protocol_sequence + 1,
    };
    WGNX_TEST_REQUIRE(
        context,
        !coordinator.IsCurrent(retry, next_sequence),
        "retry timer token crossed a handshake-sequence boundary");
}

void TestPeerControllerSendPolicy(TestContext &context) {
    using namespace wgnx::wireguard;

    WGNX_TEST_REQUIRE(
        context,
        PeerController::ClassifyStagedSend({.success = true}) ==
                StagedPacketDecision::RetireSent &&
            PeerController::ClassifyStagedSend({
                .stage = OutboundSendStage::Build,
                .build_error = TransportDataError::KeyExpired,
            }) == StagedPacketDecision::RetainForHandshake &&
            PeerController::ClassifyStagedSend({
                .stage = OutboundSendStage::Build,
                .build_error = TransportDataError::CounterExhausted,
            }) == StagedPacketDecision::RetainForHandshake,
        "peer controller did not retain plaintext for a replacement handshake");

    WGNX_TEST_REQUIRE(
        context,
        PeerController::ClassifyStagedSend({
            .stage = OutboundSendStage::Transport,
            .recoverable_transport_error = true,
        }) == StagedPacketDecision::RetireTransportFailure &&
            PeerController::ClassifyStagedSend({
                .stage = OutboundSendStage::Build,
                .build_error = TransportDataError::AuthenticationFailed,
            }) == StagedPacketDecision::StopOnTerminalFailure,
        "peer controller conflated transport loss with terminal construction failure");
}

void TestKeypairProtocolLimits(TestContext &context) {
    using namespace wgnx::wireguard;

    noise_symmetric_key sending_key{};
    noise_symmetric_key receiving_key{};
    sending_key.valid = true;
    receiving_key.valid = true;
    std::ranges::fill(sending_key.bytes, 0x31);
    std::ranges::fill(receiving_key.bytes, 0x42);

    const MonotonicTimePoint birth_time{std::chrono::seconds{30}};
    noise_keypair keypair{};
    keypair.Establish(InitiatorIndex, ResponderIndex, birth_time, sending_key, receiving_key);
    WGNX_TEST_REQUIRE(
        context,
        keypair.SendStateAt(birth_time + RejectAfterTime - std::chrono::nanoseconds{1}) ==
                KeypairSendState::Ready &&
            keypair.SendStateAt(birth_time + RejectAfterTime) == KeypairSendState::Expired &&
            keypair.CanReceiveAt(birth_time + RejectAfterTime - std::chrono::nanoseconds{1}) &&
            !keypair.CanReceiveAt(birth_time + RejectAfterTime),
        "RejectAfterTime boundary was not enforced exactly");

    noise_keypair final_counter_keypair{};
    final_counter_keypair.Establish(
        InitiatorIndex,
        ResponderIndex,
        birth_time,
        sending_key,
        receiving_key,
        RejectAfterMessages - 1);
    std::uint64_t reserved_counter = 0;
    WGNX_TEST_REQUIRE(
        context,
        final_counter_keypair.ReserveSendCounterAt(birth_time, reserved_counter) ==
                KeypairSendState::Ready &&
            reserved_counter == RejectAfterMessages - 1 &&
            final_counter_keypair.SendCounter() == RejectAfterMessages &&
            final_counter_keypair.ReserveSendCounterAt(birth_time, reserved_counter) ==
                KeypairSendState::CounterExhausted,
        "RejectAfterMessages boundary allowed an exhausted nonce");

    runtime::SetMonotonicTime(
        static_cast<wgnx::platform::ktime_t>(
            (birth_time + RejectAfterTime).time_since_epoch().count()));
    std::array<std::uint8_t, 64> output{};
    std::ranges::fill(output, 0xA5);
    const auto expired_result = noise_create_transport_data_packet(
        output,
        keypair,
        std::span<const std::uint8_t>{});
    WGNX_TEST_REQUIRE(
        context,
        expired_result.error == TransportDataError::KeyExpired &&
            keypair.SendCounter() == 0 &&
            std::ranges::all_of(output, [](std::uint8_t byte) { return byte == 0xA5; }),
        "expired keypair emitted bytes or consumed a nonce");

    runtime::SetMonotonicTime(static_cast<wgnx::platform::ktime_t>(
        birth_time.time_since_epoch().count()));
    noise_keypair exhausted_keypair{};
    exhausted_keypair.Establish(
        InitiatorIndex,
        ResponderIndex,
        birth_time,
        sending_key,
        receiving_key,
        RejectAfterMessages);
    const auto exhausted_result = noise_create_transport_data_packet(
        output,
        exhausted_keypair,
        std::span<const std::uint8_t>{});
    WGNX_TEST_REQUIRE(
        context,
        exhausted_result.error == TransportDataError::CounterExhausted &&
            exhausted_keypair.SendCounter() == RejectAfterMessages,
        "counter-exhausted keypair emitted a transport packet");
}

void TestOutboundStagingLifecycle(TestContext &context) {
    using namespace wgnx::wireguard;

    runtime::Reset(InitialRuntimeState);
    ProtocolPair pair{};
    WGNX_TEST_REQUIRE(context, pair.Initialize(), "protocol pair initialization failed");

    constexpr std::array<std::uint8_t, 20> FirstPayload = {
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
        0x00, 0x00, 0x0A, 0x42, 0x42, 0x02, 0x0A, 0x42, 0x42, 0x01,
    };
    InnerPacketRecord first_record{
        .packet_id = 41,
        .size = static_cast<std::uint16_t>(FirstPayload.size()),
    };
    std::ranges::copy(FirstPayload, first_record.bytes.begin());
    WGNX_TEST_REQUIRE(
        context,
        pair.initiator->staged_outbound_packets.Push(first_record) == QueuePushResult::Pushed &&
            wg_peer_get_outbound_staging_action(*pair.initiator, GetMonotonicTime()) ==
                OutboundStagingAction::InitiateHandshake,
        "packet without a keypair was not staged for handshake initiation");

    WGNX_TEST_REQUIRE(context, pair.CreateAndSendInitiation(), "staged-traffic initiation failed");
    WGNX_TEST_REQUIRE(context, pair.ReceiveInitiationAndSendResponse(), "staged-traffic response failed");
    WGNX_TEST_REQUIRE(context, pair.ReceiveResponseAndDeriveSession(), "staged-traffic session derivation failed");
    WGNX_TEST_REQUIRE(
        context,
        wg_peer_get_outbound_staging_action(*pair.initiator, GetMonotonicTime()) ==
            OutboundStagingAction::Send,
        "session derivation did not release staged traffic");

    const InnerPacketRecord *first_front = pair.initiator->staged_outbound_packets.Front();
    WGNX_TEST_REQUIRE(context, first_front != nullptr, "staged packet disappeared during handshake");
    const TransportResult first_send = SendTransport(
        &pair.initiator->current_keypair,
        &pair.responder_device,
        pair.responder,
        std::span<const std::uint8_t>(first_front->bytes.data(), first_front->size),
        &pair.initiator_to_responder);
    WGNX_TEST_REQUIRE(
        context,
        first_send.error == TransportDataError::None &&
            first_send.decrypt.payload_size == GetPaddedTransportPayloadSize(FirstPayload.size()) &&
            std::ranges::equal(
                FirstPayload,
                std::span<const std::uint8_t>(first_send.plaintext).first(FirstPayload.size())) &&
            std::ranges::all_of(
                std::span<const std::uint8_t>(first_send.plaintext).subspan(
                    FirstPayload.size(),
                    first_send.decrypt.payload_size - FirstPayload.size()),
                [](std::uint8_t byte) { return byte == 0; }),
        "staged packet was not transmitted after session derivation");
    InnerPacketRecord sent_record{};
    WGNX_TEST_REQUIRE(
        context,
        pair.initiator->staged_outbound_packets.Pop(
            &sent_record,
            QueueDisposition::Sent) &&
            sent_record.packet_id == first_record.packet_id,
        "transmitted staged packet was not retired exactly once");

    const MonotonicTimePoint expired_time =
        pair.initiator->current_keypair.BirthTime() + RejectAfterTime;
    runtime::SetMonotonicTime(static_cast<wgnx::platform::ktime_t>(
        expired_time.time_since_epoch().count()));
    InnerPacketRecord expired_record{
        .packet_id = 42,
        .size = static_cast<std::uint16_t>(FirstPayload.size()),
    };
    std::ranges::copy(FirstPayload, expired_record.bytes.begin());
    WGNX_TEST_REQUIRE(
        context,
        pair.initiator->staged_outbound_packets.Push(expired_record) == QueuePushResult::Pushed &&
            wg_peer_get_outbound_staging_action(*pair.initiator, GetMonotonicTime()) ==
                OutboundStagingAction::InitiateHandshake &&
            pair.initiator->staged_outbound_packets.Size() == 1,
        "submission after key expiry did not remain staged for a fresh handshake");

    const std::uint32_t old_initiator_index = pair.initiator->current_keypair.LocalIndex();
    const std::uint32_t old_responder_index = pair.responder->current_keypair.LocalIndex();
    const auto old_initiator_sending = pair.initiator->current_keypair.SendingKey().bytes;
    const MonotonicTimePoint replacement_birth = expired_time + std::chrono::seconds{1};
    runtime::SetMonotonicTime(static_cast<wgnx::platform::ktime_t>(
        replacement_birth.time_since_epoch().count()));
    WGNX_TEST_REQUIRE(
        context,
        pair.CreateAndSendInitiation() &&
            pair.ReceiveInitiationAndSendResponse() &&
            pair.ReceiveResponseAndDeriveSession(),
        "replacement handshake did not derive a new session");
    WGNX_TEST_REQUIRE(
        context,
        wg_peer_get_outbound_staging_action(*pair.initiator, GetMonotonicTime()) ==
                OutboundStagingAction::Send &&
            pair.initiator->staged_outbound_packets.Size() == 1 &&
            pair.initiator->current_keypair.LocalIndex() != old_initiator_index &&
            pair.initiator->previous_keypair.LocalIndex() == old_initiator_index &&
            pair.initiator->current_keypair.SendingKey().bytes != old_initiator_sending &&
            pair.responder->current_keypair.LocalIndex() == old_responder_index &&
            pair.responder->next_keypair.IsValid(),
        "replacement key derivation did not release the expired-key submission");

    const InnerPacketRecord *replacement_front = pair.initiator->staged_outbound_packets.Front();
    WGNX_TEST_REQUIRE(context, replacement_front != nullptr, "expired-key submission disappeared");
    const TransportResult replacement_send = SendTransport(
        &pair.initiator->current_keypair,
        &pair.responder_device,
        pair.responder,
        std::span<const std::uint8_t>(replacement_front->bytes.data(), replacement_front->size),
        &pair.initiator_to_responder);
    WGNX_TEST_REQUIRE(
        context,
        replacement_send.error == TransportDataError::None &&
            replacement_send.decrypt.payload_size == GetPaddedTransportPayloadSize(FirstPayload.size()) &&
            pair.responder->current_keypair.LocalIndex() != old_responder_index &&
            pair.responder->previous_keypair.LocalIndex() == old_responder_index &&
            !pair.responder->next_keypair.IsValid(),
        "expired-key submission was not transmitted with the replacement keypair");
    WGNX_TEST_REQUIRE(
        context,
        pair.initiator->staged_outbound_packets.Pop(
            &sent_record,
            QueueDisposition::Sent) &&
            sent_record.packet_id == expired_record.packet_id,
        "replacement-key transmission did not retire its staged packet");

    for (std::size_t i = 0; i < PeerStagedPacketCapacity; ++i) {
        InnerPacketRecord shutdown_record{.packet_id = 43 + i};
        WGNX_TEST_REQUIRE(
            context,
            pair.initiator->staged_outbound_packets.Push(shutdown_record) == QueuePushResult::Pushed,
            "peer staging queue reached capacity early");
    }
    InnerPacketRecord overflow_record{.packet_id = 43 + PeerStagedPacketCapacity};
    WGNX_TEST_REQUIRE(
        context,
        pair.initiator->staged_outbound_packets.Push(overflow_record) == QueuePushResult::Full &&
            pair.initiator->staged_outbound_packets.Statistics().rejected_full == 1 &&
            pair.initiator->staged_outbound_packets.Size() == PeerStagedPacketCapacity,
        "peer staging queue did not apply reject-new overflow policy");
    WGNX_TEST_REQUIRE(
        context,
        wg_peer_clear_staged_outbound_packets(pair.initiator) == PeerStagedPacketCapacity &&
            pair.initiator->staged_outbound_packets.Size() == 0 &&
            wg_peer_get_outbound_staging_action(*pair.initiator, GetMonotonicTime()) ==
                OutboundStagingAction::Idle,
        "peer shutdown retained staged outbound traffic");
}

void TestHandshakeRetryLifecycle(TestContext &context) {
    using namespace wgnx::wireguard;

    runtime::Reset(InitialRuntimeState);
    ProtocolPair pair{};
    WGNX_TEST_REQUIRE(context, pair.Initialize(), "protocol pair initialization failed");

    message_handshake_initiation first_initiation{};
    message_handshake_initiation second_initiation{};
    WGNX_TEST_REQUIRE(
        context,
        wg_device_create_handshake_initiation(
            &pair.initiator_device,
            &first_initiation) &&
            wg_device_create_handshake_initiation(
                &pair.initiator_device,
                &second_initiation),
        "failed to construct fresh retry initiations");
    WGNX_TEST_REQUIRE(
        context,
        first_initiation.sender_index != second_initiation.sender_index &&
            first_initiation.unencrypted_ephemeral != second_initiation.unencrypted_ephemeral &&
            wg_device_lookup_index_slot(
                &pair.initiator_device,
                first_initiation.sender_index) == wg_index_slot::None &&
            wg_device_lookup_index_slot(
                &pair.initiator_device,
                second_initiation.sender_index) == wg_index_slot::Handshake,
        "retry initiation reused ephemeral material or retained the old sender index");

    InnerPacketRecord first{.packet_id = 51};
    InnerPacketRecord second{.packet_id = 52};
    WGNX_TEST_REQUIRE(
        context,
        pair.initiator->staged_outbound_packets.Push(first) == QueuePushResult::Pushed &&
            pair.initiator->staged_outbound_packets.Push(second) == QueuePushResult::Pushed,
        "failed to stage packets for retry exhaustion");
    pair.initiator->has_last_initiation = true;

    wg_peer_begin_handshake_retry_sequence(pair.initiator);
    WGNX_TEST_REQUIRE(
        context,
        pair.initiator->handshake_retry.active &&
            pair.initiator->handshake_retry.send_attempts == 1 &&
            pair.initiator->handshake_retry.sequence_count == 1 &&
            GetHandshakeRetryDelay(0) == std::chrono::seconds{5} &&
            GetHandshakeRetryDelay(RekeyTimeoutJitterMaxMs - 1) ==
                std::chrono::milliseconds{5333} &&
            ZeroKeyMaterialAfterTime == std::chrono::seconds{540},
        "retry sequence or upstream timing constants initialized incorrectly");

    constexpr std::uint32_t MaxSendAttempts = MaxTimerHandshakes + 2;
    for (std::uint32_t expected_attempt = 2; expected_attempt <= MaxSendAttempts;
         ++expected_attempt) {
        const auto retry = wg_peer_handle_handshake_retry_timeout(pair.initiator);
        WGNX_TEST_REQUIRE(
            context,
            retry.action == HandshakeRetryTimeoutAction::Retry &&
                retry.dropped_staged_packets == 0 &&
                pair.initiator->handshake_retry.send_attempts == expected_attempt,
            "retry sequence exhausted before the upstream send-attempt boundary");
    }

    const auto exhausted = wg_peer_handle_handshake_retry_timeout(pair.initiator);
    WGNX_TEST_REQUIRE(
        context,
        exhausted.action == HandshakeRetryTimeoutAction::Exhausted &&
            exhausted.dropped_staged_packets == 2 &&
            !pair.initiator->handshake_retry.active &&
            pair.initiator->handshake_retry.send_attempts == MaxSendAttempts &&
            pair.initiator->handshake_retry.exhausted_sequence_count == 1 &&
            pair.initiator->staged_outbound_packets.Size() == 0 &&
            !pair.initiator->has_last_initiation,
        "retry exhaustion retained failed work or left the sequence active");
    WGNX_TEST_REQUIRE(
        context,
        wg_peer_handle_handshake_retry_timeout(pair.initiator).action ==
            HandshakeRetryTimeoutAction::Ignore,
        "inactive retry timeout mutated exhausted state");

    InnerPacketRecord later{.packet_id = 53};
    WGNX_TEST_REQUIRE(
        context,
        pair.initiator->staged_outbound_packets.Push(later) == QueuePushResult::Pushed,
        "failed to stage traffic after retry exhaustion");
    wg_peer_begin_handshake_retry_sequence(pair.initiator);
    WGNX_TEST_REQUIRE(
        context,
        pair.initiator->handshake_retry.active &&
            pair.initiator->handshake_retry.send_attempts == 1 &&
            pair.initiator->handshake_retry.sequence_count == 2 &&
            pair.initiator->handshake_retry.exhausted_sequence_count == 1 &&
            pair.initiator->staged_outbound_packets.Size() == 1,
        "later outbound traffic could not begin a new retry sequence");
    wg_peer_complete_handshake_retry_sequence(pair.initiator);
    WGNX_TEST_REQUIRE(
        context,
        !pair.initiator->handshake_retry.active &&
            pair.initiator->handshake_retry.send_attempts == 0 &&
            pair.initiator->staged_outbound_packets.Size() == 1,
        "successful handshake completion discarded staged traffic or retained retry state");

    WGNX_TEST_REQUIRE(
        context,
        pair.CreateAndSendInitiation() &&
            pair.ReceiveInitiationAndSendResponse() &&
            pair.ReceiveResponseAndDeriveSession(),
        "failed to derive key material for zeroing test");
    const auto precomputed = pair.initiator->handshake_material.precomputed_static_static.bytes;
    const auto static_private = pair.initiator->static_identity.static_private.bytes;
    pair.initiator->cookie.valid = true;
    pair.initiator->cookie.value.fill(0x6A);
    pair.initiator->handshake_material.ephemeral_private.valid = true;
    pair.initiator->handshake_material.ephemeral_private.bytes.fill(0xA5);
    pair.initiator->handshake_material.hash.valid = true;
    pair.initiator->handshake_material.hash.bytes.fill(0x5A);
    wg_peer_zero_key_material(pair.initiator);

    WGNX_TEST_REQUIRE(
        context,
        !pair.initiator->current_keypair.IsValid() &&
            !pair.initiator->next_keypair.IsValid() &&
            !pair.initiator->previous_keypair.IsValid() &&
            pair.initiator->handshake.state == HandshakeState::Zeroed &&
            pair.initiator->handshake.local_index == 0 &&
            !pair.initiator->handshake_material.ephemeral_private.valid &&
            std::ranges::all_of(
                pair.initiator->handshake_material.ephemeral_private.bytes,
                [](std::uint8_t byte) { return byte == 0; }) &&
            !pair.initiator->handshake_material.hash.valid &&
            std::ranges::all_of(
                pair.initiator->handshake_material.hash.bytes,
                [](std::uint8_t byte) { return byte == 0; }),
        "zero-key expiry retained session or handshake secrets");
    WGNX_TEST_REQUIRE(
        context,
        pair.initiator->handshake_material.precomputed_static_static.valid &&
            pair.initiator->handshake_material.precomputed_static_static.bytes == precomputed &&
            pair.initiator->static_identity.static_private.valid &&
            pair.initiator->static_identity.static_private.bytes == static_private &&
            pair.initiator->cookie.valid &&
            std::ranges::all_of(
                pair.initiator->cookie.value,
                [](std::uint8_t byte) { return byte == 0x6A; }),
        "zero-key expiry erased configured identity, precomputation, or cookie state");
}

} // namespace wgnx::test
