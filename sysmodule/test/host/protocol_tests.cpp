#include "protocol_tests.hpp"

#include "test_framework.hpp"
#include "test_runtime.hpp"

#include "runtime/packet_channel.hpp"
#include "runtime/packet_data_plane.hpp"
#include "runtime/endpoint_resolver.hpp"
#include "runtime/peer_runtime.hpp"
#include "runtime/runtime_coordinator.hpp"
#include "runtime/runtime_contracts.hpp"
#include "runtime/timer_schedule.hpp"
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

void TestHandshakeInitiationAdmission(TestContext &context) {
    using namespace wgnx::wireguard;

    runtime::Reset(InitialRuntimeState);
    ProtocolPair pair{};
    WGNX_TEST_REQUIRE(context, pair.Initialize(), "protocol pair initialization failed");

    std::array<std::uint8_t, HandshakeInitiationSize> first_packet{};
    message_handshake_initiation first{};
    WGNX_TEST_REQUIRE(
        context,
        pair.CreateAndSendInitiation(&first_packet) &&
            ParseHandshakeInitiation(first_packet, first).success &&
            noise_handshake_consume_initiation(&first, pair.responder),
        "first authenticated initiation was not admitted");
    WGNX_TEST_REQUIRE(
        context,
        !noise_handshake_consume_initiation(&first, pair.responder),
        "identical initiation timestamp bypassed replay admission");

    runtime::SetRealtime({
        .tv_sec = InitialRuntimeState.realtime.tv_sec + 1,
        .tv_nsec = InitialRuntimeState.realtime.tv_nsec,
    });
    runtime::SetMonotonicTime(
        InitialMonotonicTime + std::chrono::milliseconds{1}.count() * 1'000'000);
    message_handshake_initiation second{};
    std::array<std::uint8_t, HandshakeInitiationSize> second_packet{};
    WGNX_TEST_REQUIRE(
        context,
        wg_device_create_handshake_initiation(&pair.initiator_device, &second) &&
            SerializeHandshakeInitiation(second_packet, second) == ParseError::None &&
            !noise_handshake_consume_initiation(&second, pair.responder),
        "new initiation bypassed the upstream 20 ms flood interval");

    runtime::SetMonotonicTime(
        InitialMonotonicTime + std::chrono::milliseconds{21}.count() * 1'000'000);
    WGNX_TEST_REQUIRE(
        context,
        noise_handshake_consume_initiation(&second, pair.responder),
        "new initiation was not admitted after the flood interval elapsed");

    second.macs.mac1[0] ^= 0x80U;
    runtime::SetRealtime({
        .tv_sec = InitialRuntimeState.realtime.tv_sec + 2,
        .tv_nsec = InitialRuntimeState.realtime.tv_nsec,
    });
    runtime::SetMonotonicTime(
        InitialMonotonicTime + std::chrono::milliseconds{42}.count() * 1'000'000);
    WGNX_TEST_REQUIRE(
        context,
        !noise_handshake_consume_initiation(&second, pair.responder),
        "tampered initiation mac1 was admitted");
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

void TestPacketChannelOwnership(TestContext &context) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::wireguard;

    PacketChannel channel{};
    WGNX_TEST_REQUIRE(
        context,
        channel.Claim(100) == 0 && channel.IsOwnedBy(100),
        "packet channel did not establish ownership");

    InnerPacketRecord received{.packet_id = 3};
    WGNX_TEST_REQUIRE(
        context,
        channel.PushReceived(received) == QueuePushResult::Pushed &&
            channel.ReceivedSize() == 1,
        "packet channel did not retain a received packet");
    WGNX_TEST_REQUIRE(
        context,
        channel.Claim(200) == 1 && channel.IsOwnedBy(200) &&
            !channel.IsOwnedBy(100) && channel.ReceivedSize() == 0 &&
            channel.Statistics().cleared == 1,
        "packet channel ownership transfer retained the previous consumer's packets");
    WGNX_TEST_REQUIRE(
        context,
        channel.Release() == 0 && channel.ConsumerId() == 0,
        "packet channel release retained its consumer identity");
}

void TestPacketDataPlane(TestContext &context) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::wireguard;

    runtime::Reset(InitialRuntimeState);
    std::array<wgnx::PeerConfigEntry, 1> configured{};
    FillConfig(
        &configured[0],
        "data-plane",
        "10.66.66.2/32",
        InitiatorPrivateKey,
        ResponderPublicKey);
    PeerRegistry registry{};
    WGNX_TEST_REQUIRE(
        context,
        registry.Assign(configured) && registry.SetActivePeerIndex(0),
        "packet data plane registry initialization failed");
    auto &peer = registry[0];
    WGNX_TEST_REQUIRE(
        context,
        wg_device_init_from_config_entry(&peer.protocol.device, peer.config),
        "packet data plane protocol initialization failed");
    peer.protocol.instantiated = true;
    WGNX_TEST_REQUIRE(
        context,
        peer.BeginActivation(1'000) == 1 && peer.EnterHandshaking(1, 2'000),
        "packet data plane lifecycle initialization failed");

    RuntimeCoordinator coordinator{registry};
    PacketChannel channel{};
    PacketDataPlane data_plane{registry, coordinator, channel};
    EffectBatch effects{};
    constexpr std::array<std::uint8_t, 20> Ipv4Packet = {
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
        0xE2, 0x52, 0x0A, 0x42, 0x42, 0x02, 0x0A, 0x42, 0x42, 0x01,
    };
    constexpr std::array<std::uint8_t, 40> Ipv6Packet = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFD, 0x40,
        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    const PeerIdentity identity{.peer_index = 0, .activation_generation = 1};
    const auto retry_deadline = TimerDeadlineFromJiffies(500);

    const auto first = data_plane.SubmitIpv4Packet(
        Ipv4Packet,
        100,
        retry_deadline,
        3'000,
        effects);
    WGNX_TEST_REQUIRE(
        context,
        first.status == PacketSubmissionStatus::Queued && first.packet_id == 1 &&
            first.peer == identity && first.ownership_transferred &&
            channel.IsOwnedBy(100) && peer.StagedInnerPacketCount() == 1,
        "packet data plane did not claim and route the first IPv4 packet");

    const auto ipv4_only = data_plane.SubmitIpv4Packet(
        Ipv6Packet,
        100,
        retry_deadline,
        3'100,
        effects);
    const auto generic = data_plane.SubmitIpPacket(
        Ipv6Packet,
        100,
        retry_deadline,
        3'200,
        effects);
    WGNX_TEST_REQUIRE(
        context,
        ipv4_only.status == PacketSubmissionStatus::MalformedPacket &&
            ipv4_only.validation == InnerIpv4ValidationError::InvalidVersion &&
            generic.status == PacketSubmissionStatus::Queued && generic.packet_id == 2 &&
            peer.StagedInnerPacketCount() == 2,
        "packet data plane did not preserve IPv4 IPC policy over the generic IP boundary");

    const auto unsupported = data_plane.DeliverDecryptedPacket(identity, Ipv6Packet);
    const auto delivered = data_plane.DeliverDecryptedPacket(identity, Ipv4Packet);
    std::array<std::uint8_t, MaxInnerIpPacketSize> output{};
    const auto denied = data_plane.ReceivePacket(output, 101);
    const auto too_small = data_plane.ReceivePacket(
        std::span<std::uint8_t>(output).first(Ipv4Packet.size() - 1),
        100);
    const auto received = data_plane.ReceivePacket(output, 100);
    WGNX_TEST_REQUIRE(
        context,
        unsupported.status == PacketDeliveryStatus::UnsupportedPacket &&
            unsupported.version == InnerIpVersion::Ipv6 &&
            delivered.status == PacketDeliveryStatus::Queued && delivered.packet_id == 3 &&
            denied.status == PacketReceiveStatus::AccessDenied &&
            too_small.status == PacketReceiveStatus::OutputBufferTooSmall &&
            received.status == PacketReceiveStatus::Success &&
            received.packet_id == delivered.packet_id &&
            std::equal(Ipv4Packet.begin(), Ipv4Packet.end(), output.begin()),
        "packet data plane delivery lost adapter capability, PID ownership, capacity, or bytes");

    for (std::size_t index = 0; index < PacketChannel::ReceiveCapacity; ++index) {
        WGNX_TEST_REQUIRE(
            context,
            data_plane.DeliverDecryptedPacket(identity, Ipv4Packet).status ==
                PacketDeliveryStatus::Queued,
            "packet data plane receive queue filled before its declared capacity");
    }
    const auto overflow = data_plane.DeliverDecryptedPacket(identity, Ipv4Packet);
    WGNX_TEST_REQUIRE(
        context,
        overflow.status == PacketDeliveryStatus::QueueFull &&
            overflow.queue_depth == PacketChannel::ReceiveCapacity &&
            channel.Statistics().rejected_full == 1,
        "packet data plane did not retain reject-new receive overflow behavior");

    const auto transfer = data_plane.SubmitIpPacket(
        Ipv6Packet,
        200,
        retry_deadline,
        4'000,
        effects);
    WGNX_TEST_REQUIRE(
        context,
        transfer.status == PacketSubmissionStatus::Queued &&
            transfer.ownership_transferred && transfer.discarded_outbound == 2 &&
            transfer.discarded_inbound == PacketChannel::ReceiveCapacity &&
            channel.IsOwnedBy(200) && channel.ReceivedSize() == 0,
        "packet data plane ownership transfer did not clear both traffic directions");

    const auto stale_packet = data_plane.DeliverDecryptedPacket(identity, Ipv4Packet);
    WGNX_TEST_REQUIRE(
        context,
        stale_packet.status == PacketDeliveryStatus::Queued &&
            registry.SetActivePeerIndex(-1),
        "packet data plane stale-delivery setup failed");
    const auto stale = data_plane.ReceivePacket(output, 200);
    WGNX_TEST_REQUIRE(
        context,
        stale.status == PacketReceiveStatus::StaleActivation &&
            channel.Statistics().stale == 1 && channel.ReceivedSize() == 0,
        "packet data plane did not reject a queued packet from a stale activation");
}

void TestRuntimeContracts(TestContext &context) {
    using namespace wgnx::sysmodule::runtime;

    WGNX_TEST_REQUIRE(
        context,
        IsValidPeerSelection(-1, 0) &&
            !IsValidPeerSelection(0, 0) &&
            !IsValidPeerSelection(-2, 8) &&
            IsValidPeerSelection(0, 8) &&
            IsValidPeerSelection(7, 8) &&
            !IsValidPeerSelection(8, 8),
        "peer selection no longer accepts exactly disabled or a configured index");

    WGNX_TEST_REQUIRE(
        context,
        BuildDaemonFlags(false, false) == wgnx::DaemonFlag_Ready &&
            BuildDaemonFlags(true, false) ==
                (wgnx::DaemonFlag_Ready | wgnx::DaemonFlag_TunnelActive) &&
            BuildDaemonFlags(false, true) ==
                (wgnx::DaemonFlag_Ready | wgnx::DaemonFlag_HasErrors) &&
            BuildDaemonFlags(true, true) ==
                (wgnx::DaemonFlag_Ready |
                 wgnx::DaemonFlag_TunnelActive |
                 wgnx::DaemonFlag_HasErrors),
        "daemon status flags diverged from active-peer or error state");

    WGNX_TEST_REQUIRE(
        context,
        BuildPeerFlags(
            true,
            true,
            true,
            wgnx::PeerRuntimeState::Error,
            true) ==
            (wgnx::PeerFlag_Active |
             wgnx::PeerFlag_AutoStart |
             wgnx::PeerFlag_Established |
             wgnx::PeerFlag_HasError |
             wgnx::PeerFlag_HasResolvedEndpoint) &&
            BuildPeerFlags(
                false,
                false,
                false,
                wgnx::PeerRuntimeState::Active,
                false) == 0,
        "peer status flags no longer project lifecycle state independently");

    WGNX_TEST_REQUIRE(
        context,
        IsCurrentGeneration(1, 1) &&
            IsCurrentGeneration(0xffffffffU, 0xffffffffU) &&
            !IsCurrentGeneration(0, 0) &&
            !IsCurrentGeneration(1, 2),
        "generation matching accepted an unallocated or stale generation");
}

void TestPeerRegistryOwnership(TestContext &context) {
    using namespace wgnx::sysmodule::runtime;

    std::array<wgnx::PeerConfigEntry, 2> configured{};
    std::snprintf(configured[0].name.data(), configured[0].name.size(), "first");
    std::snprintf(configured[1].name.data(), configured[1].name.size(), "second");

    PeerRegistry registry{};
    WGNX_TEST_REQUIRE(
        context,
        registry.Empty() && registry.ActivePeerIndex() == -1 &&
            registry.AutoStartPeerIndex() == -1 && registry.IsValidSelection(-1) &&
            !registry.IsValidSelection(0),
        "empty peer registry exposed a configured or selected peer");
    WGNX_TEST_REQUIRE(
        context,
        registry.Assign(configured) && registry.Count() == configured.size() &&
            registry.IsValidSelection(0) && registry.IsValidSelection(1) &&
            !registry.IsValidSelection(2) &&
            std::strcmp(registry[0].config.name.data(), "first") == 0 &&
            std::strcmp(registry[1].config.name.data(), "second") == 0,
        "peer registry did not preserve fixed-slot configuration identity");

    WGNX_TEST_REQUIRE(
        context,
        registry.SetActivePeerIndex(1) && registry.SetAutoStartPeerIndex(0) &&
            !registry.SetActivePeerIndex(2) && !registry.SetAutoStartPeerIndex(-2),
        "peer registry accepted an out-of-range selection");
    WGNX_TEST_REQUIRE(
        context,
        registry[0].BeginActivation(6) == 1,
        "peer registry test could not establish an error activation");
    registry[0].EnterError(
        wgnx::PeerErrorStage::Internal,
        wgnx::PeerErrorCode::InternalFailure,
        7);
    WGNX_TEST_REQUIRE(
        context,
        registry[1].BeginActivation(8) == 1 &&
            registry[1].EnterHandshaking(1, 9) &&
            registry[1].EnterActive(1, 10),
        "peer registry test could not establish an active lifecycle");
    registry[1].derived.secrets_valid = true;
    registry[1].protocol.instantiated = true;
    const wgnx::wireguard::TimerOwner timer_owner{
        .peer_index = 1,
        .activation_generation = 1,
    };
    const auto timer = registry[1].controller.Timers().Arm(
        wgnx::wireguard::TimerHook::SendKeepalive,
        timer_owner);

    WGNX_TEST_REQUIRE(
        context,
        registry.ActivePeerIndex() == 1 && registry.AutoStartPeerIndex() == 0 &&
            registry[0].Lifecycle().state == wgnx::PeerRuntimeState::Error &&
            registry[0].Lifecycle().activation_generation == 1 &&
            !registry[0].derived.secrets_valid &&
            !registry[0].protocol.instantiated &&
            registry[1].Lifecycle().state == wgnx::PeerRuntimeState::Active &&
            registry[1].Lifecycle().activation_generation == 1 &&
            registry[1].derived.secrets_valid &&
            registry[1].protocol.instantiated &&
            registry[1].controller.Timers().IsCurrent(timer, timer_owner) &&
            !registry[0].controller.Timers().IsArmed(
                wgnx::wireguard::TimerHook::SendKeepalive),
        "peer runtime slots did not isolate index-correlated mutable state");

    registry.ClearConfiguration();
    WGNX_TEST_REQUIRE(
        context,
        registry.Empty() && registry.ActivePeerIndex() == -1 &&
            registry.AutoStartPeerIndex() == -1 && registry.IsValidSelection(-1) &&
            !registry.IsValidSelection(0),
        "clearing peer configuration retained selection state");
}

void TestPeerRuntimeLifecycle(TestContext &context) {
    using namespace wgnx::sysmodule::runtime;

    PeerRuntime peer{};
    std::snprintf(peer.config.name.data(), peer.config.name.size(), "lifecycle");
    peer.config.persistent_keepalive = 25;
    peer.Deactivate(1'000);
    WGNX_TEST_REQUIRE(
        context,
        peer.Lifecycle().state == wgnx::PeerRuntimeState::Inactive &&
            peer.Lifecycle().activation_generation == 0 &&
            peer.Lifecycle().persistent_keepalive_interval == 25,
        "inactive lifecycle diverged");

    WGNX_TEST_REQUIRE(
        context,
        peer.BeginActivation(3'000) == 1 &&
            peer.Lifecycle().state == wgnx::PeerRuntimeState::ResolvingEndpoint &&
            peer.IsCurrentActivation(1) && !peer.IsCurrentActivation(2) &&
            peer.AcceptsInnerPacketSubmission() && !peer.IsInTransportState() &&
            !peer.EnterHandshaking(2, 4'000) &&
            peer.Lifecycle().state == wgnx::PeerRuntimeState::ResolvingEndpoint,
        "activation start or stale handshaking transition diverged");

    WGNX_TEST_REQUIRE(
        context,
        peer.EnterHandshaking(1, 5'000) && peer.IsInTransportState() &&
            !peer.EnterActive(2, 6'000) &&
            peer.Lifecycle().state == wgnx::PeerRuntimeState::Handshaking &&
            peer.EnterActive(1, 7'000) &&
            peer.Lifecycle().state == wgnx::PeerRuntimeState::Active &&
            peer.Lifecycle().established &&
            peer.Lifecycle().last_handshake_ns == 7'000,
        "handshaking or active lifecycle transition diverged");

    peer.RecordReceivedBytes(40, 8'000);
    peer.RecordTransmittedBytes(60, 9'000);
    WGNX_TEST_REQUIRE(
        context,
        peer.SetDebugProbeState(
            wgnx::DebugTriggerAction::PingTunnelPeer,
            wgnx::DebugProbeStatus::Queued,
            10'000) &&
            peer.Lifecycle().rx_bytes == 40 && peer.Lifecycle().tx_bytes == 60 &&
            peer.Lifecycle().last_rx_ns == 8'000 &&
            peer.Lifecycle().last_tx_ns == 9'000,
        "peer-owned metrics or debug state diverged");

    const auto active_info = peer.BuildInfo(10'000, true, false);
    WGNX_TEST_REQUIRE(
        context,
        active_info.runtime_state == static_cast<std::uint8_t>(wgnx::PeerRuntimeState::Active) &&
            active_info.rx_bytes == 40 && active_info.tx_bytes == 60 &&
            active_info.persistent_keepalive_interval == 25 &&
            (active_info.flags & wgnx::PeerFlag_Active) != 0 &&
            (active_info.flags & wgnx::PeerFlag_Established) != 0 &&
            (active_info.flags & wgnx::PeerFlag_HasError) == 0,
        "active peer status snapshot diverged from lifecycle state");

    peer.EnterError(
        wgnx::PeerErrorStage::Transport,
        wgnx::PeerErrorCode::TransportReceiveFailed,
        11'000);
    const auto error_info = peer.BuildInfo(11'000, false, true);
    WGNX_TEST_REQUIRE(
        context,
        error_info.runtime_state == static_cast<std::uint8_t>(wgnx::PeerRuntimeState::Error) &&
            error_info.error_stage == static_cast<std::uint8_t>(wgnx::PeerErrorStage::Transport) &&
            error_info.last_error_code ==
                static_cast<std::uint32_t>(wgnx::PeerErrorCode::TransportReceiveFailed) &&
            (error_info.flags & wgnx::PeerFlag_AutoStart) != 0 &&
            (error_info.flags & wgnx::PeerFlag_HasError) != 0 &&
            (error_info.flags & wgnx::PeerFlag_Established) == 0,
        "error status snapshot diverged from lifecycle state");

    peer.Deactivate(12'000);
    WGNX_TEST_REQUIRE(
        context,
        peer.Lifecycle().state == wgnx::PeerRuntimeState::Inactive &&
            peer.Lifecycle().activation_generation == 0 &&
            peer.Lifecycle().rx_bytes == 0 && peer.Lifecycle().tx_bytes == 0 &&
            peer.Lifecycle().debug_probe_status == wgnx::DebugProbeStatus::None,
        "deactivation retained activation, metrics, or debug state");
}

void TestRuntimeCoordinatorDispatch(TestContext &context) {
    using namespace wgnx::sysmodule::runtime;

    std::array<wgnx::PeerConfigEntry, 1> configured{};
    PeerRegistry registry{};
    WGNX_TEST_REQUIRE(
        context,
        registry.Assign(configured) && registry.SetActivePeerIndex(0) &&
            registry[0].BeginActivation(1'000) == 1 &&
            registry[0].EnterHandshaking(1, 2'000),
        "coordinator test could not establish handshaking state");

    RuntimeCoordinator coordinator{registry};
    const auto out_of_range = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = {.peer_index = 1, .activation_generation = 1},
        .occurred_at = 3'000,
    });
    const auto stale = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = {.peer_index = 0, .activation_generation = 2},
        .occurred_at = 3'000,
    });
    WGNX_TEST_REQUIRE(
        context,
        out_of_range.Empty() && stale.Empty() &&
            registry[0].Lifecycle().state == wgnx::PeerRuntimeState::Handshaking &&
            registry[0].Lifecycle().activation_generation == 1,
        "coordinator accepted an out-of-range or stale event");

    const auto effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = {.peer_index = 0, .activation_generation = 1},
        .occurred_at = 4'000,
    });
    WGNX_TEST_REQUIRE(
        context,
        effects.Empty() &&
            registry[0].Lifecycle().state == wgnx::PeerRuntimeState::Handshaking,
        "coordinator accepted session completion without protocol state");

    EffectBatch bounded{};
    const RuntimeEffect effect = QueueInnerPacketSubmissionEffect{
        .peer = {.peer_index = 0, .activation_generation = 1},
    };
    bool filled = true;
    for (std::size_t index = 0; index < EffectBatch::Capacity; ++index) {
        filled = filled && bounded.Push(effect);
    }
    WGNX_TEST_REQUIRE(
        context,
        filled && bounded.Size() == EffectBatch::Capacity && !bounded.Push(effect),
        "runtime effect batch did not enforce fixed capacity");

    EffectBatch first{};
    EffectBatch second{};
    WGNX_TEST_REQUIRE(
        context,
        first.Push(QueueReceiveEffect{
            .peer = {.peer_index = 0, .activation_generation = 1},
        }) &&
            second.Push(SendPendingDatagramEffect{
                .peer = {.peer_index = 0, .activation_generation = 1},
                .datagram_generation = 7,
            }) &&
            first.Append(second) && first.Size() == 2 &&
            std::holds_alternative<QueueReceiveEffect>(*first.begin()) &&
            std::holds_alternative<SendPendingDatagramEffect>(*(first.begin() + 1)) &&
            !bounded.Append(second) && bounded.Size() == EffectBatch::Capacity,
        "runtime effect batch append lost ordering or violated bounded capacity");
    bounded.Clear();
    WGNX_TEST_REQUIRE(
        context,
        bounded.Empty() && bounded.Push(effect) && bounded.Size() == 1,
        "runtime effect batch could not be reused by the ordered receive worker");
}

void TestRuntimePeerActivation(TestContext &context) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::wireguard;

    runtime::Reset(InitialRuntimeState);
    std::array<wgnx::PeerConfigEntry, 1> configured{};
    FillConfig(
        &configured[0],
        "activation",
        "10.66.66.2/32",
        InitiatorPrivateKey,
        ResponderPublicKey);

    PeerRegistry registry{};
    WGNX_TEST_REQUIRE(
        context,
        registry.Assign(configured) && registry.SetActivePeerIndex(0),
        "activation test registry initialization failed");
    auto &peer = registry[0];
    peer.derived.secrets_valid =
        noise_parse_private_key(
            &peer.derived.local_private_key,
            InitiatorPrivateKey) &&
        noise_parse_preshared_key(
            &peer.derived.preshared_key,
            PresharedKey);
    peer.derived.has_preshared_key = true;

    RuntimeCoordinator coordinator{registry};
    const auto activation = coordinator.Dispatch(ActivationRequestedEvent{
        .peer_index = 0,
        .occurred_at = 1'000,
    });
    const auto *resolve = activation.Size() == 1
        ? std::get_if<ResolveEndpointEffect>(activation.begin())
        : nullptr;
    const PeerIdentity expected_activation{.peer_index = 0, .activation_generation = 1};
    WGNX_TEST_REQUIRE(
        context,
        resolve != nullptr && resolve->peer == expected_activation &&
            std::strcmp(resolve->endpoint.data(), "peer.test:51820") == 0 &&
            peer.Lifecycle().state == wgnx::PeerRuntimeState::ResolvingEndpoint &&
            !peer.protocol.instantiated,
        "activation did not enter resolution with a generation-tagged request");

    EndpointResolver resolver{};
    ResolveEndpointEffect replacement = *resolve;
    replacement.peer.activation_generation = 2;
    const bool first_resolve_scheduled = resolver.Queue(*resolve);
    const bool replacement_resolve_scheduled = resolver.Queue(replacement);
    const auto latest_resolve = resolver.Take();
    WGNX_TEST_REQUIRE(
        context,
        first_resolve_scheduled && !replacement_resolve_scheduled &&
            latest_resolve.has_value() && latest_resolve->peer == replacement.peer &&
            !resolver.Take().has_value(),
        "endpoint resolver did not coalesce pending work under one scheduled worker");
    resolver.MarkWorkerIdle();
    WGNX_TEST_REQUIRE(
        context,
        resolver.Queue(*resolve),
        "idle endpoint resolver did not request worker scheduling");

    wgnx::platform::endpoint_resolution_result resolved{
        .success = true,
        .resolved = {
            .family = wgnx::platform::address_family::inet,
            .port = 51820,
            .address = {192, 0, 2, 1},
        },
    };
    std::snprintf(resolved.text.data(), resolved.text.size(), "192.0.2.1:51820");
    const auto stale_resolution = coordinator.Dispatch(EndpointResolvedEvent{
        .peer = {.peer_index = 0, .activation_generation = 2},
        .result = resolved,
        .occurred_at = 2'000,
    });
    WGNX_TEST_REQUIRE(
        context,
        stale_resolution.Empty() && !peer.protocol.instantiated,
        "stale endpoint completion mutated protocol state");

    const auto resolution = coordinator.Dispatch(EndpointResolvedEvent{
        .peer = {.peer_index = 0, .activation_generation = 1},
        .result = resolved,
        .occurred_at = 2'000,
    });
    const auto *open = resolution.Size() == 1
        ? std::get_if<OpenUdpBindEffect>(resolution.begin())
        : nullptr;
    WGNX_TEST_REQUIRE(
        context,
        open != nullptr && open->socket_generation != 0 &&
            !peer.protocol.instantiated && peer.binding.HasEndpoint(),
        "resolution did not request a UDP bind before protocol instantiation");

    const auto opened = coordinator.Dispatch(UdpBindOpenedEvent{
        .peer = open->peer,
        .endpoint = open->endpoint,
        .endpoint_text = open->endpoint_text,
        .socket = 42,
        .error = wgnx::platform::socket_error::none,
        .socket_generation = open->socket_generation,
        .retry_deadline = TimerDeadlineFromJiffies(500),
        .occurred_at = 3'000,
    });
    const auto *send = opened.Size() > 1
        ? std::get_if<SendPendingDatagramEffect>(opened.begin() + 1)
        : nullptr;
    WGNX_TEST_REQUIRE(
        context,
        opened.Size() == 3 && send != nullptr &&
            std::get_if<ArmProtocolTimerEffect>(opened.begin()) != nullptr &&
            std::get_if<QueueReceiveEffect>(opened.begin() + 2) != nullptr &&
            peer.Lifecycle().state == wgnx::PeerRuntimeState::Handshaking &&
            peer.protocol.instantiated &&
            peer.binding.Matches(open->socket_generation, 42),
        "opened bind did not deterministically start the first handshake");

    PendingDatagramSnapshot snapshot{};
    WGNX_TEST_REQUIRE(
        context,
        peer.SnapshotPendingDatagram(1, send->datagram_generation, snapshot) &&
            snapshot.size == HandshakeInitiationSize,
        "initial handshake effect did not reference a peer-owned datagram");
    const auto sent = coordinator.Dispatch(PendingDatagramSentEvent{
        .peer = send->peer,
        .datagram_generation = send->datagram_generation,
        .bytes_sent = snapshot.size,
        .error = wgnx::platform::socket_error::none,
        .occurred_at = 4'000,
    });
    WGNX_TEST_REQUIRE(
        context,
        sent.Empty() && peer.Lifecycle().tx_bytes == HandshakeInitiationSize &&
            !peer.SnapshotPendingDatagram(1, send->datagram_generation, snapshot),
        "handshake send completion did not retire pending transport state");

    PeerRegistry failed_registry{};
    std::array<wgnx::PeerConfigEntry, 1> invalid{};
    RuntimeCoordinator failed_coordinator{failed_registry};
    WGNX_TEST_REQUIRE(
        context,
        failed_registry.Assign(invalid) && failed_registry.SetActivePeerIndex(0),
        "failure-path registry initialization failed");
    const auto invalid_effects = failed_coordinator.Dispatch(ActivationRequestedEvent{
        .peer_index = 0,
        .occurred_at = 5'000,
    });
    WGNX_TEST_REQUIRE(
        context,
        invalid_effects.Empty() &&
            failed_registry[0].Lifecycle().state == wgnx::PeerRuntimeState::Error &&
            failed_registry[0].Lifecycle().error_stage == wgnx::PeerErrorStage::Config,
        "invalid activation did not fail before platform work");
}

void TestRuntimeOutboundLifecycle(TestContext &context) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::wireguard;

    runtime::Reset(InitialRuntimeState);
    std::array<wgnx::PeerConfigEntry, 1> configured{};
    FillConfig(
        &configured[0],
        "runtime-outbound",
        "10.66.66.2/32",
        InitiatorPrivateKey,
        ResponderPublicKey);
    PeerRegistry registry{};
    WGNX_TEST_REQUIRE(
        context,
        registry.Assign(configured) && registry.SetActivePeerIndex(0),
        "outbound runtime registry initialization failed");
    auto &runtime_peer = registry[0];
    WGNX_TEST_REQUIRE(
        context,
        wg_device_init_from_config_entry(
            &runtime_peer.protocol.device,
            runtime_peer.config),
        "outbound runtime protocol initialization failed");
    runtime_peer.protocol.instantiated = true;
    WGNX_TEST_REQUIRE(
        context,
        runtime_peer.BeginActivation(1'000) == 1 &&
            runtime_peer.EnterHandshaking(1, 2'000),
        "outbound runtime lifecycle initialization failed");
    runtime_peer.binding.AdoptOpenSocket(
        wgnx::platform::endpoint{
            .family = wgnx::platform::address_family::inet,
            .port = 51820,
            .address = {192, 0, 2, 1},
        },
        "192.0.2.1:51820",
        1,
        91);

    RuntimeCoordinator coordinator{registry};
    constexpr std::array<std::uint8_t, 20> FirstPacket = {
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
        0x00, 0x00, 0x0A, 0x42, 0x42, 0x02, 0x0A, 0x42, 0x42, 0x01,
    };
    const PeerIdentity identity{.peer_index = 0, .activation_generation = 1};
    const auto retry_deadline = TimerDeadlineFromJiffies(500);
    auto effects = coordinator.Dispatch(InnerPacketStagedEvent{
        .peer = identity,
        .packet = FirstPacket,
        .packet_id = 61,
        .retry_deadline = retry_deadline,
        .occurred_at = 3'000,
    });
    const auto *send = effects.Size() > 1
        ? std::get_if<SendPendingDatagramEffect>(effects.begin() + 1)
        : nullptr;
    const auto *initial_arm = effects.Size() > 0
        ? std::get_if<ArmProtocolTimerEffect>(effects.begin())
        : nullptr;
    WGNX_TEST_REQUIRE(
        context,
        effects.Size() == 2 && initial_arm != nullptr &&
            initial_arm->token.IsValid() && send != nullptr &&
            runtime_peer.StagedInnerPacketCount() == 1,
        "staged packet did not start the production handshake path");

    const auto stale_timer_token = initial_arm->token;
    auto timer_token = runtime_peer.controller.Timers().Arm(
        TimerHook::RetransmitHandshake,
        stale_timer_token.owner);
    const auto stale_timer_effects = coordinator.Dispatch(ProtocolTimerExpiredEvent{
        .peer = identity,
        .hook = TimerHook::RetransmitHandshake,
        .token = stale_timer_token,
        .retry_deadline = retry_deadline,
        .zero_key_material_deadline = TimerDeadlineFromJiffies(5'000),
        .occurred_at = 3'500,
    });
    const TimerOwner current_timer_owner{
        .peer_index = identity.peer_index,
        .activation_generation = identity.activation_generation,
        .protocol_sequence = timer_token.owner.protocol_sequence,
    };
    WGNX_TEST_REQUIRE(
        context,
        stale_timer_effects.Empty() &&
            runtime_peer.controller.Timers().IsCurrent(
                timer_token,
                current_timer_owner),
        "stale queued timer delivery mutated the peer runtime");

    PendingDatagramSnapshot snapshot{};
    constexpr std::uint32_t MaxSendAttempts = MaxTimerHandshakes + 2;
    for (std::uint32_t attempt = 1; attempt <= MaxSendAttempts; ++attempt) {
        WGNX_TEST_REQUIRE(
            context,
            send != nullptr && runtime_peer.SnapshotPendingDatagram(
                1,
                send->datagram_generation,
                snapshot) && snapshot.size == HandshakeInitiationSize,
            "runtime retry did not expose a fresh pending initiation");
        effects = coordinator.Dispatch(PendingDatagramSentEvent{
            .peer = identity,
            .datagram_generation = send->datagram_generation,
            .bytes_sent = snapshot.size,
            .error = wgnx::platform::socket_error::none,
            .occurred_at = 4'000 + attempt,
        });
        WGNX_TEST_REQUIRE(
            context,
            effects.Empty(),
            "successful handshake submission produced an unexpected follow-up");
        if (attempt == MaxSendAttempts) {
            break;
        }
        effects = coordinator.Dispatch(ProtocolTimerExpiredEvent{
            .peer = identity,
            .hook = TimerHook::RetransmitHandshake,
            .token = timer_token,
            .retry_deadline = retry_deadline,
            .zero_key_material_deadline = TimerDeadlineFromJiffies(5'000),
            .occurred_at = 5'000 + attempt,
        });
        send = effects.Size() > 2
            ? std::get_if<SendPendingDatagramEffect>(effects.begin() + 2)
            : nullptr;
        const auto *retry_arm = effects.Size() > 1
            ? std::get_if<ArmProtocolTimerEffect>(effects.begin() + 1)
            : nullptr;
        WGNX_TEST_REQUIRE(
            context,
            effects.Size() == 3 &&
                std::get_if<CancelProtocolTimerEffect>(effects.begin()) != nullptr &&
                retry_arm != nullptr && retry_arm->token.IsValid() &&
                send != nullptr,
            "runtime retry expiration did not request a fresh initiation");
        timer_token = retry_arm->token;
    }

    effects = coordinator.Dispatch(ProtocolTimerExpiredEvent{
        .peer = identity,
        .hook = TimerHook::RetransmitHandshake,
        .token = timer_token,
        .retry_deadline = retry_deadline,
        .zero_key_material_deadline = TimerDeadlineFromJiffies(5'000),
        .occurred_at = 7'000,
    });
    WGNX_TEST_REQUIRE(
        context,
        effects.Size() == 2 &&
            std::get_if<CancelProtocolTimerEffect>(effects.begin()) != nullptr &&
            std::get_if<ArmProtocolTimerEffect>(effects.begin() + 1) != nullptr &&
            runtime_peer.StagedInnerPacketCount() == 0,
        "runtime retry exhaustion did not drop and account for staged traffic");

    constexpr std::array<std::uint8_t, 20> RecoveryPacket = {
        0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
        0x00, 0x00, 0x0A, 0x42, 0x42, 0x02, 0x0A, 0x42, 0x42, 0x01,
    };
    effects = coordinator.Dispatch(InnerPacketStagedEvent{
        .peer = identity,
        .packet = RecoveryPacket,
        .packet_id = 62,
        .retry_deadline = retry_deadline,
        .occurred_at = 8'000,
    });
    send = effects.Size() > 1
        ? std::get_if<SendPendingDatagramEffect>(effects.begin() + 1)
        : nullptr;
    WGNX_TEST_REQUIRE(
        context,
        send != nullptr && runtime_peer.SnapshotPendingDatagram(
            1,
            send->datagram_generation,
            snapshot),
        "later traffic did not begin a fresh runtime handshake");

    ProtocolPair responder{};
    WGNX_TEST_REQUIRE(context, responder.Initialize(), "recovery responder initialization failed");
    WGNX_TEST_REQUIRE(
        context,
        responder.initiator_to_responder.Send(
            std::span<const std::uint8_t>(snapshot.bytes).first(snapshot.size)) &&
            responder.ReceiveInitiationAndSendResponse(),
        "runtime initiation did not produce a responder handshake");
    std::span<const std::uint8_t> response{};
    WGNX_TEST_REQUIRE(
        context,
        responder.responder_to_initiator.Receive(response),
        "runtime peer did not receive the recovery response");
    effects = coordinator.Dispatch(PendingDatagramSentEvent{
        .peer = identity,
        .datagram_generation = send->datagram_generation,
        .bytes_sent = snapshot.size,
        .error = wgnx::platform::socket_error::none,
        .occurred_at = 9'000,
    });
    runtime::SetMonotonicTime(SessionBirthTime);
    WGNX_TEST_REQUIRE(
        context,
        effects.Empty() && noise_handshake_begin_session(
            &responder.responder_device,
            responder.responder),
        "responder session derivation failed");
    effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = identity,
        .packet = response,
        .source = {
            .family = wgnx::platform::address_family::inet,
            .port = 51820,
            .address = {192, 0, 2, 1},
        },
        .source_text = {"192.0.2.1:51820"},
        .keepalive_deadline = TimerDeadlineFromJiffies(600),
        .rekey_deadline = TimerDeadlineFromJiffies(700),
        .zero_key_material_deadline = TimerDeadlineFromJiffies(800),
        .occurred_at = SessionBirthTime,
    });
    send = nullptr;
    for (const auto &effect : effects) {
        if (auto *candidate = std::get_if<SendPendingDatagramEffect>(&effect)) {
            send = candidate;
        }
    }
    WGNX_TEST_REQUIRE(
        context,
        effects.Size() == 6 && send != nullptr &&
            runtime_peer.Lifecycle().state == wgnx::PeerRuntimeState::Active,
        "session establishment did not arm timers and release outbound work");

    WGNX_TEST_REQUIRE(
        context,
        runtime_peer.SnapshotPendingDatagram(1, send->datagram_generation, snapshot),
        "session confirmation keepalive was not staged");
    std::array<
        std::uint8_t,
        GetPaddedTransportPayloadSize(wgnx::wireguard::MaxInnerIpv4PacketSize)>
        responder_plaintext{};
    IncomingTransportDataResult responder_confirmation{};
    WGNX_TEST_REQUIRE(
        context,
        noise_consume_incoming_transport_data_packet(
            std::span<const std::uint8_t>(snapshot.bytes).first(snapshot.size),
            responder.responder_device,
            *responder.responder,
            responder_plaintext,
            responder_confirmation) == TransportDataError::None &&
            responder_confirmation.promoted_next_keypair &&
            responder.responder->current_keypair.IsValid(),
        "responder did not confirm the initial runtime session");
    effects = coordinator.Dispatch(PendingDatagramSentEvent{
        .peer = identity,
        .datagram_generation = send->datagram_generation,
        .bytes_sent = snapshot.size,
        .error = wgnx::platform::socket_error::none,
        .occurred_at = SessionBirthTime + 1,
    });
    WGNX_TEST_REQUIRE(context, effects.Empty(), "keepalive completion mutated queue policy");

    effects = coordinator.Dispatch(ProcessOutboundQueueEvent{
        .peer = identity,
        .retry_deadline = retry_deadline,
        .occurred_at = SessionBirthTime + 2,
    });
    send = effects.Size() == 1
        ? std::get_if<SendPendingDatagramEffect>(effects.begin())
        : nullptr;
    WGNX_TEST_REQUIRE(
        context,
        send != nullptr && runtime_peer.SnapshotPendingDatagram(
            1,
            send->datagram_generation,
            snapshot) && snapshot.size > TransportDataHeaderSize,
        "recovered plaintext was not converted to encrypted transport data");
    effects = coordinator.Dispatch(PendingDatagramSentEvent{
        .peer = identity,
        .datagram_generation = send->datagram_generation,
        .bytes_sent = snapshot.size,
        .error = wgnx::platform::socket_error::none,
        .occurred_at = SessionBirthTime + 3,
    });
    WGNX_TEST_REQUIRE(
        context,
        effects.Size() == 1 &&
            std::get_if<QueueInnerPacketSubmissionEffect>(effects.begin()) != nullptr &&
            runtime_peer.StagedInnerPacketCount() == 0,
        "successful transport completion did not retire and continue the queue");

    const std::uint32_t previous_runtime_index =
        runtime_peer.protocol.device.peer.current_keypair.LocalIndex();
    runtime::SetMonotonicTime(SessionBirthTime + wgnx::platform::NSEC_PER_SEC);
    runtime::SetRealtime({
        .tv_sec = InitialRuntimeState.realtime.tv_sec + 1,
        .tv_nsec = InitialRuntimeState.realtime.tv_nsec,
    });
    message_handshake_initiation peer_initiation{};
    std::array<std::uint8_t, HandshakeInitiationSize> peer_initiation_packet{};
    WGNX_TEST_REQUIRE(
        context,
        wg_device_create_handshake_initiation(
            &responder.responder_device,
            &peer_initiation) &&
            SerializeHandshakeInitiation(
                peer_initiation_packet,
                peer_initiation) == ParseError::None,
        "remote peer did not create a rotation initiation");

    const wgnx::platform::endpoint roamed_endpoint{
        .family = wgnx::platform::address_family::inet,
        .port = 51999,
        .address = {198, 51, 100, 44},
    };
    effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = identity,
        .packet = peer_initiation_packet,
        .source = roamed_endpoint,
        .source_text = {"198.51.100.44:51999"},
        .keepalive_deadline = TimerDeadlineFromJiffies(900),
        .zero_key_material_deadline = TimerDeadlineFromJiffies(1'000),
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC,
    });
    send = effects.Size() == 3
        ? std::get_if<SendPendingDatagramEffect>(effects.begin() + 2)
        : nullptr;
    WGNX_TEST_REQUIRE(
        context,
        send != nullptr &&
            runtime_peer.protocol.device.peer.current_keypair.LocalIndex() ==
                previous_runtime_index &&
            runtime_peer.protocol.device.peer.next_keypair.IsValid() &&
            runtime_peer.binding.Endpoint().port == roamed_endpoint.port &&
            runtime_peer.binding.Endpoint().address == roamed_endpoint.address,
        "authenticated initiation did not preserve the current session and roam the endpoint");

    WGNX_TEST_REQUIRE(
        context,
        runtime_peer.SnapshotPendingDatagram(
            identity.activation_generation,
            send->datagram_generation,
            snapshot) &&
            snapshot.kind == PendingDatagramKind::HandshakeResponse &&
            snapshot.size == HandshakeResponseSize,
        "runtime did not stage the responder handshake response");
    const auto response_packet =
        std::span<const std::uint8_t>(snapshot.bytes).first(snapshot.size);
    WGNX_TEST_REQUIRE(
        context,
        noise_handshake_consume_incoming_packet(
            response_packet,
            &responder.responder_device,
            responder.responder) == HandshakePacketOutcome::ResponseConsumed &&
            noise_handshake_begin_session(
                &responder.responder_device,
                responder.responder),
        "remote peer did not derive the responder-created session");
    effects = coordinator.Dispatch(PendingDatagramSentEvent{
        .peer = identity,
        .datagram_generation = send->datagram_generation,
        .bytes_sent = snapshot.size,
        .error = wgnx::platform::socket_error::none,
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 1,
    });
    WGNX_TEST_REQUIRE(
        context,
        effects.Empty(),
        "handshake response completion produced an unexpected follow-up");

    constexpr std::array<std::uint8_t, 20> InboundPacket = {
        0x45, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x40, 0x11,
        0xE2, 0x50, 0x0A, 0x42, 0x42, 0x01, 0x0A, 0x42, 0x42, 0x02,
    };
    std::array<std::uint8_t, MaxEncryptedDatagramSize> inbound_datagram{};
    const auto inbound_create = noise_create_transport_data_packet(
        inbound_datagram,
        responder.responder->current_keypair,
        InboundPacket);
    WGNX_TEST_REQUIRE(
        context,
        inbound_create.error == TransportDataError::None,
        "remote peer did not create responder-session transport data");
    const auto inbound_packet = std::span<const std::uint8_t>(inbound_datagram).first(
        inbound_create.packet_size);
    effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = identity,
        .packet = inbound_packet,
        .source = roamed_endpoint,
        .source_text = {"198.51.100.44:51999"},
        .keepalive_deadline = TimerDeadlineFromJiffies(1'100),
        .rekey_deadline = TimerDeadlineFromJiffies(1'200),
        .zero_key_material_deadline = TimerDeadlineFromJiffies(1'300),
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 2,
    });
    const PublishDecryptedPacketEffect *publish = nullptr;
    for (const auto &effect : effects) {
        if (const auto *candidate = std::get_if<PublishDecryptedPacketEffect>(&effect)) {
            publish = candidate;
        }
    }
    DecryptedPacketView decrypted{};
    WGNX_TEST_REQUIRE(
        context,
        publish != nullptr && runtime_peer.ViewDecryptedPacket(
            identity.activation_generation,
            publish->packet_generation,
            decrypted) &&
            std::ranges::equal(decrypted.packet, InboundPacket) &&
            runtime_peer.protocol.device.peer.current_keypair.LocalIndex() !=
                previous_runtime_index &&
            runtime_peer.protocol.device.peer.previous_keypair.LocalIndex() ==
                previous_runtime_index &&
            !runtime_peer.protocol.device.peer.next_keypair.IsValid(),
        "first responder-session transport packet did not promote and publish atomically");

    const auto received_bytes = runtime_peer.Lifecycle().rx_bytes;
    effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = identity,
        .packet = inbound_packet,
        .source = roamed_endpoint,
        .source_text = {"198.51.100.44:51999"},
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 3,
    });
    WGNX_TEST_REQUIRE(
        context,
        effects.Empty() && runtime_peer.Lifecycle().rx_bytes == received_bytes,
        "replayed transport data changed peer state or authenticated counters");

    auto stale_datagram = inbound_datagram;
    stale_datagram[4] ^= 0x80U;
    effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = identity,
        .packet = std::span<const std::uint8_t>(stale_datagram).first(
            inbound_create.packet_size),
        .source = roamed_endpoint,
        .source_text = {"198.51.100.44:51999"},
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 4,
    });
    WGNX_TEST_REQUIRE(
        context,
        effects.Empty() && runtime_peer.Lifecycle().rx_bytes == received_bytes,
        "stale receiver index changed peer state or authenticated counters");

    const wgnx::platform::endpoint unauthenticated_endpoint{
        .family = wgnx::platform::address_family::inet,
        .port = 60000,
        .address = {203, 0, 113, 7},
    };
    constexpr std::array<std::uint8_t, 3> Malformed = {1, 2, 3};
    effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = identity,
        .packet = Malformed,
        .source = unauthenticated_endpoint,
        .source_text = {"203.0.113.7:60000"},
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 5,
    });
    WGNX_TEST_REQUIRE(
        context,
        effects.Empty() &&
            runtime_peer.binding.Endpoint().port == roamed_endpoint.port &&
            runtime_peer.binding.Endpoint().address == roamed_endpoint.address,
        "unauthenticated malformed datagram changed the roaming endpoint");

    effects = coordinator.Dispatch(EncryptedDatagramReceivedEvent{
        .peer = identity,
        .packet = peer_initiation_packet,
        .source = unauthenticated_endpoint,
        .source_text = {"203.0.113.7:60000"},
        .occurred_at = SessionBirthTime + wgnx::platform::NSEC_PER_SEC + 6,
    });
    WGNX_TEST_REQUIRE(
        context,
        effects.Empty() && runtime_peer.Lifecycle().rx_bytes == received_bytes &&
            runtime_peer.binding.Endpoint().port == roamed_endpoint.port &&
            runtime_peer.binding.Endpoint().address == roamed_endpoint.address,
        "replayed handshake initiation changed session or endpoint state");
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

void TestTimerSchedule(TestContext &context) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::wireguard;

    TimerCoordinator coordinator{};
    TimerSchedule schedule{};
    const TimerOwner owner{
        .peer_index = 2,
        .activation_generation = 9,
        .protocol_sequence = 4,
    };
    const TimerToken first = coordinator.Arm(TimerHook::RetransmitHandshake, owner);
    const auto first_deadline = TimerDeadlineFromJiffies(100);
    WGNX_TEST_REQUIRE(
        context,
        schedule.Arm(first, first_deadline) &&
            schedule.IsArmed(TimerHook::RetransmitHandshake) &&
            schedule.ArmedToken(TimerHook::RetransmitHandshake) == first &&
            schedule.Deadline(TimerHook::RetransmitHandshake) == first_deadline,
        "timer schedule did not retain an armed token and deadline");

    const TimerToken replacement = coordinator.Arm(
        TimerHook::RetransmitHandshake,
        owner);
    const auto replacement_deadline = TimerDeadlineFromJiffies(200);
    WGNX_TEST_REQUIRE(
        context,
        schedule.Arm(replacement, replacement_deadline) &&
            schedule.ArmedToken(TimerHook::RetransmitHandshake) == replacement &&
            schedule.Deadline(TimerHook::RetransmitHandshake) == replacement_deadline,
        "timer schedule replacement retained stale armed state");

    WGNX_TEST_REQUIRE(
        context,
        schedule.CaptureExpiration(TimerHook::RetransmitHandshake) &&
            !schedule.IsArmed(TimerHook::RetransmitHandshake),
        "timer expiration did not consume the physical arm");
    const TimerToken queued = schedule.TakeDelivery(TimerHook::RetransmitHandshake);
    WGNX_TEST_REQUIRE(
        context,
        queued == replacement && coordinator.IsCurrent(queued, owner) &&
            !schedule.TakeDelivery(TimerHook::RetransmitHandshake).IsValid(),
        "timer delivery did not preserve the captured generation");

    const TimerToken stale_queued = replacement;
    const TimerToken current = coordinator.Arm(TimerHook::RetransmitHandshake, owner);
    WGNX_TEST_REQUIRE(
        context,
        schedule.Arm(current, TimerDeadlineFromJiffies(300)) &&
            !coordinator.IsCurrent(stale_queued, owner) &&
            !schedule.Cancel(stale_queued) &&
            schedule.IsArmed(TimerHook::RetransmitHandshake) &&
            schedule.Cancel(current),
        "timer replacement did not make a queued delivery stale");
    WGNX_TEST_REQUIRE(
        context,
        !schedule.IsArmed(TimerHook::RetransmitHandshake) &&
            !schedule.ArmedToken(TimerHook::RetransmitHandshake).IsValid() &&
            schedule.Deadline(TimerHook::RetransmitHandshake) == TimerDeadline{},
        "timer cancellation retained physical schedule state");

    WGNX_TEST_REQUIRE(
        context,
        !schedule.Arm({}, TimerDeadlineFromJiffies(400)) &&
            !schedule.CaptureExpiration(TimerHook::SendKeepalive),
        "timer schedule accepted invalid or unarmed work");
}

void TestPeerControllerSendPolicy(TestContext &context) {
    using namespace wgnx::wireguard;

    PeerController controller{};
    wg_peer peer{};
    InnerPacketRecord record{.packet_id = 1};
    WGNX_TEST_REQUIRE(
        context,
        peer.staged_outbound_packets.Push(record) == QueuePushResult::Pushed,
        "failed to stage send-policy test packet");
    const auto sent = controller.ApplyStagedSendOutcome(
        peer,
        OutboundSendOutcome::Sent());
    WGNX_TEST_REQUIRE(
        context,
        sent.retired && sent.disposition == QueueDisposition::Sent &&
            sent.action == StagedPacketAction::Continue &&
            peer.staged_outbound_packets.Size() == 0,
        "peer controller did not retire a successfully sent packet");

    record.packet_id = 2;
    static_cast<void>(peer.staged_outbound_packets.Push(record));
    const auto expired = controller.ApplyStagedSendOutcome(
        peer,
        OutboundSendOutcome::BuildFailed(TransportDataError::KeyExpired));
    WGNX_TEST_REQUIRE(
        context,
        !expired.retired && expired.action == StagedPacketAction::InitiateHandshake &&
            peer.staged_outbound_packets.Size() == 1,
        "peer controller did not retain plaintext for a replacement handshake");

    const auto dropped = controller.ApplyStagedSendOutcome(
        peer,
        OutboundSendOutcome::TransportDropped());
    WGNX_TEST_REQUIRE(
        context,
        dropped.retired && dropped.disposition == QueueDisposition::SendFailed &&
            dropped.action == StagedPacketAction::Continue &&
            peer.staged_outbound_packets.Size() == 0,
        "peer controller did not retire a packet lost by the UDP transport");

    record.packet_id = 3;
    static_cast<void>(peer.staged_outbound_packets.Push(record));
    const auto fatal = controller.ApplyStagedSendOutcome(
        peer,
        OutboundSendOutcome::BuildFailed(TransportDataError::AuthenticationFailed));
    WGNX_TEST_REQUIRE(
        context,
        !fatal.retired && fatal.action == StagedPacketAction::StopOnTerminalFailure &&
            peer.staged_outbound_packets.Size() == 1,
        "peer controller conflated terminal construction failure with packet loss");
}

void TestPeerControllerRecoveryWorkflow(TestContext &context) {
    using namespace wgnx::wireguard;

    runtime::Reset(InitialRuntimeState);
    ProtocolPair pair{};
    WGNX_TEST_REQUIRE(context, pair.Initialize(), "protocol pair initialization failed");

    PeerController controller{};
    InnerPacketRecord first{.packet_id = 61};
    WGNX_TEST_REQUIRE(
        context,
        pair.initiator->staged_outbound_packets.Push(first) == QueuePushResult::Pushed &&
            wg_peer_get_outbound_staging_action(*pair.initiator, GetMonotonicTime()) ==
                OutboundStagingAction::InitiateHandshake,
        "initial packet was not staged for the production controller");

    auto transition = controller.StartHandshake(pair.initiator_device, *pair.initiator);
    WGNX_TEST_REQUIRE(
        context,
        transition.action == HandshakeTransitionAction::SendInitiation &&
            pair.initiator->handshake_retry.send_attempts == 1,
        "controller did not begin the initial retry sequence");

    std::uint32_t previous_index = 0;
    std::array<std::uint8_t, NoisePublicKeySize> previous_ephemeral{};
    std::size_t simulated_sends = 0;
    const auto observe_fresh_send = [&]() {
        const auto &initiation = pair.initiator->last_initiation;
        const bool fresh = simulated_sends == 0 ||
                           (initiation.sender_index != previous_index &&
                            initiation.unencrypted_ephemeral != previous_ephemeral);
        previous_index = initiation.sender_index;
        previous_ephemeral = initiation.unencrypted_ephemeral;
        ++simulated_sends;
        return fresh;
    };
    WGNX_TEST_REQUIRE(context, observe_fresh_send(), "initial controller initiation was not fresh");

    constexpr std::uint32_t MaxSendAttempts = MaxTimerHandshakes + 2;
    for (std::uint32_t expected_attempt = 2; expected_attempt <= MaxSendAttempts;
         ++expected_attempt) {
        const TimerOwner owner{
            .peer_index = 0,
            .activation_generation = 1,
            .protocol_sequence = pair.initiator->handshake_retry.sequence_count,
        };
        const TimerToken token = controller.Timers().Arm(
            TimerHook::RetransmitHandshake,
            owner);
        WGNX_TEST_REQUIRE(
            context,
            controller.Timers().IsCurrent(token, owner),
            "controller retry timer was stale before delivery");
        controller.Timers().Cancel(TimerHook::RetransmitHandshake);

        transition = controller.HandleHandshakeRetryTimer(
            pair.initiator_device,
            *pair.initiator);
        WGNX_TEST_REQUIRE(
            context,
            transition.action == HandshakeTransitionAction::SendInitiation &&
                pair.initiator->handshake_retry.send_attempts == expected_attempt &&
                observe_fresh_send(),
            "controller retry did not construct and emit fresh initiation state");
    }

    transition = controller.HandleHandshakeRetryTimer(
        pair.initiator_device,
        *pair.initiator);
    WGNX_TEST_REQUIRE(
        context,
        transition.action == HandshakeTransitionAction::Exhausted &&
            transition.dropped_staged_packets == 1 &&
            simulated_sends == MaxSendAttempts &&
            pair.initiator->staged_outbound_packets.Size() == 0 &&
            pair.initiator->staged_outbound_packets.Statistics().retry_exhausted == 1,
        "controller did not exhaust and account for the unanswered sequence");

    InnerPacketRecord later{.packet_id = 62};
    later.size = 20;
    later.bytes[0] = 0x45;
    later.bytes[2] = 0x00;
    later.bytes[3] = 0x14;
    WGNX_TEST_REQUIRE(
        context,
        pair.initiator->staged_outbound_packets.Push(later) == QueuePushResult::Pushed,
        "failed to stage later traffic after exhaustion");
    transition = controller.StartHandshake(pair.initiator_device, *pair.initiator);
    WGNX_TEST_REQUIRE(
        context,
        transition.action == HandshakeTransitionAction::SendInitiation &&
            pair.initiator->handshake_retry.sequence_count == 2 &&
            pair.initiator->handshake_retry.send_attempts == 1 &&
            observe_fresh_send(),
        "later traffic did not start a fresh controller sequence");

    std::array<std::uint8_t, HandshakeInitiationSize> initiation_packet{};
    WGNX_TEST_REQUIRE(
        context,
        SerializeHandshakeInitiation(initiation_packet, pair.initiator->last_initiation) ==
                ParseError::None &&
            pair.initiator_to_responder.Send(initiation_packet) &&
            pair.ReceiveInitiationAndSendResponse(),
        "controller initiation did not reach the in-memory responder");

    std::span<const std::uint8_t> response_packet{};
    WGNX_TEST_REQUIRE(
        context,
        pair.responder_to_initiator.Receive(response_packet) &&
            noise_handshake_consume_incoming_packet(
                response_packet,
                &pair.initiator_device,
                pair.initiator) == HandshakePacketOutcome::ResponseConsumed,
        "controller recovery response was not authenticated");
    runtime::SetMonotonicTime(SessionBirthTime);
    WGNX_TEST_REQUIRE(
        context,
        controller.CompleteSession(pair.initiator_device, *pair.initiator) &&
            noise_handshake_begin_session(&pair.responder_device, pair.responder) &&
            !pair.initiator->handshake_retry.active &&
            wg_peer_get_outbound_staging_action(*pair.initiator, GetMonotonicTime()) ==
                OutboundStagingAction::Send,
        "controller did not derive the recovered session or release staged traffic");

    const auto *front = pair.initiator->staged_outbound_packets.Front();
    WGNX_TEST_REQUIRE(context, front != nullptr, "recovered packet disappeared before send");
    const TransportResult send = SendTransport(
        &pair.initiator->current_keypair,
        &pair.responder_device,
        pair.responder,
        std::span<const std::uint8_t>(front->bytes.data(), front->size),
        &pair.initiator_to_responder);
    const auto sent = controller.ApplyStagedSendOutcome(
        *pair.initiator,
        send.error == TransportDataError::None
            ? OutboundSendOutcome::Sent()
            : OutboundSendOutcome::BuildFailed(send.error));
    WGNX_TEST_REQUIRE(
        context,
        send.error == TransportDataError::None && sent.retired && sent.remaining == 0 &&
            pair.initiator->staged_outbound_packets.Statistics().sent == 1,
        "recovered staged packet did not pass through the production controller send path");
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
    runtime::SetRealtime({
        .tv_sec = InitialRuntimeState.realtime.tv_sec + 1,
        .tv_nsec = InitialRuntimeState.realtime.tv_nsec,
    });
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
