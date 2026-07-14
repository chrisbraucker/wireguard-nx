#include "protocol_tests.hpp"

#include "test_framework.hpp"
#include "test_runtime.hpp"

#include "wireguard/data.hpp"
#include "wireguard/device.hpp"
#include "wireguard/handshake.hpp"
#include "wireguard/messages.hpp"
#include "wireguard/timers.hpp"

#include <array>
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

    bool Send(const wgnx::platform::packet_buffer &packet) {
        if (m_count == Capacity || packet.data == nullptr || packet.len > MaximumPacketSize) {
            return false;
        }

        Datagram &datagram = m_datagrams[(m_head + m_count) % Capacity];
        std::memcpy(datagram.bytes.data(), packet.data, packet.len);
        datagram.size = packet.len;
        ++m_count;
        ++m_total_sent;
        return true;
    }

    bool Receive(wgnx::platform::packet_buffer *out_packet) {
        if (out_packet == nullptr || m_count == 0) {
            return false;
        }

        Datagram &datagram = m_datagrams[m_head];
        wgnx::platform::packet_init(out_packet, datagram.bytes.data(), datagram.bytes.size());
        out_packet->len = datagram.size;
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
        if (!wgnx::wireguard::noise_handshake_create_initiation(&initiation, initiator)) {
            return false;
        }

        wgnx::platform::static_packet_buffer<wgnx::wireguard::HandshakeInitiationSize> packet{};
        if (wgnx::wireguard::SerializeHandshakeInitiation(&packet.packet, initiation) !=
            wgnx::wireguard::ParseError::None) {
            return false;
        }
        if (out_bytes != nullptr) {
            std::memcpy(out_bytes->data(), packet.packet.data, packet.packet.len);
        }
        return initiator_to_responder.Send(packet.packet);
    }

    bool ReceiveInitiationAndSendResponse() {
        wgnx::platform::packet_buffer incoming{};
        if (!initiator_to_responder.Receive(&incoming)) {
            return false;
        }

        wgnx::wireguard::message_handshake_initiation initiation{};
        if (!wgnx::wireguard::ParseHandshakeInitiation(&incoming, &initiation).success ||
            !wgnx::wireguard::noise_handshake_consume_initiation(&initiation, responder)) {
            return false;
        }

        wgnx::wireguard::message_handshake_response response{};
        if (!wgnx::wireguard::noise_handshake_create_response(&response, responder)) {
            return false;
        }

        wgnx::platform::static_packet_buffer<wgnx::wireguard::HandshakeResponseSize> packet{};
        if (wgnx::wireguard::SerializeHandshakeResponse(&packet.packet, response) !=
            wgnx::wireguard::ParseError::None) {
            return false;
        }
        return responder_to_initiator.Send(packet.packet);
    }

    bool ReceiveResponseAndDeriveSession() {
        wgnx::platform::packet_buffer incoming{};
        if (!responder_to_initiator.Receive(&incoming)) {
            return false;
        }
        if (wgnx::wireguard::noise_handshake_consume_incoming_packet(
                &incoming,
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
    const auto &responder_keypair = pair.responder->current_keypair;
    if (!initiator_keypair.valid) {
        context.Fail("initiator_keypair.valid", __FILE__, __LINE__, "initiator current keypair is invalid");
        return false;
    }
    if (!responder_keypair.valid) {
        context.Fail("responder_keypair.valid", __FILE__, __LINE__, "responder current keypair is invalid");
        return false;
    }
    if (initiator_keypair.birthdate_ns != SessionBirthTime ||
        responder_keypair.birthdate_ns != SessionBirthTime) {
        context.Fail("keypair birth time", __FILE__, __LINE__, "controlled monotonic time was not used");
        return false;
    }
    if (std::memcmp(
            initiator_keypair.sending_key.bytes,
            responder_keypair.receiving_key.bytes,
            sizeof(initiator_keypair.sending_key.bytes)) != 0) {
        context.Fail("session keys", __FILE__, __LINE__, "initiator sending key does not match responder receiving key");
        return false;
    }
    if (std::memcmp(
            responder_keypair.sending_key.bytes,
            initiator_keypair.receiving_key.bytes,
            sizeof(responder_keypair.sending_key.bytes)) != 0) {
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
    wgnx::wireguard::noise_keypair *receiver,
    std::span<const std::uint8_t> payload,
    InMemoryDatagramLink *link) {
    TransportResult result{};
    wgnx::platform::static_packet_buffer<2048> outgoing{};
    result.error = wgnx::wireguard::noise_create_transport_data_packet(
        &outgoing.packet,
        *sender,
        payload);
    if (result.error != wgnx::wireguard::TransportDataError::None) {
        return result;
    }
    if (!link->Send(outgoing.packet)) {
        result.error = wgnx::wireguard::TransportDataError::InvalidPacket;
        return result;
    }

    ++sender->send_counter;
    std::memcpy(result.wire_packet.data(), outgoing.packet.data, outgoing.packet.len);
    result.wire_packet_size = outgoing.packet.len;

    wgnx::platform::packet_buffer incoming{};
    if (!link->Receive(&incoming)) {
        result.error = wgnx::wireguard::TransportDataError::InvalidPacket;
        return result;
    }
    result.error = wgnx::wireguard::noise_consume_transport_data_packet(
        &incoming,
        receiver,
        result.plaintext,
        &result.decrypt);
    return result;
}

bool BuildDeterministicInitiation(
    std::array<std::uint8_t, wgnx::wireguard::HandshakeInitiationSize> *out,
    wgnx::wireguard::HandshakeState *out_state,
    std::uint32_t *out_transition_count,
    wgnx::platform::ktime_t *out_transition_time) {
    runtime::Reset(InitialRuntimeState);
    ProtocolPair pair{};
    if (!pair.Initialize() || !pair.CreateAndSendInitiation(out)) {
        return false;
    }

    *out_state = pair.initiator->handshake.state;
    *out_transition_count = pair.initiator->handshake.transition_count;
    *out_transition_time = pair.initiator->handshake.last_transition_ns;
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
    wgnx::platform::ktime_t first_transition_time = 0;
    wgnx::platform::ktime_t second_transition_time = 0;

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
        first_transition_time == InitialMonotonicTime &&
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
        &pair.responder->current_keypair,
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
        &pair.initiator->current_keypair,
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
        &pair.responder->current_keypair,
        InitiatorPayload,
        &pair.initiator_to_responder);
    WGNX_TEST_REQUIRE(
        context,
        second.error == wgnx::wireguard::TransportDataError::None &&
            second.decrypt.header.counter == 1,
        "second initiator packet did not advance the send counter");

    wgnx::platform::packet_buffer replay{};
    wgnx::platform::packet_init(&replay, const_cast<std::uint8_t *>(second.wire_packet.data()), second.wire_packet_size);
    replay.len = second.wire_packet_size;
    std::array<std::uint8_t, 256> replay_plaintext{};
    const auto replay_error = wgnx::wireguard::noise_consume_transport_data_packet(
        &replay,
        &pair.responder->current_keypair,
        replay_plaintext,
        nullptr);
    WGNX_TEST_REQUIRE(
        context,
        replay_error == wgnx::wireguard::TransportDataError::ReplayRejected,
        wgnx::wireguard::GetTransportDataErrorName(replay_error));
    WGNX_TEST_REQUIRE(
        context,
        pair.initiator->current_keypair.send_counter == 2 &&
            pair.responder->current_keypair.send_counter == 1 &&
            pair.initiator->current_keypair.receive_counter == 0 &&
            pair.responder->current_keypair.receive_counter == 1,
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
        5'000,
        pair.initiator->name);
    wgnx::wireguard::wg_timers_schedule(
        &timers,
        wgnx::wireguard::TimerHook::Rekey,
        120'000,
        pair.initiator->name);
    WGNX_TEST_REQUIRE(
        context,
        timers.retransmit_handshake.pending &&
            timers.retransmit_handshake.expires == 5'000 &&
            timers.rekey.pending &&
            timers.rekey.expires == 120'000,
        "timer schedule state or deadline diverged");

    wgnx::wireguard::wg_timers_schedule(
        &timers,
        wgnx::wireguard::TimerHook::RetransmitHandshake,
        7'500,
        pair.initiator->name);
    WGNX_TEST_REQUIRE(
        context,
        timers.retransmit_handshake.pending && timers.retransmit_handshake.expires == 7'500,
        "rescheduling did not replace the timer deadline");

    wgnx::wireguard::wg_timers_cancel(
        &timers,
        wgnx::wireguard::TimerHook::RetransmitHandshake,
        pair.initiator->name);
    WGNX_TEST_REQUIRE(
        context,
        !timers.retransmit_handshake.pending &&
            timers.retransmit_handshake.expires == 0 &&
            timers.rekey.pending,
        "single timer cancellation changed the wrong timer state");
    wgnx::wireguard::wg_timers_cancel_all(&timers, pair.initiator->name);
    WGNX_TEST_REQUIRE(context, !wgnx::wireguard::wg_timers_any_pending(timers), "cancel-all left timer intent pending");
}

} // namespace wgnx::test
