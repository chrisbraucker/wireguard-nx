#include "protocol_tests.hpp"
#include "protocol_test_support.hpp"

#include "config_text_validation.hpp"
#include "platform/endpoint_parser.hpp"

#include <cstring>

namespace wgnx::test {

void TestFuzzedParsingBoundaries(TestContext &context) {
    const auto valid_config = wgnx::sysmodule::ValidateConnectionConfigLayout(
        "[Interface]\nAddress = 10.13.13.8/24\n[Peer]\nEndpoint = 10.13.13.1:51820\n");
    WGNX_TEST_REQUIRE(context, valid_config.IsValid(), "valid config layout rejected");

    const auto duplicate_interface = wgnx::sysmodule::ValidateConnectionConfigLayout(
        "[Interface]\n[Interface]\n[Peer]\n");
    WGNX_TEST_REQUIRE(
        context,
        duplicate_interface.error == wgnx::sysmodule::ConfigLayoutError::MultipleInterfaceSections &&
            duplicate_interface.line == 2,
        "duplicate Interface section did not retain its diagnostic location");

    wgnx::platform::EndpointTextParts endpoint{};
    WGNX_TEST_REQUIRE(
        context,
        wgnx::platform::ParseEndpointText(" [2001:db8::1]:51820 ", &endpoint) &&
            std::strcmp(endpoint.host.data(), "2001:db8::1") == 0 &&
            std::strcmp(endpoint.service.data(), "51820") == 0 &&
            wgnx::platform::ParseEndpointPort(endpoint.service.data()),
        "bracketed IPv6 endpoint was not parsed");
    WGNX_TEST_REQUIRE(
        context,
        !wgnx::platform::ParseEndpointText("2001:db8::1:51820", &endpoint) &&
            !wgnx::platform::ParseEndpointPort("0") &&
            !wgnx::platform::ParseEndpointPort("65536"),
        "endpoint parser accepted malformed endpoint or port");
}

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
            full_statistics.Dropped() == 1 &&
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
