#include "protocol_tests.hpp"
#include "protocol_test_support.hpp"

namespace wgnx::test {

void TestPacketChannelOwnership(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::wireguard;

    PacketChannel channel{};
    constexpr ProcessId FirstConsumer{100};
    constexpr ProcessId SecondConsumer{200};
    WGNX_TEST_REQUIRE(context, channel.Claim(FirstConsumer) == 0 && channel.IsOwnedBy(FirstConsumer),
                      "packet channel did not establish ownership");

    InnerPacketRecord received{.packet_id = 3};
    WGNX_TEST_REQUIRE(context, channel.PushReceived(received) == QueuePushResult::Pushed && channel.ReceivedSize() == 1,
                      "packet channel did not retain a received packet");
    WGNX_TEST_REQUIRE(context,
                      channel.Claim(SecondConsumer) == 1 && channel.IsOwnedBy(SecondConsumer) && !channel.IsOwnedBy(FirstConsumer) &&
                          channel.ReceivedSize() == 0 && channel.Statistics().cleared == 1,
                      "packet channel ownership transfer retained the previous consumer's packets");
    WGNX_TEST_REQUIRE(context, channel.Release() == 0 && channel.ConsumerId().IsZero(),
                      "packet channel release retained its consumer identity");
}

void TestPacketDataPlane(TestContext& context) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::wireguard;

    runtime::Reset(InitialRuntimeState);
    std::array<wgnx::PeerConfigEntry, 1> configured{};
    FillConfig(&configured[0], "data-plane", "10.66.66.2/32", InitiatorPrivateKey, ResponderPublicKey);
    PeerRegistry registry{};
    RuntimeCoordinator coordinator{registry};
    WGNX_TEST_REQUIRE(context, ConfigureTestPeers(coordinator, configured, 0) && !ActivateTestPeer(coordinator, 0, 90).Empty(),
                      "packet data plane registry initialization failed");

    PacketChannel channel{};
    PacketDataPlane data_plane{coordinator, channel};
    EffectBatch effects{};
    constexpr std::array<std::uint8_t, 20> Ipv4Packet = {
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0xE2, 0x52, 0x0A, 0x42, 0x42, 0x02, 0x0A, 0x42, 0x42, 0x01,
    };
    constexpr std::array<std::uint8_t, 40> Ipv6Packet = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFD, 0x40, 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    const PeerIdentity identity{.peer_index = PeerIndex{0}, .activation_generation = ActivationGeneration{1}};
    constexpr ProcessId FirstConsumer{100};
    constexpr ProcessId OtherConsumer{101};
    constexpr ProcessId SecondConsumer{200};
    const TimerFacts timer_facts{
        .now = TimerDeadlineFromJiffies(500),
    };

    const auto first = data_plane.SubmitIpv4Packet(Ipv4Packet, FirstConsumer, timer_facts, 3'000, effects);
    PeerPacketStateSnapshot peer{};
    static_cast<void>(coordinator.SnapshotPacketState(peer));
    WGNX_TEST_REQUIRE(context,
                      first.status == PacketSubmissionStatus::Queued && first.packet_id == PacketId{1} && first.peer == identity &&
                          first.ownership_transferred && channel.IsOwnedBy(FirstConsumer) && peer.staged_packet_count == 1,
                      "packet data plane did not claim and route the first IPv4 packet");

    const auto ipv4_only = data_plane.SubmitIpv4Packet(Ipv6Packet, FirstConsumer, timer_facts, 3'100, effects);
    const auto generic = data_plane.SubmitIpPacket(Ipv6Packet, FirstConsumer, timer_facts, 3'200, effects);
    static_cast<void>(coordinator.SnapshotPacketState(peer));
    WGNX_TEST_REQUIRE(
        context,
        ipv4_only.status == PacketSubmissionStatus::MalformedPacket && ipv4_only.validation == InnerIpv4ValidationError::InvalidVersion &&
            generic.status == PacketSubmissionStatus::Queued && generic.packet_id == PacketId{2} && peer.staged_packet_count == 2,
        "packet data plane did not preserve IPv4 IPC policy over the generic IP boundary");

    const auto unsupported = data_plane.DeliverDecryptedPacket(identity, Ipv6Packet);
    const auto delivered = data_plane.DeliverDecryptedPacket(identity, Ipv4Packet);
    std::array<std::uint8_t, MaxInnerIpPacketSize> output{};
    const auto denied = data_plane.ReceivePacket(output, OtherConsumer);
    const auto too_small = data_plane.ReceivePacket(std::span<std::uint8_t>(output).first(Ipv4Packet.size() - 1), FirstConsumer);
    const auto received = data_plane.ReceivePacket(output, FirstConsumer);
    WGNX_TEST_REQUIRE(context,
                      unsupported.status == PacketDeliveryStatus::UnsupportedPacket && unsupported.version == InnerIpVersion::Ipv6 &&
                          delivered.status == PacketDeliveryStatus::Queued && delivered.packet_id == PacketId{3} &&
                          denied.status == PacketReceiveStatus::AccessDenied &&
                          too_small.status == PacketReceiveStatus::OutputBufferTooSmall &&
                          received.status == PacketReceiveStatus::Success && received.packet_id == delivered.packet_id &&
                          std::equal(Ipv4Packet.begin(), Ipv4Packet.end(), output.begin()),
                      "packet data plane delivery lost adapter capability, PID ownership, capacity, or bytes");

    for (std::size_t index = 0; index < PacketChannel::ReceiveCapacity; ++index) {
        WGNX_TEST_REQUIRE(context, data_plane.DeliverDecryptedPacket(identity, Ipv4Packet).status == PacketDeliveryStatus::Queued,
                          "packet data plane receive queue filled before its declared capacity");
    }
    const auto overflow = data_plane.DeliverDecryptedPacket(identity, Ipv4Packet);
    WGNX_TEST_REQUIRE(context,
                      overflow.status == PacketDeliveryStatus::QueueFull && overflow.queue_depth == PacketChannel::ReceiveCapacity &&
                          channel.Statistics().rejected_full == 1,
                      "packet data plane did not retain reject-new receive overflow behavior");

    const auto transfer = data_plane.SubmitIpPacket(Ipv6Packet, SecondConsumer, timer_facts, 4'000, effects);
    WGNX_TEST_REQUIRE(context,
                      transfer.status == PacketSubmissionStatus::Queued && transfer.ownership_transferred &&
                          transfer.discarded_outbound == 2 && transfer.discarded_inbound == PacketChannel::ReceiveCapacity &&
                          channel.IsOwnedBy(SecondConsumer) && channel.ReceivedSize() == 0,
                      "packet data plane ownership transfer did not clear both traffic directions");

    const auto stale_packet = data_plane.DeliverDecryptedPacket(identity, Ipv4Packet);
    WGNX_TEST_REQUIRE(context, stale_packet.status == PacketDeliveryStatus::Queued && coordinator.SetActivePeerIndex(-1),
                      "packet data plane stale-delivery setup failed");
    const auto stale = data_plane.ReceivePacket(output, SecondConsumer);
    WGNX_TEST_REQUIRE(
        context, stale.status == PacketReceiveStatus::StaleActivation && channel.Statistics().stale == 1 && channel.ReceivedSize() == 0,
        "packet data plane did not reject a queued packet from a stale activation");
}

} // namespace wgnx::test
