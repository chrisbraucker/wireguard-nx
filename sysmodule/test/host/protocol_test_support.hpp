#pragma once

#include "test_framework.hpp"
#include "test_runtime.hpp"

#include "runtime/autostart_persistence.hpp"
#include "runtime/packet_channel.hpp"
#include "runtime/packet_data_plane.hpp"
#include "runtime/endpoint_resolver.hpp"
#include "runtime/debug_probe_runner.hpp"
#include "runtime/effect_drain.hpp"
#include "runtime/peer/peer_runtime.hpp"
#include "runtime/runtime_coordinator.hpp"
#include "runtime/runtime_contracts.hpp"
#include "runtime/timer_schedule.hpp"
#include "runtime/udp_binding.hpp"
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

template <typename Binding>
concept HasLegacyUdpPlatformIo = requires(Binding& binding, wgnx::sysmodule::runtime::SocketGeneration generation,
                                          std::span<const std::uint8_t> packet, std::size_t* sent) {
    binding.Open(generation);
    binding.Close();
    binding.Send(packet, sent);
    binding.Suspend();
};

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
    .realtime =
        {
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

        Datagram& datagram = m_datagrams[(m_head + m_count) % Capacity];
        std::ranges::copy(packet, datagram.bytes.begin());
        datagram.size = packet.size();
        ++m_count;
        ++m_total_sent;
        return true;
    }

    bool Receive(std::span<const std::uint8_t>& out_packet) {
        if (m_count == 0) {
            return false;
        }

        Datagram& datagram = m_datagrams[m_head];
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

inline void FillConfig(wgnx::PeerConfigEntry* config, const char* name, const char* address, const char* private_key,
                       const char* remote_public_key) {
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

inline wgnx::sysmodule::runtime::PeerConfigDerivedInfo DeriveTestSecrets(const wgnx::PeerConfigEntry& config) {
    wgnx::sysmodule::runtime::PeerConfigDerivedInfo derived{};
    const bool private_key_valid =
        wgnx::wireguard::noise_parse_private_key(std::addressof(derived.local_private_key), config.private_key.data());
    const bool preshared_key_valid =
        config.preshared_key[0] == '\0' ||
        wgnx::wireguard::noise_parse_preshared_key(std::addressof(derived.preshared_key), config.preshared_key.data());
    derived.has_preshared_key = config.preshared_key[0] != '\0' && preshared_key_valid;
    derived.secrets_valid = private_key_valid && preshared_key_valid;
    return derived;
}

template <std::size_t Size>
bool ConfigureTestPeers(wgnx::sysmodule::runtime::RuntimeCoordinator& coordinator,
                        const std::array<wgnx::PeerConfigEntry, Size>& configured, std::int32_t active_peer_index = -1,
                        std::int32_t auto_start_peer_index = -1, wgnx::platform::ktime_t now = 0) {
    std::array<wgnx::sysmodule::runtime::PeerConfigDerivedInfo, Size> derived{};
    for (std::size_t index = 0; index < Size; ++index) {
        derived[index] = DeriveTestSecrets(configured[index]);
    }
    return coordinator.Configure(configured, derived, auto_start_peer_index, now) && coordinator.SetActivePeerIndex(active_peer_index);
}

inline wgnx::sysmodule::runtime::EffectBatch CompleteTestPeerActivation(wgnx::sysmodule::runtime::RuntimeCoordinator& coordinator,
                                                                        const wgnx::sysmodule::runtime::ResolveEndpointEffect& resolve,
                                                                        wgnx::platform::socket_handle socket, wgnx::platform::ktime_t now) {
    using namespace wgnx::sysmodule::runtime;
    using namespace wgnx::wireguard;
    wgnx::platform::endpoint_resolution_result resolved{
        .success = true,
        .resolved =
            {
                .family = wgnx::platform::address_family::inet,
                .port = 51820,
                .address = {192, 0, 2, 1},
            },
    };
    std::snprintf(resolved.text.data(), resolved.text.size(), "192.0.2.1:51820");
    const auto resolution = coordinator.Dispatch(EndpointResolvedEvent{
        .peer = resolve.peer,
        .path_generation = resolve.path_generation,
        .result = resolved,
        .occurred_at = now + 1,
    });
    const auto* open = resolution.Size() == 1 ? std::get_if<OpenUdpBindEffect>(resolution.begin()) : nullptr;
    if (open == nullptr) {
        return {};
    }
    return coordinator.Dispatch(UdpBindOpenedEvent{
        .peer = open->peer,
        .path_generation = open->path_generation,
        .endpoint = open->endpoint,
        .endpoint_text = open->endpoint_text,
        .socket = socket,
        .error = wgnx::platform::socket_error::none,
        .socket_generation = open->socket_generation,
        .purpose = open->purpose,
        .timer_facts =
            {
                .now = TimerDeadlineFromJiffies(500),
            },
        .occurred_at = now + 2,
    });
}

inline wgnx::sysmodule::runtime::EffectBatch AllowTestLocalPath(wgnx::sysmodule::runtime::RuntimeCoordinator& coordinator,
                                                                const wgnx::sysmodule::runtime::StartNetworkPathRequestEffect& start,
                                                                wgnx::platform::ktime_t now) {
    using namespace wgnx::sysmodule::runtime;
    return coordinator.Dispatch(NetworkPathAvailabilityChangedEvent{
        .peer = start.peer,
        .path_generation = start.path_generation,
        .observation =
            {
                .availability = wgnx::platform::network_path_availability::available,
                .raw_state = wgnx::platform::network_path_raw_state::available,
                .request_generation = start.path_generation.Value(),
            },
        .occurred_at = now,
    });
}

inline wgnx::sysmodule::runtime::EffectBatch ActivateTestPeer(wgnx::sysmodule::runtime::RuntimeCoordinator& coordinator,
                                                              std::uint32_t peer_index, wgnx::platform::socket_handle socket,
                                                              wgnx::platform::ktime_t now = 1'000) {
    using namespace wgnx::sysmodule::runtime;

    const auto activation = coordinator.Dispatch(ActivationRequestedEvent{
        .peer_index = PeerIndex{peer_index},
        .occurred_at = now,
    });
    const auto* start = activation.Size() == 1 ? std::get_if<StartNetworkPathRequestEffect>(activation.begin()) : nullptr;
    const auto path_effects = start != nullptr ? AllowTestLocalPath(coordinator, *start, now + 1) : EffectBatch{};
    const auto* resolve = path_effects.Size() == 1 ? std::get_if<ResolveEndpointEffect>(path_effects.begin()) : nullptr;
    return resolve != nullptr ? CompleteTestPeerActivation(coordinator, *resolve, socket, now + 2) : EffectBatch{};
}

inline bool CheckHandshakeState(TestContext& context, const wgnx::wireguard::wg_peer& peer, wgnx::wireguard::HandshakeState expected_state,
                                std::uint32_t expected_transitions, const char* phase) {
    if (peer.handshake.state == expected_state && peer.handshake.transition_count == expected_transitions) {
        return true;
    }

    char detail[256]{};
    std::snprintf(detail, sizeof(detail), "peer=%s phase=%s state=%s expected=%s transitions=%u expected_transitions=%u", peer.name, phase,
                  wgnx::wireguard::GetHandshakeStateName(peer.handshake.state), wgnx::wireguard::GetHandshakeStateName(expected_state),
                  peer.handshake.transition_count, expected_transitions);
    context.Fail("handshake state", __FILE__, __LINE__, detail);
    return false;
}

struct ProtocolPair {
    wgnx::PeerConfigEntry initiator_config{};
    wgnx::PeerConfigEntry responder_config{};
    wgnx::wireguard::wg_device initiator_device{};
    wgnx::wireguard::wg_device responder_device{};
    wgnx::wireguard::wg_peer* initiator{nullptr};
    wgnx::wireguard::wg_peer* responder{nullptr};
    InMemoryDatagramLink initiator_to_responder{};
    InMemoryDatagramLink responder_to_initiator{};

    bool Initialize() {
        FillConfig(&initiator_config, "initiator", "10.66.66.2/32", InitiatorPrivateKey, ResponderPublicKey);
        FillConfig(&responder_config, "responder", "10.66.66.1/32", ResponderPrivateKey, InitiatorPublicKey);

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

    bool CreateAndSendInitiation(std::array<std::uint8_t, wgnx::wireguard::HandshakeInitiationSize>* out_bytes = nullptr) {
        wgnx::wireguard::message_handshake_initiation initiation{};
        const bool created = initiator->handshake.local_index == 0
                                 ? wgnx::wireguard::wg_device_create_handshake_initiation(&initiator_device, &initiation)
                                 : wgnx::wireguard::noise_handshake_create_initiation(&initiation, initiator);
        if (!created) {
            return false;
        }

        std::array<std::uint8_t, wgnx::wireguard::HandshakeInitiationSize> packet{};
        if (wgnx::wireguard::SerializeHandshakeInitiation(packet, initiation) != wgnx::wireguard::ParseError::None) {
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
            const std::uint32_t local_index = wgnx::wireguard::wg_device_allocate_index(&responder_device);
            wgnx::wireguard::noise_handshake_set_local_index(&responder->handshake, local_index);
            wgnx::wireguard::wg_device_register_handshake_index(&responder_device, local_index);
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
        if (wgnx::wireguard::SerializeHandshakeResponse(packet, response) != wgnx::wireguard::ParseError::None) {
            return false;
        }
        return responder_to_initiator.Send(packet);
    }

    bool ReceiveResponseAndDeriveSession() {
        std::span<const std::uint8_t> incoming{};
        if (!responder_to_initiator.Receive(incoming)) {
            return false;
        }
        if (wgnx::wireguard::noise_handshake_consume_incoming_packet(incoming, &initiator_device, initiator) !=
            wgnx::wireguard::HandshakePacketOutcome::ResponseConsumed) {
            return false;
        }

        runtime::SetMonotonicTime(SessionBirthTime);
        return wgnx::wireguard::noise_handshake_begin_session(&initiator_device, initiator) &&
               wgnx::wireguard::noise_handshake_begin_session(&responder_device, responder);
    }
};

inline bool CheckSessionKeys(TestContext& context, const ProtocolPair& pair) {
    const auto& initiator_keypair = pair.initiator->current_keypair;
    const auto& responder_keypair =
        pair.responder->current_keypair.IsValid() ? pair.responder->current_keypair : pair.responder->next_keypair;
    if (!initiator_keypair.IsValid()) {
        context.Fail("initiator_keypair.valid", __FILE__, __LINE__, "initiator current keypair is invalid");
        return false;
    }
    if (!responder_keypair.IsValid()) {
        context.Fail("responder_keypair.valid", __FILE__, __LINE__, "responder current keypair is invalid");
        return false;
    }
    const wgnx::wireguard::MonotonicTimePoint expected_birth{wgnx::wireguard::MonotonicDuration{SessionBirthTime}};
    if (initiator_keypair.BirthTime() != expected_birth || responder_keypair.BirthTime() != expected_birth) {
        context.Fail("keypair birth time", __FILE__, __LINE__, "controlled monotonic time was not used");
        return false;
    }
    if (std::memcmp(initiator_keypair.SendingKey().bytes.data(), responder_keypair.ReceivingKey().bytes.data(),
                    initiator_keypair.SendingKey().bytes.size()) != 0) {
        context.Fail("session keys", __FILE__, __LINE__, "initiator sending key does not match responder receiving key");
        return false;
    }
    if (std::memcmp(responder_keypair.SendingKey().bytes.data(), initiator_keypair.ReceivingKey().bytes.data(),
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

inline TransportResult SendTransport(wgnx::wireguard::noise_keypair* sender, wgnx::wireguard::wg_device* receiver_device,
                                     wgnx::wireguard::wg_peer* receiver, std::span<const std::uint8_t> payload,
                                     InMemoryDatagramLink* link) {
    TransportResult result{};
    std::array<std::uint8_t, 2048> outgoing{};
    const auto create_result = wgnx::wireguard::noise_create_transport_data_packet(outgoing, *sender, payload);
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
    result.error = wgnx::wireguard::noise_consume_incoming_transport_data_packet(incoming, *receiver_device, *receiver, result.plaintext,
                                                                                 incoming_result);
    result.decrypt = incoming_result.decrypt;
    return result;
}

inline bool BuildDeterministicInitiation(std::array<std::uint8_t, wgnx::wireguard::HandshakeInitiationSize>* out,
                                         wgnx::wireguard::HandshakeState* out_state, std::uint32_t* out_transition_count,
                                         wgnx::wireguard::MonotonicTimePoint* out_transition_time) {
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

} // namespace wgnx::test
