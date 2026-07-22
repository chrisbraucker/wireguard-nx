#pragma once

#include "wireguard/constants.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>

namespace wgnx::wireguard {

using MonotonicDuration = std::chrono::nanoseconds;

struct ProtocolMonotonicClock {
    using rep = MonotonicDuration::rep;
    using period = MonotonicDuration::period;
    using duration = MonotonicDuration;
    using time_point = std::chrono::time_point<ProtocolMonotonicClock, duration>;
    static constexpr bool is_steady = true;
};

using MonotonicTimePoint = ProtocolMonotonicClock::time_point;

MonotonicTimePoint GetMonotonicTime();

struct noise_public_key {
    std::array<std::uint8_t, NoisePublicKeySize> bytes{};
    bool valid{false};
};

struct noise_private_key {
    std::array<std::uint8_t, NoisePublicKeySize> bytes{};
    bool valid{false};

    noise_private_key() = default;
    ~noise_private_key();
    noise_private_key(const noise_private_key &) = delete;
    noise_private_key &operator=(const noise_private_key &) = delete;
    noise_private_key(noise_private_key &&other) noexcept;
    noise_private_key &operator=(noise_private_key &&other) noexcept;
    void Clear();
};

struct noise_symmetric_key {
    std::array<std::uint8_t, 32> bytes{};
    bool valid{false};

    noise_symmetric_key() = default;
    ~noise_symmetric_key();
    noise_symmetric_key(const noise_symmetric_key &) = delete;
    noise_symmetric_key &operator=(const noise_symmetric_key &) = delete;
    noise_symmetric_key(noise_symmetric_key &&other) noexcept;
    noise_symmetric_key &operator=(noise_symmetric_key &&other) noexcept;
    void Clear();
};

struct noise_secret32 {
    std::array<std::uint8_t, 32> bytes{};
    bool valid{false};

    noise_secret32() = default;
    ~noise_secret32();
    noise_secret32(const noise_secret32 &) = delete;
    noise_secret32 &operator=(const noise_secret32 &) = delete;
    noise_secret32(noise_secret32 &&other) noexcept;
    noise_secret32 &operator=(noise_secret32 &&other) noexcept;
    void Clear();
};

struct noise_cookie {
    std::array<std::uint8_t, CookieValueSize> value{};
    std::array<std::uint8_t, NoiseMacSize> last_mac1{};
    MonotonicTimePoint birth_time{};
    bool valid{false};
    bool has_last_mac1{false};

    noise_cookie() = default;
    ~noise_cookie();
    noise_cookie(const noise_cookie &) = delete;
    noise_cookie &operator=(const noise_cookie &) = delete;
    noise_cookie(noise_cookie &&other) noexcept;
    noise_cookie &operator=(noise_cookie &&other) noexcept;
    void Clear();
};

struct noise_static_identity {
    noise_private_key static_private{};
    noise_public_key static_public{};
    noise_public_key remote_static{};
    noise_symmetric_key preshared_key{};
};

struct noise_handshake_material {
    noise_private_key ephemeral_private{};
    noise_public_key ephemeral_public{};
    noise_public_key remote_ephemeral{};
    noise_secret32 precomputed_static_static{};
    noise_symmetric_key chaining_key{};
    noise_symmetric_key hash{};
};

class ReplayWindow {
public:
    static constexpr std::size_t BlockBitLog = 6;
    static constexpr std::size_t BlockBits = std::size_t{1} << BlockBitLog;
    static constexpr std::size_t RingBlocks = std::size_t{1} << 7;
    static constexpr std::uint64_t WindowSize = (RingBlocks - 1) * BlockBits;

    bool TryAdvance(std::uint64_t counter);
    void Reset();

    bool HasReceivedPacket() const { return m_initialized; }
    std::uint64_t HighestCounter() const { return m_highest_counter; }

private:
    static constexpr std::size_t BlockMask = RingBlocks - 1;
    static constexpr std::size_t BitMask = BlockBits - 1;

    std::uint64_t m_highest_counter{0};
    std::array<std::uint64_t, RingBlocks> m_ring{};
    bool m_initialized{false};
};

enum class KeypairState : std::uint8_t {
    Empty = 0,
    Established,
};

enum class KeypairSendState : std::uint8_t {
    Ready = 0,
    Invalid,
    Expired,
    CounterExhausted,
};

const char *GetKeypairSendStateName(KeypairSendState state);

struct KeypairAgeResult {
    bool valid{false};
    MonotonicDuration age{};
};

class noise_keypair {
public:
    noise_keypair() = default;
    ~noise_keypair();
    noise_keypair(const noise_keypair &) = delete;
    noise_keypair &operator=(const noise_keypair &) = delete;
    noise_keypair(noise_keypair &&other) noexcept;
    noise_keypair &operator=(noise_keypair &&other) noexcept;

    void Establish(
        std::uint32_t local_index,
        std::uint32_t remote_index,
        MonotonicTimePoint birth_time,
        const noise_symmetric_key &sending_key,
        const noise_symmetric_key &receiving_key,
        std::uint64_t send_counter = 0,
        bool is_initiator = true);
    void Reset();

    bool IsValid() const;
    bool CanSendAt(MonotonicTimePoint now) const;
    bool CanReceiveAt(MonotonicTimePoint now) const;
    KeypairSendState SendStateAt(MonotonicTimePoint now) const;
    KeypairState State() const { return m_state; }
    std::uint32_t LocalIndex() const { return m_local_index; }
    std::uint32_t RemoteIndex() const { return m_remote_index; }
    std::uint64_t SendCounter() const { return m_send_counter; }
    bool IsInitiator() const { return m_is_initiator; }
    bool NeedsRekeyAt(MonotonicTimePoint now) const;
    KeypairSendState ReserveSendCounterAt(MonotonicTimePoint now, std::uint64_t &out_counter);
    MonotonicTimePoint BirthTime() const { return m_birth_time; }
    KeypairAgeResult AgeAt(MonotonicTimePoint now) const;
    const noise_symmetric_key &SendingKey() const { return m_sending_key; }
    const noise_symmetric_key &ReceivingKey() const { return m_receiving_key; }
    const ReplayWindow &ReceiveReplayWindow() const { return m_receive_replay_window; }
    ReplayWindow &ReceiveReplayWindow() { return m_receive_replay_window; }

private:
    KeypairState m_state{KeypairState::Empty};
    std::uint32_t m_local_index{0};
    std::uint32_t m_remote_index{0};
    std::uint64_t m_send_counter{0};
    bool m_is_initiator{false};
    MonotonicTimePoint m_birth_time{};
    noise_symmetric_key m_sending_key{};
    noise_symmetric_key m_receiving_key{};
    ReplayWindow m_receive_replay_window{};
};

static_assert(!std::is_copy_constructible_v<noise_keypair>);
static_assert(std::is_nothrow_move_constructible_v<noise_keypair>);

void noise_cookie_reset(noise_cookie *cookie);
void noise_cookie_record_last_mac1(noise_cookie *cookie, const std::uint8_t mac1[NoiseMacSize]);
bool noise_cookie_is_valid(const noise_cookie *cookie);
void noise_static_identity_reset(noise_static_identity *identity);
void noise_handshake_material_reset(noise_handshake_material *material);

bool noise_is_valid_encoded_key(std::string_view text, bool allow_empty = false);
bool noise_parse_private_key(noise_private_key *out_key, std::string_view text);
bool noise_parse_public_key(noise_public_key *out_key, std::string_view text);
bool noise_parse_preshared_key(noise_symmetric_key *out_key, std::string_view text);
bool noise_public_key_to_text(std::span<char> out_text, const noise_public_key *key);
bool noise_derive_public_key(noise_public_key *out_key, const noise_private_key *private_key);
bool noise_derive_public_key_text(std::span<char> out_text, const noise_private_key *private_key);
bool noise_derive_public_key_text(std::span<char> out_text, std::string_view private_key_text);
bool noise_static_identity_init(
    noise_static_identity *identity,
    std::string_view private_key_text,
    std::string_view peer_public_key_text,
    std::string_view preshared_key_text);
bool noise_static_identity_init_from_keys(
    noise_static_identity *identity,
    const noise_private_key *private_key,
    std::string_view peer_public_key_text,
    const noise_symmetric_key *preshared_key);
bool noise_precompute_static_static(
    noise_handshake_material *material,
    const noise_static_identity *identity);

} // namespace wgnx::wireguard
