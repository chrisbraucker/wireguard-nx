#pragma once

#include "wgnx/platform/clock.hpp"

#include "wireguard/constants.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>

namespace wgnx::wireguard {

using MonotonicTime = std::chrono::nanoseconds;

MonotonicTime GetMonotonicTime();

struct noise_public_key {
    std::array<std::uint8_t, NoisePublicKeySize> bytes{};
    bool valid{false};
};

struct noise_private_key {
    std::array<std::uint8_t, NoisePublicKeySize> bytes{};
    bool valid{false};
};

struct noise_symmetric_key {
    std::array<std::uint8_t, 32> bytes{};
    bool valid{false};
};

struct noise_secret32 {
    std::array<std::uint8_t, 32> bytes{};
    bool valid{false};
};

struct noise_cookie {
    std::array<std::uint8_t, CookieValueSize> value{};
    std::array<std::uint8_t, NoiseMacSize> last_mac1{};
    MonotonicTime birth_time{};
    bool valid{false};
    bool has_last_mac1{false};
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
    bool TryAdvance(std::uint64_t counter);
    void Reset();

    bool HasReceivedPacket() const { return m_initialized; }
    std::uint64_t HighestCounter() const { return m_highest_counter; }
    std::uint64_t Bitmap() const { return m_bitmap; }

private:
    /*
     * Deviation from Linux:
     * Replay tracking is currently compressed to a 64-packet window instead of
     * the larger upstream bitmap. The current sysmodule shape is single-active-
     * peer and memory-sensitive, so this keeps per-keypair state compact while
     * still making duplicate and stale transport-data packets fail
     * deterministically. The implication is that packets arriving more than 63
     * counters behind the highest accepted value are rejected earlier than they
     * would be upstream.
     */
    std::uint64_t m_highest_counter{0};
    std::uint64_t m_bitmap{0};
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
    MonotonicTime age{};
};

class noise_keypair {
public:
    void Establish(
        std::uint32_t local_index,
        std::uint32_t remote_index,
        MonotonicTime birth_time,
        const noise_symmetric_key &sending_key,
        const noise_symmetric_key &receiving_key,
        std::uint64_t send_counter = 0);
    void Reset();

    bool IsValid() const;
    bool CanSendAt(MonotonicTime now) const;
    bool CanReceiveAt(MonotonicTime now) const;
    KeypairSendState SendStateAt(MonotonicTime now) const;
    KeypairState State() const { return m_state; }
    std::uint32_t LocalIndex() const { return m_local_index; }
    std::uint32_t RemoteIndex() const { return m_remote_index; }
    std::uint64_t SendCounter() const { return m_send_counter; }
    KeypairSendState ReserveSendCounterAt(MonotonicTime now, std::uint64_t &out_counter);
    MonotonicTime BirthTime() const { return m_birth_time; }
    KeypairAgeResult AgeAt(MonotonicTime now) const;
    const noise_symmetric_key &SendingKey() const { return m_sending_key; }
    const noise_symmetric_key &ReceivingKey() const { return m_receiving_key; }
    const ReplayWindow &ReceiveReplayWindow() const { return m_receive_replay_window; }
    ReplayWindow &ReceiveReplayWindow() { return m_receive_replay_window; }

private:
    KeypairState m_state{KeypairState::Empty};
    std::uint32_t m_local_index{0};
    std::uint32_t m_remote_index{0};
    std::uint64_t m_send_counter{0};
    MonotonicTime m_birth_time{};
    noise_symmetric_key m_sending_key{};
    noise_symmetric_key m_receiving_key{};
    ReplayWindow m_receive_replay_window{};
};

static_assert(std::is_trivially_copyable_v<noise_keypair>);

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
bool noise_derive_public_key_text(std::span<char> out_text, std::string_view private_key_text);
bool noise_static_identity_init(
    noise_static_identity *identity,
    std::string_view private_key_text,
    std::string_view peer_public_key_text,
    std::string_view preshared_key_text);
bool noise_precompute_static_static(
    noise_handshake_material *material,
    const noise_static_identity *identity);

} // namespace wgnx::wireguard
