#pragma once

#include "bsd_service.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>

namespace wgnx::mitm {

class BsdMitmService : public ams::sf::MitmServiceImplBase {
  public:
    BsdMitmService(std::shared_ptr<::Service>&& forward_service, const ams::sm::MitmProcessInfo& client_info);
    ~BsdMitmService();

    static bool ShouldMitm(const ams::sm::MitmProcessInfo& client_info);

    ams::Result Socket(ams::sf::Out<s32> out_fd, ams::sf::Out<s32> out_errno, s32 domain, s32 type, s32 protocol);
    ams::Result Poll(ams::sf::Out<s32> out_count, ams::sf::Out<s32> out_errno, const ams::sf::InAutoSelectBuffer& fds_in,
                     ams::sf::OutAutoSelectBuffer fds_out, s32 nfds, s32 timeout);
    ams::Result Recv(ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, s32 fd, s32 flags, ams::sf::OutAutoSelectBuffer buffer);
    ams::Result RecvFrom(ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addr_len, s32 fd, s32 flags,
                         ams::sf::OutAutoSelectBuffer buffer, ams::sf::OutAutoSelectBuffer address);
    ams::Result Send(ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, s32 fd, s32 flags, const ams::sf::InAutoSelectBuffer& buffer);
    ams::Result SendTo(ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, s32 fd, s32 flags,
                       const ams::sf::InAutoSelectBuffer& buffer, const ams::sf::InAutoSelectBuffer& address);
    ams::Result Connect(ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, s32 fd, const ams::sf::InAutoSelectBuffer& address);
    ams::Result GetPeerName(ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addr_len, s32 fd,
                            ams::sf::OutAutoSelectBuffer address);
    ams::Result GetSockName(ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addr_len, s32 fd,
                            ams::sf::OutAutoSelectBuffer address);
    ams::Result Close(ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, s32 fd);

  private:
    struct SocketState {
        bool occupied{};
        bool udp_ipv4{};
        bool tunneled{};
        s32 descriptor{};
    };

    [[nodiscard]] SocketState* FindSocket(s32 descriptor);
    [[nodiscard]] static const char* SocketRouteName(const SocketState* socket);
    void ForgetSocket(s32 descriptor);

    std::uint64_t m_owner{};
    std::array<SocketState, 4> m_sockets{};
    static std::atomic_uint32_t s_next_session_id;
};

static_assert(IsIBsdSystemService<BsdMitmService>);

} // namespace wgnx::mitm
