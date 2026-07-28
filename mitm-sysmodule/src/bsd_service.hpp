#pragma once

#include <stratosphere.hpp>

/*
 * The BSD CMIF layouts below are derived from libnx's public bsd service
 * wrapper and validated against the requester bsd:s trace corpus.
 * libnx decodes every response as [result, errno], then any command-specific
 * output, so every handled command declares that envelope explicitly.
 * Only the narrow connected IPv4 UDP subset is handled locally.
 * All other commands are forwarded by Atmosphere's MITM dispatcher.
 */
#define WGNX_I_BSD_SYSTEM_SERVICE_INTERFACE_INFO(C, H)                                                                                     \
    AMS_SF_METHOD_INFO(C, H, 2, ams::Result, Socket,                                                                                       \
                       (ams::sf::Out<s32> out_fd, ams::sf::Out<s32> out_errno, s32 domain, s32 type, s32 protocol),                        \
                       (out_fd, out_errno, domain, type, protocol), ams::hos::Version_Min, ams::hos::Version_Max)                          \
    AMS_SF_METHOD_INFO(C, H, 6, ams::Result, Poll,                                                                                         \
                       (ams::sf::Out<s32> out_count, ams::sf::Out<s32> out_errno, const ams::sf::InAutoSelectBuffer& fds_in,               \
                        ams::sf::OutAutoSelectBuffer fds_out, s32 nfds, s32 timeout),                                                      \
                       (out_count, out_errno, fds_in, fds_out, nfds, timeout), ams::hos::Version_Min, ams::hos::Version_Max)               \
    AMS_SF_METHOD_INFO(C, H, 8, ams::Result, Recv,                                                                                         \
                       (ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, s32 fd, s32 flags, ams::sf::OutAutoSelectBuffer buffer),  \
                       (out_size, out_errno, fd, flags, buffer), ams::hos::Version_Min, ams::hos::Version_Max)                             \
    AMS_SF_METHOD_INFO(C, H, 9, ams::Result, RecvFrom,                                                                                     \
                       (ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addr_len, s32 fd, s32 flags,        \
                        ams::sf::OutAutoSelectBuffer buffer, ams::sf::OutAutoSelectBuffer address),                                        \
                       (out_size, out_errno, out_addr_len, fd, flags, buffer, address), ams::hos::Version_Min, ams::hos::Version_Max)      \
    AMS_SF_METHOD_INFO(                                                                                                                    \
        C, H, 10, ams::Result, Send,                                                                                                       \
        (ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, s32 fd, s32 flags, const ams::sf::InAutoSelectBuffer& buffer),           \
        (out_size, out_errno, fd, flags, buffer), ams::hos::Version_Min, ams::hos::Version_Max)                                            \
    AMS_SF_METHOD_INFO(C, H, 11, ams::Result, SendTo,                                                                                      \
                       (ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, s32 fd, s32 flags,                                        \
                        const ams::sf::InAutoSelectBuffer& buffer, const ams::sf::InAutoSelectBuffer& address),                            \
                       (out_size, out_errno, fd, flags, buffer, address), ams::hos::Version_Min, ams::hos::Version_Max)                    \
    AMS_SF_METHOD_INFO(C, H, 14, ams::Result, Connect,                                                                                     \
                       (ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, s32 fd, const ams::sf::InAutoSelectBuffer& address),    \
                       (out_result, out_errno, fd, address), ams::hos::Version_Min, ams::hos::Version_Max)                                 \
    AMS_SF_METHOD_INFO(C, H, 15, ams::Result, GetPeerName,                                                                                 \
                       (ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addr_len, s32 fd,                 \
                        ams::sf::OutAutoSelectBuffer address),                                                                             \
                       (out_result, out_errno, out_addr_len, fd, address), ams::hos::Version_Min, ams::hos::Version_Max)                   \
    AMS_SF_METHOD_INFO(C, H, 16, ams::Result, GetSockName,                                                                                 \
                       (ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addr_len, s32 fd,                 \
                        ams::sf::OutAutoSelectBuffer address),                                                                             \
                       (out_result, out_errno, out_addr_len, fd, address), ams::hos::Version_Min, ams::hos::Version_Max)                   \
    AMS_SF_METHOD_INFO(C, H, 26, ams::Result, Close, (ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, s32 fd),                  \
                       (out_result, out_errno, fd), ams::hos::Version_Min, ams::hos::Version_Max)

AMS_SF_DEFINE_MITM_INTERFACE(wgnx::mitm, IBsdSystemService, WGNX_I_BSD_SYSTEM_SERVICE_INTERFACE_INFO, 0x57474253);
