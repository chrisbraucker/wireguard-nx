#include "bsd_tunneled_contract.hpp"
#include "bsd_tunneled_contract_tests.hpp"

#include <cerrno>
#include <cstdio>
#include <poll.h>
#include <sys/socket.h>

namespace {

bool Check(const bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "failure: %s\n", message);
    }
    return condition;
}

} // namespace

bool RunBsdTunneledContractTests() {
    using namespace wgnx::mitm;

    return Check(SupportsTunneledMessageFlags(0), "zero message flags were rejected") &&
           Check(!SupportsTunneledMessageFlags(MSG_DONTWAIT), "MSG_DONTWAIT was accepted") &&
           Check(SupportsTunneledPoll(1, POLLIN), "single-descriptor POLLIN was rejected") &&
           Check(SupportsTunneledPoll(1, POLLOUT), "single-descriptor POLLOUT was rejected") &&
           Check(SupportsTunneledPoll(1, POLLIN | POLLOUT), "combined readiness events were rejected") &&
           Check(!SupportsTunneledPoll(2, POLLIN), "multi-descriptor tunnel poll was accepted") &&
           Check(!SupportsTunneledPoll(1, POLLPRI), "unsupported tunnel poll event was accepted") &&
           Check(SupportsTunneledFcntl(BsdFcntlGetFl, 0), "F_GETFL was rejected") &&
           Check(BsdFcntlNonBlock == 0x800, "BSD:S O_NONBLOCK wire value changed") &&
           Check(TunneledFcntlResult(BsdFcntlGetFl) == BsdFcntlNonBlock, "F_GETFL did not report BSD:S O_NONBLOCK") &&
           Check(SupportsTunneledFcntl(BsdFcntlSetFl, BsdFcntlNonBlock), "F_SETFL(BSD:S O_NONBLOCK) was rejected") &&
           Check(!SupportsTunneledFcntl(BsdFcntlSetFl, 0x4000), "toolchain O_NONBLOCK ABI value was accepted") &&
           Check(TunneledFcntlResult(BsdFcntlSetFl) == 0, "F_SETFL did not report success") &&
           Check(!SupportsTunneledFcntl(BsdFcntlSetFl, 0), "blocking F_SETFL was accepted") &&
           Check(!SupportsTunneledFcntl(99, 0), "unknown fcntl command was accepted");
}
