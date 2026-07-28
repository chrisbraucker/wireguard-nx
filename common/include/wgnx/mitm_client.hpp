#pragma once

#include <switch.h>

#include <memory>

namespace wgnx::mitm::client {

constexpr inline char ServiceName[] = "wgm:ctl";
constexpr inline std::uint32_t ShutdownCommandId = 3;

inline Result QueryServiceAvailability(bool& out_present) {
    const SmServiceName service_name = smEncodeName(ServiceName);
    std::uint8_t present = 0;
    const Result rc = tipcDispatchInOut(smGetServiceSessionTipc(), 65100, service_name, present);
    out_present = R_SUCCEEDED(rc) && present != 0;
    return rc;
}

inline bool IsServiceRunning() {
    bool present = false;
    return R_SUCCEEDED(QueryServiceAvailability(present)) && present;
}

class ScopedService {
  public:
    ScopedService() = default;
    ~ScopedService() {
        Close();
    }

    ScopedService(const ScopedService&) = delete;
    ScopedService& operator=(const ScopedService&) = delete;

    Result Open() {
        if (m_open) {
            return 0;
        }

        const Result rc = smGetService(std::addressof(m_service), ServiceName);
        m_open = R_SUCCEEDED(rc);
        return rc;
    }

    void Close() {
        if (!m_open) {
            return;
        }

        serviceClose(std::addressof(m_service));
        m_service = {};
        m_open = false;
    }

    [[nodiscard]] Service* Get() {
        return std::addressof(m_service);
    }

  private:
    Service m_service{};
    bool m_open{};
};

inline Result Shutdown() {
    ScopedService service;
    Result rc = service.Open();
    if (R_FAILED(rc)) {
        return rc;
    }

    return serviceDispatch(service.Get(), ShutdownCommandId);
}

} // namespace wgnx::mitm::client
