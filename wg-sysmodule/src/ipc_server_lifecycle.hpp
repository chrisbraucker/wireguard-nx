#pragma once

namespace wgnx::sysmodule {

enum class IpcServerLifecyclePhase {
    Idle,
    Serving,
    StopRequested,
    ServerThreadJoined,
    ProcessExitReady,
};

// This model makes the required shutdown ownership explicit and host-testable.
// Normal shutdown is terminal for the process, so the static ServerManager is retained
// after its LoopProcess thread exits and Horizon reclaims its handles on process exit.
class IpcServerLifecycle {
  public:
    [[nodiscard]] bool BeginServing() {
        if (m_phase != IpcServerLifecyclePhase::Idle) {
            return false;
        }

        m_phase = IpcServerLifecyclePhase::Serving;
        return true;
    }

    [[nodiscard]] bool BeginStopping() {
        if (m_phase != IpcServerLifecyclePhase::Serving) {
            return false;
        }

        m_phase = IpcServerLifecyclePhase::StopRequested;
        return true;
    }

    [[nodiscard]] bool MarkServerThreadJoined() {
        if (m_phase != IpcServerLifecyclePhase::StopRequested) {
            return false;
        }

        m_phase = IpcServerLifecyclePhase::ServerThreadJoined;
        return true;
    }

    [[nodiscard]] bool MarkProcessExitReady() {
        if (m_phase != IpcServerLifecyclePhase::ServerThreadJoined) {
            return false;
        }

        m_phase = IpcServerLifecyclePhase::ProcessExitReady;
        return true;
    }

    [[nodiscard]] IpcServerLifecyclePhase Phase() const {
        return m_phase;
    }

  private:
    IpcServerLifecyclePhase m_phase{IpcServerLifecyclePhase::Idle};
};

} // namespace wgnx::sysmodule
