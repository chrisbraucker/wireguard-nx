#pragma once

namespace wgnx::sysmodule {

enum class IpcServerLifecyclePhase {
    Idle,
    Serving,
    StopRequested,
    ServerThreadJoined,
    Destroyed,
};

// This model makes the required shutdown ownership explicit and host-testable.
// The ServerManager may only be destroyed after its LoopProcess thread has exited.
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

    [[nodiscard]] bool MarkDestroyed() {
        if (m_phase != IpcServerLifecyclePhase::ServerThreadJoined) {
            return false;
        }

        m_phase = IpcServerLifecyclePhase::Destroyed;
        return true;
    }

    [[nodiscard]] IpcServerLifecyclePhase Phase() const {
        return m_phase;
    }

  private:
    IpcServerLifecyclePhase m_phase{IpcServerLifecyclePhase::Idle};
};

} // namespace wgnx::sysmodule
