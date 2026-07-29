#pragma once

namespace wgnx::mitm {

enum class TerminalServerLifecyclePhase {
    Idle,
    Serving,
    StopRequested,
    ServerThreadJoined,
    RetainedForProcessExit,
};

// A sysmodule shutdown is terminal for this process.
// Horizon aborts while destructing ServerManager after LoopProcess has exited, so
// the manager and anything it owns must remain alive until process teardown.
class TerminalServerLifecycle {
  public:
    [[nodiscard]] bool BeginServing() {
        if (m_phase != TerminalServerLifecyclePhase::Idle) {
            return false;
        }

        m_phase = TerminalServerLifecyclePhase::Serving;
        return true;
    }

    [[nodiscard]] bool BeginStopping() {
        if (m_phase != TerminalServerLifecyclePhase::Serving) {
            return false;
        }

        m_phase = TerminalServerLifecyclePhase::StopRequested;
        return true;
    }

    [[nodiscard]] bool MarkServerThreadJoined() {
        if (m_phase != TerminalServerLifecyclePhase::StopRequested) {
            return false;
        }

        m_phase = TerminalServerLifecyclePhase::ServerThreadJoined;
        return true;
    }

    [[nodiscard]] bool RetainForProcessExit() {
        if (m_phase != TerminalServerLifecyclePhase::ServerThreadJoined) {
            return false;
        }

        m_phase = TerminalServerLifecyclePhase::RetainedForProcessExit;
        return true;
    }

    [[nodiscard]] TerminalServerLifecyclePhase Phase() const {
        return m_phase;
    }

  private:
    TerminalServerLifecyclePhase m_phase{TerminalServerLifecyclePhase::Idle};
};

} // namespace wgnx::mitm
