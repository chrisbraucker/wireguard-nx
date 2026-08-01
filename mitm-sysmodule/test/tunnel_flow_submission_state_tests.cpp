#include "tunnel_flow_submission_state.hpp"
#include "tunnel_flow_submission_state_tests.hpp"

#include <cstdio>

namespace {

bool Check(const bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "failure: %s\n", message);
    }
    return condition;
}

} // namespace

bool RunTunnelFlowSubmissionStateTests() {
    using wgnx::mitm::TunnelFlowSubmissionState;

    constexpr std::size_t Capacity = 2;
    TunnelFlowSubmissionState state{};
    const bool accepts_initial_send = state.CanAccept(Capacity) && !state.CanSubmit();

    state.Enqueue();
    const bool accepts_second_send = state.CanAccept(Capacity) && state.CanSubmit() && state.queued == 1;

    state.Enqueue();
    const bool rejects_full_adapter_queue = !state.CanAccept(Capacity) && state.CanSubmit() && state.queued == Capacity;

    state.Retire(1);
    const bool restores_local_admission = state.CanAccept(Capacity) && state.CanSubmit() && state.queued == 1;

    state.NoteQueueFull();
    const bool blocks_until_writable = !state.CanAccept(Capacity) && !state.CanSubmit();

    state.NoteWritable();
    const bool writable_completion_restores_submission = state.CanAccept(Capacity) && state.CanSubmit();

    state.Retire(1);
    const bool deferred_submission_retires_after_writable = state.queued == 0 && !state.CanSubmit();

    state.Close();
    const bool terminal_state_rejects_all_work = !state.CanAccept(Capacity) && !state.CanSubmit() && state.closed;

    return Check(accepts_initial_send, "empty flow did not accept its first send") &&
           Check(accepts_second_send, "flow did not accept queued send below capacity") &&
           Check(rejects_full_adapter_queue, "full adapter queue accepted another send") &&
           Check(restores_local_admission, "retiring one queued payload did not restore admission") &&
           Check(blocks_until_writable, "WGNX queue pressure did not block new sends") &&
           Check(writable_completion_restores_submission, "writable completion did not restore submission") &&
           Check(deferred_submission_retires_after_writable, "deferred payload did not retire after writable resubmission") &&
           Check(terminal_state_rejects_all_work, "closed flow admitted or submitted work");
}
