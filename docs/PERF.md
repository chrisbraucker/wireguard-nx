# Performance Findings

## 2026-08-01 Initial Wi-Fi UDP Baseline

This note records the first performance evidence from `workspace/task_4_reports/performance_wifi_latency` and `workspace/task_4_reports/performance_wifi_throughput`.
The Switch and the remote peer used the same Wi-Fi segment.
The throughput workload sent 4,096 one-way UDP datagrams of 1,380 bytes in each run.
Each run therefore offered 5,652,480 bytes, or 5.65 MB, and each path had six final runs.
The 1,380-byte payload produces a 1,408-byte IPv4/UDP inner packet and leaves 12 bytes below the configured 1,420-byte tunnel MTU.
Requester submission rate and harness receive goodput use separate local clocks and must not be combined by timestamp subtraction.

| Path                  | Median latency from requester run means | Median sender rate | Median receiver goodput | Delivery |
|-----------------------|----------------------------------------:|-------------------:|------------------------:|---------:|
| Direct `wgnx:tun`     |                                32.83 ms |         0.114 MB/s |              0.113 MB/s |     100% |
| BSD MITM to WireGuard |                                32.81 ms |         0.123 MB/s |              0.123 MB/s |     100% |
| Native BSD            |                                 3.54 ms |         7.678 MB/s |              6.898 MB/s |    84.5% |
| Passive BSD MITM      |                                 3.67 ms |         6.862 MB/s |              6.577 MB/s |    95.3% |

In this diagnostic-heavy baseline, the full BSD MITM path was within run-to-run variation of direct `wgnx:tun` for both latency and throughput.
That run therefore did not expose the MITM cost that becomes visible in the quiet-build measurement below.
The baseline measured about 29 ms of additional tunnel round-trip time relative to direct Wi-Fi, but this remains provisional until repeated with the quiet build.
The direct and full tunnel workloads delivered every accepted datagram exactly once and in order.
The unpaced native and passive runs lost host-received datagrams, so their rates are burst-injection measurements rather than Wi-Fi capacity measurements.

## Observed Ceiling And Disposition

The direct `wgnx:tun` runs took 47.6 to 59.2 seconds to submit 5.65 MB.
They reported 4,082 to 4,086 `QueueFull` retries for 4,096 accepted datagrams.
The full BSD MITM runs took 45.3 to 50.1 seconds and reported 2,045 to 2,069 requester `QueueFull` retries per run.
The WireGuard flow summaries confirm 4,096 admitted sends per tunnel workload and no dropped inbound records.
This is correct bounded backpressure rather than a loss, crash, or unexplained timeout.

The initial runs appeared to be limited by synchronous one-datagram CMIF submission into bounded peer staging, followed by `QueueFull`, a `Writable` completion, and retry of the same datagram.
The corrected quiet-build results below show that high-rate filesystem diagnostics dominated this measurement.
The initial rates therefore do not measure the Wi-Fi, cryptographic, IPC, or eventual architecture throughput ceiling.
The successful bounded `QueueFull` and `Writable` recovery remains valid correctness evidence.
The smallest offered rate that first reaches this backpressure boundary remains unmeasured.

## Measurement Build Correction

The throughput WireGuard log contains 171,899 lines.
146,366 lines are timer schedule or cancellation records, including 69,277 persistent-keepalive schedule records and 69,277 matching cancellations.
The existing `WGNX_PACKET_DIAGNOSTICS=0` measurement switch did not suppress those records because the timer and inbound packet traces used `logger::Log` instead of `logger::LogPacket`.
Those traces now use the existing packet-diagnostic gate, while lifecycle, state-transition, and flow-closure summaries remain enabled.
No new build option is required for the rerun because `WGNX_PACKET_DIAGNOSTICS` already defaults to `0`.

The corrected build was deployed with `WGNX_PACKET_DIAGNOSTICS=0` and retained flow summaries without the high-rate timer and packet records.

## Corrected Quiet-Build Throughput

The coherent corrected evidence set is archived under `workspace/task_4_reports/perf_wifi_quiet`.
It used WireGuard build `0.0.1-dev-21f1018-dirty`, MITM build `0.0.1-dev-689fa7f`, requester build `0.1.0-a70f22e-dirty`, and the same 4,096-datagram workload as the initial throughput run.
Each direct and full BSD MITM path completed six runs.

| Path                  | Median requester submission rate | Median harness receiver goodput |  Requester range | Delivery |                              Queue pressure per run |
|-----------------------|---------------------------------:|--------------------------------:|-----------------:|---------:|----------------------------------------------------:|
| Direct `wgnx:tun`     |                       2.587 MB/s |                      2.584 MB/s | 2.571-2.619 MB/s |     100% |                            4,087 `QueueFull` events |
| BSD MITM to WireGuard |                       1.273 MB/s |                      1.273 MB/s | 1.264-1.277 MB/s |     100% | 4,086 requester retries and 4,087 downstream events |

Every run delivered all 4,096 datagrams and 5,652,480 bytes exactly once and in order.
Requester and harness rates agree within normal timing variation while remaining independent local-clock measurements.
The direct path is about 22.7 times faster than its diagnostic-heavy initial result, and the full MITM path is about 10.3 times faster than its initial result.
The full MITM path reaches about 49 percent of direct `wgnx:tun` goodput in this workload.

The MITM worker accepted all 24,576 datagrams across its six runs, rejected no operations, discarded no sends, and reported an operation-queue high-water mark of one.
This rules out saturation of the MITM operation queue in this run.
The remaining direct-to-MITM delta belongs to the combined MITM worker, BSD translation, additional IPC, batching, completion-drain, and writable-retry work, but this evidence does not isolate their individual costs.
The current measured ceiling is therefore approximately 2.6 MB/s for direct `wgnx:tun` and 1.27 MB/s for the full BSD MITM path on this Wi-Fi topology, with bounded backpressure rather than loss or instability.

## Unpaced Direct-Flow Sweep

The same quiet build was swept with 64, 256, 1,024, and 4,096 unpaced datagrams while retaining the 1,380-byte payload and one direct `wgnx:tun` flow.
The attempted 16,384-datagram setting was correctly rejected because the requester configuration currently caps a workload at 4,096 datagrams.

|    Datagrams | Requester submission rate | Harness receiver goodput | `QueueFull` events | Delivery |
|-------------:|--------------------------:|-------------------------:|-------------------:|---------:|
|           64 |                1.950 MB/s |               1.852 MB/s |                 55 |     100% |
|          256 |                2.674 MB/s |               2.670 MB/s |                247 |     100% |
|        1,024 |                2.630 MB/s |               2.613 MB/s |              1,015 |     100% |
|        4,096 |                2.601 MB/s |               2.601 MB/s |              4,087 |     100% |
| 4,096 repeat |                2.613 MB/s |               2.622 MB/s |              4,087 |     100% |

The direct path settles near 2.6 MB/s from 256 datagrams onward.
Every unpaced workload reaches bounded peer staging almost immediately, including the 64-datagram case, and then drains without loss, duplication, or reordering.
Nine sends avoid `QueueFull` in each burst, but concurrent draining means this is an observed burst shape rather than a fixed queue-capacity measurement.

Separate follow-up on-device observations, which are not present in the archived quiet evidence set, reported no `QueueFull` events with either 2 ms or 1 ms pacing.
At 1,380 bytes per datagram, 1 ms pacing offers approximately 1.38 MB/s before protocol overhead and remains below the measured direct ceiling.
The first pressure point therefore lies between 1 ms pacing and an unpaced burst, but the requester's millisecond pacing granularity cannot locate it more precisely.

## Task 5 Interpretation And Next Measurement

The corrected results support a Task 5 feasibility conclusion of viable with optimization.
The architecture moves sustained data without loss or instability, while the direct and MITM rates leave clear performance work before media-sized traffic should be considered production-ready.
The evidence does not yet justify shared-memory transport because ordinary CMIF is functional and its isolated ceiling has not been measured.
The next high-signal experiment is the Task 5 auxiliary net-probe IPC sink, comparing the existing IP-sized contract with fewer calls carrying larger experimental payloads before changing the production `wgnx:tun` contract.
Repeat the throughput and latency matrix after the userspace IP adapter replaces the manual UDP path.
