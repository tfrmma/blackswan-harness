# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - Unreleased

First release. Two layers of fault injection, a determinism engine tying
them together, and a real CLI, all verified against real sockets, a real
kernel, and real processes, not simulated.

### Kernel-level faults (layer 1)
- `XdpPacketLossInjector` and `XdpCorruptionInjector` — real XDP programs
  (`bpf/xdp_pktloss.c`, `bpf/xdp_corrupt.c`), deterministic via a global
  atomic counter against a configured fraction, no RNG involved.
- `XdpPartitionInjector` (`bpf/xdp_partition.c`) — split-brain by source
  IP and optional source port. IPv4 and IPv6 (128 bit address match),
  single and QinQ double VLAN tagging (802.1Q/802.1ad), and correct
  handling of non-initial IPv4/IPv6 fragments (previously a real
  correctness bug: fragment payload bytes could get misread as a
  udphdr/tcphdr and falsely match).
- `CgroupMemoryPressureInjector` — Hard (real OOM-kill, confirmed via
  SIGKILL) and Soft pressure modes, cgroup v1 and v2.
- `TimeSkewInjector` — clock skew via Linux time namespaces, not
  LD_PRELOAD, so it holds for binaries that call `clock_gettime` through
  the vDSO or a raw syscall, not just ones that go through libc in a way
  LD_PRELOAD can intercept.
- Known limitation: XDP allows one program per interface per attach mode,
  so the three XDP-based faults above can't be armed simultaneously on
  the same interface yet. See README Known limitations.

### Exchange-protocol faults (layer 2)
- FIX 4.0-4.4 (`crates/adapters/src/fix`): a real TCP man-in-the-middle
  proxy (`FixProxy`) sitting between client and exchange, parsing framed
  FIX messages and applying one of:
  - `FixSilentReject` — drops a message with no response at all.
  - `FixAckWithoutExecution` — forwards the ack, drops the fill.
  - `FixRateLimitThrottle` — drops outbound traffic past a configured
    count, no exchange-side rate limit involved, the proxy itself is the
    limiter.
  - `FixExecutionReportPriceMutation` — rewrites the Price field on an
    inbound fill to a configured value, the first real use of
    `InterceptAction::Mutate`. `message.rs::set_field` recomputes
    BodyLength and CheckSum from scratch rather than copying them, so the
    result is a genuinely valid FIX message.

### Determinism engine
- `DeterministicRng` (SplitMix64), `ValidatedSchedule`, `Scheduler` over a
  `VirtualClock`, and `Trace` with save/load and bit-exact replay
  matching, in `blackswan-replay`.
- `Runner::run_realtime()` drives real injectors (arm/disarm at the
  scheduled offset, best-effort teardown on drop) against wall-clock
  time, separate from the virtual-clock scheduling path used for replay
  verification.

### CLI
- `blackswan run <scenario.toml>` and `blackswan replay <trace>`, TOML
  scenario configs (see `examples/`), real injectors wired up from config
  through `crates/cli/src/build.rs`.

### CI
- `.github/workflows/ci.yml`: `fmt` and `clippy` (both `-D warnings`),
  `test` (matrix across ubuntu-22.04, ubuntu-24.04, and ubuntu-24.04-arm,
  privileged kernel tests included via `sudo`), and `determinism-gate`
  (builds the CLI, runs and replays the FIX rate-limit example, asserts
  the trace matches bit-exact). All jobs confirmed green against real
  GitHub Actions infrastructure, not just locally.

### Known limitations
See the README's Known limitations section for the full, honest list,
including what's fixed-and-verified versus fixed-but-not-yet-confirmed on
real hardware (the cgroup v2 sibling-cgroup workaround specifically).
