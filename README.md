# blackswan-harness

Deterministic chaos engineering for latency-sensitive
trading infrastructure. Two layers: kernel-level fault injection (eBPF,
cgroups, time namespaces) that works against any target with zero code
changes, and protocol-aware adapters (FIX, exchange WS/REST) for
exchange-semantic faults that don't exist at the kernel level, silent
rejects, acks without execution, sudden rate-limit throttling.

Every fault run is seeded and replayable. A scenario that finds a bug should
reproduce that bug bit-exact, not just "probably" reproduce it.

## Status

Layer 1 (kernel-level fault injection) is complete: three real XDP faults
(packet loss, byte corruption, network partition), cgroup-based memory
pressure, and time namespace clock skew. Layer 2 (protocol-aware adapters)
has its first real target: FIX, with four exchange-semantic faults (silent
reject, ack without execution, rate-limit throttle, execution report price
mutation) running through a real TCP proxy. Phase 5 (control plane) has a
real CLI: `blackswan run` drives a TOML-configured scenario against real
injectors in real time, `blackswan replay` confirms a scenario reproduces a
saved trace bit-exact. Verified end to end, config file through real
sockets and a real kernel fault, not just unit tested in isolation.

## Layout

- `crates/core` - shared traits (`FaultInjector`, `ProtocolAdapter`, `Clock`,
  `Scenario`). Everything else depends on this, nothing in here depends on
  eBPF, cgroups, or any specific protocol.
- `crates/replay` - determinism engine: `DeterministicRng` (SplitMix64),
  `ValidatedSchedule` (structural checks on a `Scenario`), `Scheduler`
  (drives a `VirtualClock` against a schedule), `Trace` (record, save,
  reload, and bit-exact compare a run), and `Runner` (ties a schedule to a
  registry of real `FaultInjector`s, arms/disarms them at the right times,
  disarms anything still armed on drop). Implemented and tested.
- `crates/kernel` - layer 1, kernel-level fault injection. `XdpPacketLossInjector`,
  `XdpCorruptionInjector`, and `XdpPartitionInjector` are real: XDP programs
  (`bpf/xdp_pktloss.c`, `bpf/xdp_corrupt.c`, `bpf/xdp_partition.c`) compiled
  at build time via clang targeting `bpf`, loaded and attached through
  `aya`. All fully deterministic, no in-kernel randomness, every fault
  decision comes from userspace config maps. None of the three can attach to
  the same interface simultaneously (XDP allows one program per interface
  per attach mode), see the TODO in `kernel/src/lib.rs`, worth unifying into
  a single dispatcher before a fourth XDP fault shows up.
  `CgroupMemoryPressureInjector` (`kernel/src/cgroup_mem.rs`) is real too:
  detects cgroup v1 vs v2 at arm time, creates a child cgroup, moves the
  target pid in, writes a byte limit (`memory.max`/`memory.high` on v2,
  `memory.limit_in_bytes`/`memory.soft_limit_in_bytes` on v1).
  `TimeSkewInjector` (`kernel/src/time_skew.rs`) is the last layer 1 piece:
  clock skew via Linux time namespaces. Structurally different from every
  other injector here, time namespaces can only be configured for a process
  at its own `exec()`, never retroactively, so `arm()` launches its own
  supervised child instead of attaching to an existing target, and
  `disarm()` terminates that child rather than just neutralizing an effect
  (documented as the explicit exception on `FaultInjector::disarm` itself).
  Only `CLOCK_MONOTONIC`/`CLOCK_BOOTTIME` are affected, never
  `CLOCK_REALTIME`, that's a hard kernel limitation. Layer 1 is complete.
- `crates/adapters` - layer 2, protocol-aware exchange fault injection. FIX
  4.0-4.4 dialect (3-field header: BeginString, BodyLength, MsgType; the
  FIXT.1.1/5.0 extended header isn't supported). `crates/adapters/src/fix/`:
  `message.rs` (parsing, checksum, and `set_field`, a re-encoder that
  recomputes BodyLength/CheckSum after replacing one tag's value, verified
  against a real reference message), `framing.rs` (finds message boundaries
  in a TCP byte stream), `proxy.rs` (`FixProxy`, a real TCP man-in-the-
  middle, single connection at a time), `adapter.rs` (`FixSilentReject`,
  `FixAckWithoutExecution`, `FixRateLimitThrottle`,
  `FixExecutionReportPriceMutation`, the actual `ProtocolAdapter` decision
  logic), `injector.rs` (`FixFaultInjector`, wraps any `ProtocolAdapter` as
  a `FaultInjector`, composition instead of one struct per fault since all
  four share the same proxy mechanism and only differ in decision logic).
  Verified end to end over real TCP sockets, no root needed.
- `crates/cli` - the control plane binary (`blackswan`). `run` loads a TOML
  scenario config, builds the named injectors, and drives them through
  `Runner::run_realtime` so live faults (a listening FIX proxy, an attached
  XDP hook) stay reachable by real external traffic for the scenario's real
  duration, not just fire virtually and exit. `replay` re-runs a scenario
  fast (`Runner::run`, no real-time pacing) and confirms it reproduces a
  previously saved `Trace` bit-exact. `config.rs` has one variant per real
  injector this binary knows how to build; `build.rs` turns a config entry
  into the actual injector. Example configs in `examples/`.

## Known limitations

- `xdp_partition` peels up to two 802.1Q/802.1ad tags (single VLAN and QinQ
  double tagging) before checking for IPv4 or IPv6, verified with hand
  built raw frames injected over `lo` via AF_PACKET, this sandbox can't
  create a real VLAN subinterface to test full end to end delivery
  (`ip link add ... type vlan` fails, no loadable kernel modules here), and
  has no IPv6 stack at all (`/proc/net/if_inet6` doesn't exist, binding a
  v6 socket fails with EAFNOSUPPORT, confirmed not assumed), so both the
  VLAN and IPv6 checks observe XDP's own verdict (does the frame reach
  `netif_receive_skb` or not) rather than real socket delivery. IPv6
  matches on the full 128 bit source address (`partition_src_ip6`, a
  parallel map to the v4 one, `src_port` is shared, family-agnostic).
  Extension headers: exactly one Fragment header is walked (the v6
  equivalent of the v4 fragmentation fix below), anything else in the
  chain (Hop-by-Hop, Routing, Destination Options, ESP/AH...) isn't
  walked, safely passed instead rather than guessed at, a real coverage
  gap for a target that uses those, not just a cosmetic one. Also fixed
  for both v4 and v6: non-initial fragments used to get their raw payload
  bytes misread as a udphdr/tcphdr, a real correctness bug, not just a
  coverage gap, could falsely drop allowed traffic on a byte coincidence.
  Every fix here has a live regression test, and every one of those was
  confirmed to actually fail without the fix and pass with it (reverted,
  watched it fail, restored), not just written and trusted.
- `XdpPacketLossInjector` and `XdpCorruptionInjector` are now verified under
  real concurrent bursty load, not just gently spaced traffic: 8 threads
  firing 7000 packets with no spacing at all, checking the aggregate drop
  and corruption counts against an exact modulus rather than correlating
  order (arrival order isn't guaranteed under real concurrency, only the
  totals are). `__sync_fetch_and_add` held up exactly in both. This
  doesn't extend to `XdpPartitionInjector`, whose determinism is a plain
  IP/port match rather than a counter, so there's no modulus to stress in
  the same way.
- None of `XdpPacketLossInjector`, `XdpCorruptionInjector`, and
  `XdpPartitionInjector` can be attached to the same interface
  simultaneously (XDP allows one program per interface per attach mode).
  Not blocking right now, memory pressure and clock skew aren't XDP-based,
  but running two of these three faults on the same target at once is a
  real use case and needs the dispatcher unification mentioned in
  `kernel/src/lib.rs` before release.
- `CgroupMemoryPressureInjector` detects and supports both cgroup v1 and v2
  memory controller interfaces, but only the v1 path has actually been
  exercised: this sandbox has `memory` delegated on the legacy v1 hierarchy,
  not v2 unified (`cgroup.controllers` at the v2 root only lists `hugetlb`),
  verified directly rather than assumed. The v2 code path follows the
  documented cgroup-v2 interface but needs real verification on a v2-only
  machine before it's trusted.
- On GitHub Actions hosted runners specifically (confirmed cgroup v2
  unified, `cgroup2fs`), the live `cgroup_mem_pressure_live` tests can't run
  at all, and it isn't a bug in the injector: the job's own process tree
  lives directly inside `system.slice/hosted-compute-agent.service`, a
  cgroup with member processes of its own, and cgroup v2's no internal
  process constraint forbids a non-root cgroup from enabling a controller
  in its `cgroup.subtree_control` while it still has processes of its own
  (see the [kernel's cgroup-v2 admin
  guide](https://docs.kernel.org/admin-guide/cgroup-v2.html#no-internal-process-constraint)).
  Confirmed directly on a hosted runner: `echo +memory >
  .../hosted-compute-agent.service/cgroup.subtree_control` returns an I/O
  error, and a child cgroup created underneath never gets `memory.max` (or
  any other memory controller interface file). CI skips these two tests by
  name for this reason, see the CI section below. `cgroup_mem.rs` places
  the fault's cgroup as a sibling of the caller's own cgroup specifically
  to sidestep this constraint (see the comment there), but that workaround
  hasn't actually been confirmed passing yet on a machine with real v2
  delegation, only reasoned through against the kernel doc. Worth an
  honest test before leaning on it.
- `FixProxy` handles one client connection at a time, a second connection
  attempt queues in the OS backlog rather than being actively refused, and
  won't be served until the first session ends. Fine for testing a single
  OMS/SOR instance against one exchange session, not for anything wanting
  concurrent FIX sessions through the same proxy.
- The FIX adapters only inspect flat fields (35, 39, 150), no repeating
  group support. Not needed for the three faults implemented so far, would
  matter for anything wanting to key off a field inside a repeating group.
- Only three FIX message types are actively inspected (ExecutionReport,
  Reject, OrderCancelReject). `InterceptAction::Mutate` has one real
  adapter now, `FixExecutionReportPriceMutation` (inbound, rewrites Price
  on a fill, `message.rs::set_field` recomputes BodyLength/CheckSum so the
  result is a genuinely valid message, not just plausible-looking bytes,
  verified against an independent checksum computation and re-framed with
  `find_complete_message` in the live test, not just parsed once and
  trusted). Mutating outbound NewOrderSingle fields (wrong price, stale
  ClOrdID, wrong side) is still a real gap, not just an unlikely one,
  nothing reads or rewrites a client's own order yet.
- FIX is the only protocol adapter. WebSocket (most crypto exchange retail
  APIs) and plain REST (order entry over HTTP, real 429s instead of FIX
  BusinessMessageReject) are the obvious next targets, deliberately not
  built yet, and deliberately not forced through `FixProxy`'s shape since
  one example isn't enough evidence for what a shared proxy abstraction
  across three different protocols should look like.
- `HarnessError::ArmFailed` is verified on a real failure path now, not
  just the happy path: `arm_failed_live.rs` arms `XdpPacketLossInjector`
  against a nonexistent interface and confirms the error propagates
  cleanly, `is_armed()` stays false, and `disarm()` is still a safe no-op
  afterward. One injector is enough evidence here, every XDP-based
  injector in this crate fails through the exact same
  `program.attach(&iface, ...)` call.

## CI

`.github/workflows/ci.yml`. Four jobs: `fmt` and `clippy` (both hard gates,
`-D warnings`, matching the zero-warnings bar this repo has been held to by
hand throughout), `test` (a matrix across ubuntu-22.04, ubuntu-24.04, and
ubuntu-24.04-arm, each running the normal suite plus the privileged kernel
tests via `sudo`, skipping the two cgroup memory-pressure tests that can't
pass on a hosted runner's cgroup topology, see Known limitations), and
`determinism-gate` (builds the CLI, runs the FIX rate-limit example
scenario, then replays it and asserts the trace matches bit-exact, the
actual promise this README opens with, checked in CI, not just in an
isolated unit test).

The arm64 leg is real, not aspirational: `kernel/build.rs` used to hardcode
the x86_64 multiarch include path, fixed while wiring this up (via
`dpkg-architecture -qDEB_HOST_MULTIARCH`, with a fallback for the two
architectures this crate claims to support), otherwise the arm64 job would
have failed on the first push.

Caveat: this workflow is written against verified facts (the runner labels,
the actions used, local reproduction of what each job runs) but hasn't
been exercised by an actual GitHub Actions run yet, that needs a real push
to confirm.

## Requirements

Compiling `crates/kernel` needs `clang` and `libbpf-dev` (for
`bpf/bpf_helpers.h`) on the build machine. Running `XdpPacketLossInjector`
directly or through `Runner`, needs root or `CAP_BPF` + `CAP_NET_ADMIN`. The
live tests are `#[ignore]`d by default and share the loopback interface, run
them explicitly and serialized with
`cargo test -p blackswan-kernel -- --ignored --test-threads=1`.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT
