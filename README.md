# blackswan-harness

Deterministic chaos engineering for OMS/SOR and other latency-sensitive
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
has its first real target: FIX, with three exchange-semantic faults (silent
reject, ack without execution, rate-limit throttle) running through a real
TCP proxy. The `Runner` ties a `Scenario` to real injectors from both
layers end to end, verified against live sockets.

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
  `message.rs` (parsing, checksum, verified against a real reference
  message), `framing.rs` (finds message boundaries in a TCP byte stream),
  `proxy.rs` (`FixProxy`, a real TCP man-in-the-middle, single connection at
  a time), `adapter.rs` (`FixSilentReject`, `FixAckWithoutExecution`,
  `FixRateLimitThrottle`, the actual `ProtocolAdapter` decision logic),
  `injector.rs` (`FixFaultInjector`, wraps any `ProtocolAdapter` as a
  `FaultInjector`, composition instead of one struct per fault since all
  three share the same proxy mechanism and only differ in decision logic).
  Verified end to end over real TCP sockets, no root needed.
- `crates/cli` - control plane binary. Currently a no-op.

## Known limitations

- `xdp_partition` only understands plain Ethernet + IPv4. No VLAN (802.1Q
  shifts the EtherType position), no IPv6, no IP fragmentation. Packets in
  any of those categories are safely ignored (never matched, so the fault
  never fires on them), but that's a real coverage gap for a target running
  dual-stack or on a tagged VLAN, not just a cosmetic one.
- No throughput/load testing on any XDP injector yet, only traffic spaced
  5ms apart in the live tests. The global atomic counter should hold up
  under real concurrency, but "should" isn't "verified", worth a real
  saturation test before trusting the exact drop/corrupt counts under load.
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
- `FixProxy` handles one client connection at a time, a second connection
  attempt queues in the OS backlog rather than being actively refused, and
  won't be served until the first session ends. Fine for testing a single
  OMS/SOR instance against one exchange session, not for anything wanting
  concurrent FIX sessions through the same proxy.
- The FIX adapters only inspect flat fields (35, 39, 150), no repeating
  group support. Not needed for the three faults implemented so far, would
  matter for anything wanting to key off a field inside a repeating group.
- Only three FIX message types are handled (ExecutionReport, Reject,
  OrderCancelReject) and `InterceptAction::Mutate` has no FIX adapter using
  it yet, mutating an outbound NewOrderSingle (wrong price, stale ClOrdID,
  wrong side) is a real gap, not just an unlikely one.
- FIX is the only protocol adapter. WebSocket (most crypto exchange retail
  APIs) and plain REST (order entry over HTTP, real 429s instead of FIX
  BusinessMessageReject) are the obvious next targets, deliberately not
  built yet, and deliberately not forced through `FixProxy`'s shape since
  one example isn't enough evidence for what a shared proxy abstraction
  across three different protocols should look like.
- No test yet exercises a real failure path (arming against a nonexistent
  interface, for example) to confirm `HarnessError::ArmFailed` actually
  propagates cleanly in practice, only the happy path has live coverage so
  far.

## Requirements

Compiling `crates/kernel` needs `clang` and `libbpf-dev` (for
`bpf/bpf_helpers.h`) on the build machine. Running `XdpPacketLossInjector`
directly or through `Runner`, needs root or `CAP_BPF` + `CAP_NET_ADMIN`. The
live tests are `#[ignore]`d by default and share the loopback interface, run
them explicitly and serialized with
`cargo test -p blackswan-kernel -- --ignored --test-threads=1`.

## License

MIT
