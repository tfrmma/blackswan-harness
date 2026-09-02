# blackswan-harness

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Deterministic chaos engineering for OMS/SOR and other latency-sensitive
trading infrastructure.

Most chaos tools tell you a fault happened. This one guarantees it happens
again, exactly the same way, on demand. Every run in blackswan-harness is
seeded and replayable: the same scenario executed twice produces a
bit-exact identical sequence of events. A scenario that finds a bug should
reproduce that bug, not "probably" reproduce it.

## Why

Chaos testing for trading systems usually means one of two things: a shell
script that runs `tc` and `iptables` by hand, or a general-purpose chaos
tool (built for microservices and Kubernetes) bent into a shape it wasn't
designed for. Neither gives you two things that actually matter for this
domain:

- **Reproducibility.** If a fault scenario surfaces a race condition or a
  reconciliation bug, you need to hit it again on demand, not hope it
  recurs. Every fault decision in blackswan-harness traces back to a seeded
  RNG and a virtual clock, recorded in a `Trace` that can be replayed and
  compared bit-for-bit against a previous run.
- **Protocol awareness.** A dropped TCP packet and a silently rejected FIX
  order are different failure modes that break different code paths. Kernel
  level chaos (dropped packets, corrupted bytes, partitioned peers, memory
  pressure, clock skew) can't express the second kind. blackswan-harness
  treats both as first-class, composable faults.

## Architecture

Two layers, both implementing the same `FaultInjector` trait so they run
through the same scheduler and the same scenario format:

- **Layer 1, kernel-level.** eBPF (XDP) for packet loss, byte corruption,
  and peer partitioning; cgroups for memory pressure; Linux time namespaces
  for clock skew. Works against any target process with zero code changes,
  no agent to install, no library to link.
- **Layer 2, protocol-aware.** A real man-in-the-middle proxy that parses
  the wire protocol and realizes faults that only make sense at that level:
  a silent reject, an order acknowledged but never filled, a request that
  vanishes under simulated rate-limit throttling. FIX is implemented today;
  the adapter interface is protocol-agnostic.

Every fault is deterministic by construction. Kernel-level decisions run on
counters and configuration written from userspace, never on in-kernel
randomness. Protocol-level decisions read parsed message fields against
rules you set, never a coin flip.

```
Scenario (seed + timed steps)
        |
        v
ValidatedSchedule --> Scheduler --> Runner --> FaultInjector (layer 1 or 2)
                                       |
                                       v
                                    Trace (recorded, replayable, comparable)
```

## Status

**Layer 1 is complete.** Three real XDP faults (packet loss, byte
corruption, network partition), cgroup-based memory pressure, and time
namespace clock skew, all verified against a live kernel, not mocked.

**Layer 2 has its first target: FIX.** Three exchange-semantic faults
(silent reject, ack without execution, rate-limit throttle) running through
a real TCP proxy, verified over live sockets.

**Not built yet:** the control plane (scenario config files, a real CLI),
additional protocol adapters (WebSocket, REST), and further FIX message
coverage. See [Roadmap](#roadmap) and [Known limitations](#known-limitations).

## Example

```rust
use blackswan_core::{FaultContext, FaultInjector, Scenario, ScenarioStep, StepAction, SystemClock};
use blackswan_kernel::XdpPacketLossInjector;
use blackswan_replay::{Runner, ValidatedSchedule};
use std::collections::HashMap;
use std::sync::Arc;

let scenario = Scenario {
    name: "gateway-packet-loss".into(),
    seed: 42,
    steps: vec![
        ScenarioStep { at_ns: 0, fault_id: "pktloss".into(), action: StepAction::Arm },
        ScenarioStep { at_ns: 30_000_000_000, fault_id: "pktloss".into(), action: StepAction::Disarm },
    ],
};
let schedule = ValidatedSchedule::validate(scenario)?;

let mut injectors: HashMap<String, Box<dyn FaultInjector>> = HashMap::new();
injectors.insert("pktloss".into(), Box::new(XdpPacketLossInjector::new("pktloss", "eth0", 20)));

let ctx = FaultContext { clock: Arc::new(SystemClock), seed: 42 };
let mut runner = Runner::new(&schedule, injectors, ctx)?;
let trace = runner.run(1_000_000)?;
trace.save(std::path::Path::new("run.json"))?;
```

Run it again with the same seed and the same schedule, and `trace` will
`matches_schedule()` the one you just saved.

## Crate layout

- **`core`** — shared traits everything else depends on: `FaultInjector`
  (arm/disarm/is_armed), `ProtocolAdapter`, `Clock`, `Scenario`. No eBPF,
  cgroup, or protocol-specific code here.
- **`replay`** — the determinism engine. `DeterministicRng` (SplitMix64),
  `ValidatedSchedule` (structural validation of a `Scenario`), `Scheduler`
  (drives a virtual clock against a schedule), `Trace` (record, persist,
  reload, bit-exact compare), `Runner` (ties a schedule to real injectors,
  arms/disarms them at the right time, disarms anything still armed on
  drop).
- **`kernel`** — layer 1. `XdpPacketLossInjector`, `XdpCorruptionInjector`,
  `XdpPartitionInjector` (eBPF, compiled at build time via clang, loaded
  through `aya`), `CgroupMemoryPressureInjector` (v1/v2 aware), and
  `TimeSkewInjector` (Linux time namespaces; structurally different from
  every other injector here, see its doc comment).
- **`adapters`** — layer 2. `fix/` holds a from-scratch FIX 4.0-4.4 parser,
  stream framing, a real TCP proxy (`FixProxy`), three `ProtocolAdapter`
  implementations, and `FixFaultInjector`, which wraps any `ProtocolAdapter`
  as a `FaultInjector`.
- **`cli`** — the control plane binary. Currently a no-op; this is phase 5.

## Requirements

Compiling `kernel` needs `clang` and `libbpf-dev` (for `bpf/bpf_helpers.h`)
on the build machine. Running any kernel-level injector, directly or
through `Runner`, needs root or `CAP_BPF` + `CAP_NET_ADMIN`. The layer 1
live tests are `#[ignore]`d by default and share state (network interfaces,
cgroups), run them explicitly and serialized:

```
cargo test -p blackswan-kernel -- --ignored --test-threads=1
```

Layer 2 tests need no special privileges, plain TCP sockets:

```
cargo test -p blackswan-adapters
```

## Known limitations

- `xdp_partition` only understands plain Ethernet + IPv4. No VLAN, no IPv6,
  no IP fragmentation. Packets outside that are safely passed through
  rather than mismatched, but that's real missing coverage for a target on
  a tagged VLAN or dual-stack, not a cosmetic gap.
- No throughput/load testing on any XDP injector, only lightly spaced
  traffic in the live tests. The global atomic counters should hold up
  under real concurrency; that hasn't been verified under load yet.
- None of the three XDP injectors can attach to the same interface
  simultaneously (XDP allows one program per interface per attach mode).
  Running two of them on the same target at once is a real use case and
  needs a shared dispatcher, not built yet.
- `CgroupMemoryPressureInjector` detects and targets both cgroup v1 and v2,
  but only v1 has actually been exercised in CI/dev so far. The v2 path
  follows the documented interface but needs verification on a v2-only
  machine before it's fully trusted.
- `FixProxy` handles one client connection at a time. Fine for testing a
  single OMS/SOR instance against one exchange session, not for concurrent
  FIX sessions through the same proxy.
- FIX coverage is narrow: three message types, flat fields only (no
  repeating groups), and `InterceptAction::Mutate` has no adapter using it
  yet. WebSocket and REST adapters don't exist yet either.
- No test yet exercises a real failure path (arming against a nonexistent
  interface, for example) to confirm errors propagate cleanly, only the
  happy path has live coverage so far.

## Roadmap

- **Phase 5 — control plane.** Scenario config files, a real CLI, run/replay
  subcommands, structured reporting of what fired and when.
- **Phase 6 — validation and release.** Real runs against production-shaped
  OMS/SOR targets, and a CI that's actually demanding: privileged runners
  for the live kernel tests, an arm64 leg, multiple kernel versions in the
  matrix, a determinism gate that fails the build on a `Trace` mismatch,
  clippy and fmt as hard gates.
- **Beyond that:** more FIX message coverage, WebSocket and REST adapters,
  `tc`/`netem`-based latency and reordering faults (a different mechanism
  from XDP, not shoehorned into it).

## License

MIT
