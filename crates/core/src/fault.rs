use crate::clock::Clock;
use crate::error::HarnessError;
use std::sync::Arc;

// Context handed to a fault injector when it's armed. Carries the deterministic
// clock and the seed for this run. Speculated back in phase 1 that this would
// probably grow a TargetHandle once kernel and adapter injectors needed
// something to attach to. Five real injectors later (three XDP, cgroup memory
// pressure, time namespace clock skew) that never happened, every one of them
// takes its target (interface name, pid, argv) as a constructor argument
// instead. Not adding TargetHandle, the evidence says it isn't needed.
pub struct FaultContext {
    pub clock: Arc<dyn Clock>,
    pub seed: u64,
}

// A single fault primitive: packet loss, clock skew, memory pressure, a mangled
// exchange ACK, whatever. Layer 1 (kernel) and layer 2 (protocol adapter)
// injectors both implement this, the scenario runner doesn't care which.
pub trait FaultInjector: Send + Sync {
    fn id(&self) -> &str;

    // Activate the fault. Must be idempotent, calling arm() on an already-armed
    // injector should be a no-op, not an error.
    fn arm(&mut self, ctx: &FaultContext) -> Result<(), HarnessError>;

    // Revert to steady state. Called on scenario teardown and also from the
    // runner's drop guard on panic unwind, so this has to be safe to call twice.
    //
    // For most injectors "steady state" means neutralizing the effect while
    // leaving the target alone (an XDP hook stays attached, a cgroup limit
    // just goes back to unlimited). A small number of faults can't work that
    // way: Linux time namespaces, for instance, can only be configured for a
    // process at its own exec(), never retroactively, so a clock skew
    // injector has no target to "leave alone", it has to launch and
    // supervise its own process and disarm() has to mean terminating it.
    // That's still "revert to steady state" (the state before arm() was that
    // this specific process didn't exist), just not the same steady state
    // every other injector means by the phrase. See kernel::TimeSkewInjector.
    fn disarm(&mut self) -> Result<(), HarnessError>;

    fn is_armed(&self) -> bool;
}

// TODO: injectors probably need a blast-radius hint so the scenario runner can
// refuse to stack two faults that step on each other, e.g. two things touching
// the same cgroup memory limit. Not blocking the skeleton, revisit once there
// are at least two real kernel injectors to compare.
