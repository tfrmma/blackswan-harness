// Determinism engine: seeded RNG, schedule validation, a virtual-clock
// scheduler, and trace recording/replay. Kernel (phase 3) and adapter
// (phase 4) injectors will both depend on DeterministicRng and Scheduler,
// this crate has no idea those layers exist.

pub mod rng;
pub mod runner;
pub mod schedule;
pub mod scheduler;
pub mod trace;

pub use rng::DeterministicRng;
pub use runner::Runner;
pub use schedule::ValidatedSchedule;
pub use scheduler::Scheduler;
pub use trace::{Trace, TraceEvent};
