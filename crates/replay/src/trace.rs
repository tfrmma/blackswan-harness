use blackswan_core::{HarnessError, ScenarioStep};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

// A step as it actually fired, not just as scheduled. wall_ns is real time
// (SystemClock), separate from step.at_ns which is virtual schedule time,
// they'll drift apart under real load and that drift is exactly what's
// useful to inspect after a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub step: ScenarioStep,
    pub wall_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    pub scenario_name: String,
    pub seed: u64,
    pub events: Vec<TraceEvent>,
}

impl Trace {
    pub fn new(scenario_name: impl Into<String>, seed: u64) -> Self {
        Self { scenario_name: scenario_name.into(), seed, events: Vec::new() }
    }

    pub fn record(&mut self, step: ScenarioStep, wall_ns: u64) {
        self.events.push(TraceEvent { step, wall_ns });
    }

    pub fn save(&self, path: &Path) -> Result<(), HarnessError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| HarnessError::InvalidScenario(e.to_string()))?;
        let mut f = std::fs::File::create(path)?;
        f.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, HarnessError> {
        let bytes = std::fs::read(path)?;
        serde_json::from_slice(&bytes).map_err(|e| HarnessError::InvalidScenario(e.to_string()))
    }

    // Bit-exact comparison of the fault sequence. Deliberately ignores
    // wall_ns, that's expected to differ between runs, only the schedule of
    // what fired and in what order has to match for a replay to count as
    // faithful.
    pub fn matches_schedule(&self, other: &Trace) -> bool {
        self.seed == other.seed
            && self.events.iter().map(|e| &e.step).eq(other.events.iter().map(|e| &e.step))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackswan_core::StepAction;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path(name: &str) -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("blackswan-trace-test-{}-{}.json", name, n))
    }

    #[test]
    fn round_trips_through_disk() {
        let path = temp_path("roundtrip");
        let mut trace = Trace::new("smoke-test", 42);
        trace.record(
            ScenarioStep { at_ns: 0, fault_id: "pkt-loss".into(), action: StepAction::Arm },
            1_000,
        );

        trace.save(&path).unwrap();
        let loaded = Trace::load(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(trace.scenario_name, loaded.scenario_name);
        assert!(trace.matches_schedule(&loaded));
    }

    #[test]
    fn matches_schedule_ignores_wall_time_but_not_seed() {
        let mut a = Trace::new("s", 1);
        a.record(
            ScenarioStep { at_ns: 0, fault_id: "x".into(), action: StepAction::Arm },
            100,
        );

        let mut b = Trace::new("s", 1);
        b.record(
            ScenarioStep { at_ns: 0, fault_id: "x".into(), action: StepAction::Arm },
            999_999, // different wall time, same schedule
        );
        assert!(a.matches_schedule(&b));

        let mut c = Trace::new("s", 2); // different seed
        c.record(
            ScenarioStep { at_ns: 0, fault_id: "x".into(), action: StepAction::Arm },
            100,
        );
        assert!(!a.matches_schedule(&c));
    }
}
