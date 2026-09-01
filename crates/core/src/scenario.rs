use serde::{Deserialize, Serialize};

// A scenario is a named set of faults with timing, loaded from config. Fault
// instances get resolved against the injector registry at run time, this
// struct is just the declarative shape that comes out of the config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub name: String,
    pub seed: u64,
    pub steps: Vec<ScenarioStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioStep {
    pub at_ns: u64,
    pub fault_id: String,
    pub action: StepAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepAction {
    Arm,
    Disarm,
}

// TODO: nothing validates yet that fault_id in a step actually exists in the
// registry, or that steps are sorted by at_ns. Both belong in the runner once
// it exists (phase 5), not here, this type should stay a dumb data shape.
