use blackswan_core::{HarnessError, Scenario, ScenarioStep, StepAction};
use std::collections::HashSet;

// Validated wrapper around a Scenario. The only way to get one is through
// validate(), which is where structurally broken schedules get caught before
// anything tries to run them: steps out of order, or a disarm for a fault
// that was never armed.
pub struct ValidatedSchedule {
    scenario: Scenario,
}

impl ValidatedSchedule {
    pub fn validate(scenario: Scenario) -> Result<Self, HarnessError> {
        let mut armed: HashSet<&str> = HashSet::new();
        let mut last_ns = 0u64;

        for step in &scenario.steps {
            if step.at_ns < last_ns {
                return Err(HarnessError::InvalidScenario(format!(
                    "step for {} at {}ns is out of order, previous step was at {}ns",
                    step.fault_id, step.at_ns, last_ns
                )));
            }
            last_ns = step.at_ns;

            match step.action {
                StepAction::Arm => {
                    if !armed.insert(step.fault_id.as_str()) {
                        return Err(HarnessError::InvalidScenario(format!(
                            "fault {} armed twice without an intervening disarm",
                            step.fault_id
                        )));
                    }
                }
                StepAction::Disarm => {
                    if !armed.remove(step.fault_id.as_str()) {
                        return Err(HarnessError::InvalidScenario(format!(
                            "fault {} disarmed but was never armed",
                            step.fault_id
                        )));
                    }
                }
            }
        }

        Ok(Self { scenario })
    }

    pub fn steps(&self) -> &[ScenarioStep] {
        &self.scenario.steps
    }

    pub fn name(&self) -> &str {
        &self.scenario.name
    }

    pub fn seed(&self) -> u64 {
        self.scenario.seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario_with(steps: Vec<ScenarioStep>) -> Scenario {
        Scenario { name: "test".into(), seed: 1, steps }
    }

    #[test]
    fn accepts_well_formed_schedule() {
        let s = scenario_with(vec![
            ScenarioStep { at_ns: 0, fault_id: "pkt-loss".into(), action: StepAction::Arm },
            ScenarioStep { at_ns: 1000, fault_id: "pkt-loss".into(), action: StepAction::Disarm },
        ]);
        assert!(ValidatedSchedule::validate(s).is_ok());
    }

    #[test]
    fn rejects_out_of_order_steps() {
        let s = scenario_with(vec![
            ScenarioStep { at_ns: 1000, fault_id: "pkt-loss".into(), action: StepAction::Arm },
            ScenarioStep { at_ns: 500, fault_id: "pkt-loss".into(), action: StepAction::Disarm },
        ]);
        assert!(ValidatedSchedule::validate(s).is_err());
    }

    #[test]
    fn rejects_double_arm() {
        let s = scenario_with(vec![
            ScenarioStep { at_ns: 0, fault_id: "pkt-loss".into(), action: StepAction::Arm },
            ScenarioStep { at_ns: 100, fault_id: "pkt-loss".into(), action: StepAction::Arm },
        ]);
        assert!(ValidatedSchedule::validate(s).is_err());
    }

    #[test]
    fn rejects_disarm_without_arm() {
        let s = scenario_with(vec![ScenarioStep {
            at_ns: 0,
            fault_id: "pkt-loss".into(),
            action: StepAction::Disarm,
        }]);
        assert!(ValidatedSchedule::validate(s).is_err());
    }
}
