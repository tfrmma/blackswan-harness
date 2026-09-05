use crate::schedule::ValidatedSchedule;
use blackswan_core::{Clock, ScenarioStep, VirtualClock};

// Walks a validated schedule against a virtual clock, yielding steps as they
// come due. Doesn't call into any injector, callers own what arm/disarm
// actually does, this only answers "what fires now". Kernel and adapter
// injectors don't exist yet (phases 3/4), so there's nothing to wire this
// into beyond the tests for now.
pub struct Scheduler<'a> {
    schedule: &'a ValidatedSchedule,
    clock: VirtualClock,
    cursor: usize,
}

impl<'a> Scheduler<'a> {
    pub fn new(schedule: &'a ValidatedSchedule, start_ns: u64) -> Self {
        Self {
            schedule,
            clock: VirtualClock::new(start_ns),
            cursor: 0,
        }
    }

    pub fn now_ns(&self) -> u64 {
        self.clock.now_ns()
    }

    // Advances virtual time by delta_ns and returns every step that's now
    // due (at_ns <= new time) and hasn't fired yet, in schedule order.
    // ValidatedSchedule already guarantees the steps are time-sorted so no
    // sorting happens here.
    pub fn advance(&mut self, delta_ns: u64) -> &[ScenarioStep] {
        self.clock.advance(delta_ns);
        let now = self.clock.now_ns();
        let start = self.cursor;

        while self.cursor < self.schedule.steps().len() && self.schedule.steps()[self.cursor].at_ns <= now {
            self.cursor += 1;
        }

        &self.schedule.steps()[start..self.cursor]
    }

    pub fn is_finished(&self) -> bool {
        self.cursor >= self.schedule.steps().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackswan_core::{Scenario, StepAction};

    fn two_step_schedule() -> ValidatedSchedule {
        let scenario = Scenario {
            name: "test".into(),
            seed: 1,
            steps: vec![
                ScenarioStep {
                    at_ns: 1_000,
                    fault_id: "a".into(),
                    action: StepAction::Arm,
                },
                ScenarioStep {
                    at_ns: 5_000,
                    fault_id: "a".into(),
                    action: StepAction::Disarm,
                },
            ],
        };
        ValidatedSchedule::validate(scenario).unwrap()
    }

    #[test]
    fn nothing_fires_before_its_time() {
        let schedule = two_step_schedule();
        let mut sched = Scheduler::new(&schedule, 0);
        assert!(sched.advance(500).is_empty());
        assert_eq!(sched.now_ns(), 500);
    }

    #[test]
    fn step_fires_once_time_reaches_it() {
        let schedule = two_step_schedule();
        let mut sched = Scheduler::new(&schedule, 0);
        sched.advance(500);
        let due = sched.advance(600); // now at 1100ns, first step was at 1000ns
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].fault_id, "a");
    }

    #[test]
    fn coalesces_multiple_due_steps_in_one_advance() {
        let schedule = two_step_schedule();
        let mut sched = Scheduler::new(&schedule, 0);
        let due = sched.advance(10_000); // jumps past both steps at once
        assert_eq!(due.len(), 2);
        assert!(sched.is_finished());
    }
}
