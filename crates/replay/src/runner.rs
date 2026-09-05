use crate::schedule::ValidatedSchedule;
use crate::scheduler::Scheduler;
use crate::trace::Trace;
use blackswan_core::{FaultContext, FaultInjector, HarnessError, StepAction};
use std::collections::HashMap;

// Ties a validated schedule to real fault injectors. DeterministicRng,
// Scheduler and Trace prove the scheduling math is right, but until this,
// nothing actually called arm()/disarm() on something real at the times the
// schedule says it should, that gap is what this closes.
pub struct Runner<'a> {
    schedule: &'a ValidatedSchedule,
    injectors: HashMap<String, Box<dyn FaultInjector>>,
    ctx: FaultContext,
}

impl<'a> Runner<'a> {
    // Registry validation happens here, not in ValidatedSchedule::validate,
    // because that type doesn't know about injectors and shouldn't, schedule
    // shape and "do the referenced faults actually exist" are different
    // concerns that just happen to both gate the same steps.
    pub fn new(
        schedule: &'a ValidatedSchedule,
        injectors: HashMap<String, Box<dyn FaultInjector>>,
        ctx: FaultContext,
    ) -> Result<Self, HarnessError> {
        for step in schedule.steps() {
            if !injectors.contains_key(&step.fault_id) {
                return Err(HarnessError::InvalidScenario(format!(
                    "step references fault_id {} which has no registered injector",
                    step.fault_id
                )));
            }
        }
        Ok(Self {
            schedule,
            injectors,
            ctx,
        })
    }

    // Drives the schedule to completion as fast as possible, calling
    // arm/disarm on real injectors in schedule order, recording everything
    // into a Trace. Never sleeps in real time, tick_ns only controls virtual
    // clock granularity between checks. Correct for replay verification
    // (confirm a scenario reproduces a trace, fast), wrong for actually
    // exercising a live injector against real external traffic, that needs
    // real wall-clock time to elapse so something else has a chance to
    // reach it, see run_realtime for that.
    pub fn run(&mut self, tick_ns: u64) -> Result<Trace, HarnessError> {
        self.run_inner(tick_ns, false)
    }

    // Same as run(), but actually sleeps roughly tick_ns of wall-clock time
    // between virtual clock advances, so a scenario's real duration
    // elapses for real. Found the need for this the hard way: a CLI `run`
    // that called plain run() armed and disarmed a FIX proxy fault in
    // microseconds and exited before any external client could reach it,
    // the schedule's at_ns values are meaningless as a real exercise window
    // if nothing ever waits for them.
    pub fn run_realtime(&mut self, tick_ns: u64) -> Result<Trace, HarnessError> {
        self.run_inner(tick_ns, true)
    }

    fn run_inner(&mut self, tick_ns: u64, realtime: bool) -> Result<Trace, HarnessError> {
        let mut scheduler = Scheduler::new(self.schedule, 0);
        let mut trace = Trace::new(self.schedule.name(), self.schedule.seed());

        while !scheduler.is_finished() {
            if realtime {
                std::thread::sleep(std::time::Duration::from_nanos(tick_ns));
            }

            let due: Vec<_> = scheduler.advance(tick_ns).to_vec();
            let now = scheduler.now_ns();

            for step in due {
                let injector = self
                    .injectors
                    .get_mut(&step.fault_id)
                    .expect("fault_id existence already checked in Runner::new");

                match step.action {
                    StepAction::Arm => injector.arm(&self.ctx)?,
                    StepAction::Disarm => injector.disarm()?,
                }

                trace.record(step, now);
            }
        }

        Ok(trace)
    }

    pub fn is_armed(&self, fault_id: &str) -> Option<bool> {
        self.injectors.get(fault_id).map(|i| i.is_armed())
    }

    // Best-effort disarm of everything still armed. Doesn't stop at the
    // first failure, tries all of them and returns the first error if any,
    // a run that errored out partway through shouldn't leave later faults
    // silently still active because an earlier one failed to disarm.
    pub fn teardown(&mut self) -> Result<(), HarnessError> {
        let mut first_err = None;
        for injector in self.injectors.values_mut() {
            if injector.is_armed() {
                if let Err(e) = injector.disarm() {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        first_err.map_or(Ok(()), Err)
    }
}

impl<'a> Drop for Runner<'a> {
    fn drop(&mut self) {
        // matches the "safe to call twice" contract on FaultInjector::disarm,
        // this is exactly the drop guard that fault.rs anticipated back in
        // phase 1
        let _ = self.teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackswan_core::{Scenario, ScenarioStep, SystemClock};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // Cheap fake so these tests don't need root/CAP_BPF, the real injector
    // gets exercised separately in blackswan-kernel's live tests.
    struct CountingInjector {
        id: String,
        armed: bool,
        arm_calls: Arc<AtomicUsize>,
        disarm_calls: Arc<AtomicUsize>,
    }

    impl FaultInjector for CountingInjector {
        fn id(&self) -> &str {
            &self.id
        }

        fn arm(&mut self, _ctx: &FaultContext) -> Result<(), HarnessError> {
            self.arm_calls.fetch_add(1, Ordering::SeqCst);
            self.armed = true;
            Ok(())
        }

        fn disarm(&mut self) -> Result<(), HarnessError> {
            self.disarm_calls.fetch_add(1, Ordering::SeqCst);
            self.armed = false;
            Ok(())
        }

        fn is_armed(&self) -> bool {
            self.armed
        }
    }

    fn ctx() -> FaultContext {
        FaultContext {
            clock: Arc::new(SystemClock),
            seed: 1,
        }
    }

    #[test]
    fn rejects_schedule_referencing_unknown_fault_id() {
        let scenario = Scenario {
            name: "test".into(),
            seed: 1,
            steps: vec![ScenarioStep {
                at_ns: 0,
                fault_id: "does-not-exist".into(),
                action: StepAction::Arm,
            }],
        };
        let schedule = ValidatedSchedule::validate(scenario).unwrap();
        let injectors: HashMap<String, Box<dyn FaultInjector>> = HashMap::new();

        assert!(Runner::new(&schedule, injectors, ctx()).is_err());
    }

    #[test]
    fn arms_and_disarms_registered_injector_at_the_right_times() {
        let arm_calls = Arc::new(AtomicUsize::new(0));
        let disarm_calls = Arc::new(AtomicUsize::new(0));

        let injector = CountingInjector {
            id: "pkt-loss".into(),
            armed: false,
            arm_calls: arm_calls.clone(),
            disarm_calls: disarm_calls.clone(),
        };

        let scenario = Scenario {
            name: "test".into(),
            seed: 1,
            steps: vec![
                ScenarioStep {
                    at_ns: 1_000,
                    fault_id: "pkt-loss".into(),
                    action: StepAction::Arm,
                },
                ScenarioStep {
                    at_ns: 5_000,
                    fault_id: "pkt-loss".into(),
                    action: StepAction::Disarm,
                },
            ],
        };
        let schedule = ValidatedSchedule::validate(scenario).unwrap();

        let mut injectors: HashMap<String, Box<dyn FaultInjector>> = HashMap::new();
        injectors.insert("pkt-loss".into(), Box::new(injector));

        let mut runner = Runner::new(&schedule, injectors, ctx()).unwrap();
        let trace = runner.run(500).unwrap();

        assert_eq!(arm_calls.load(Ordering::SeqCst), 1);
        assert_eq!(disarm_calls.load(Ordering::SeqCst), 1);
        assert_eq!(trace.events.len(), 2);
    }

    #[test]
    fn run_realtime_actually_takes_real_time_unlike_run() {
        let injector = CountingInjector {
            id: "pkt-loss".into(),
            armed: false,
            arm_calls: Arc::new(AtomicUsize::new(0)),
            disarm_calls: Arc::new(AtomicUsize::new(0)),
        };

        // 20 steps of 5ms each, 100ms of virtual time total, small enough
        // to keep the test fast but large enough that "didn't sleep at
        // all" and "actually slept" are unmistakably different durations
        let steps: Vec<_> = (0..20)
            .map(|i| ScenarioStep {
                at_ns: i * 5_000_000,
                fault_id: "pkt-loss".into(),
                action: if i % 2 == 0 {
                    StepAction::Arm
                } else {
                    StepAction::Disarm
                },
            })
            .collect();
        let scenario = Scenario {
            name: "test".into(),
            seed: 1,
            steps,
        };
        let schedule = ValidatedSchedule::validate(scenario).unwrap();

        let mut injectors: HashMap<String, Box<dyn FaultInjector>> = HashMap::new();
        injectors.insert("pkt-loss".into(), Box::new(injector));

        let mut runner = Runner::new(&schedule, injectors, ctx()).unwrap();
        let started = std::time::Instant::now();
        runner.run_realtime(5_000_000).unwrap();
        let elapsed = started.elapsed();

        assert!(
            elapsed >= std::time::Duration::from_millis(90),
            "run_realtime should take roughly 100ms of real time, took {elapsed:?}"
        );
    }

    #[test]
    fn drop_disarms_anything_left_armed() {
        let arm_calls = Arc::new(AtomicUsize::new(0));
        let disarm_calls = Arc::new(AtomicUsize::new(0));

        let injector = CountingInjector {
            id: "pkt-loss".into(),
            armed: false,
            arm_calls: arm_calls.clone(),
            disarm_calls: disarm_calls.clone(),
        };

        // only an Arm step, no Disarm, on purpose, this is what a run that
        // gets interrupted partway through looks like
        let scenario = Scenario {
            name: "test".into(),
            seed: 1,
            steps: vec![ScenarioStep {
                at_ns: 0,
                fault_id: "pkt-loss".into(),
                action: StepAction::Arm,
            }],
        };
        let schedule = ValidatedSchedule::validate(scenario).unwrap();

        let mut injectors: HashMap<String, Box<dyn FaultInjector>> = HashMap::new();
        injectors.insert("pkt-loss".into(), Box::new(injector));

        {
            let mut runner = Runner::new(&schedule, injectors, ctx()).unwrap();
            runner.run(1_000).unwrap();
            assert_eq!(arm_calls.load(Ordering::SeqCst), 1);
            assert_eq!(disarm_calls.load(Ordering::SeqCst), 0);
        } // runner dropped here

        assert_eq!(
            disarm_calls.load(Ordering::SeqCst),
            1,
            "drop should have disarmed the still-armed injector"
        );
    }
}
