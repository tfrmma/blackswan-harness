// End to end check that two runs of the same scenario with the same seed
// produce the same fault sequence, and that a recorded trace can be saved,
// reloaded, and still match. This is the actual thing the README promises
// ("a scenario that finds a bug should reproduce that bug bit-exact"), so
// it gets an integration test instead of just unit coverage on the pieces.

use blackswan_core::{Scenario, ScenarioStep, StepAction};
use blackswan_replay::{DeterministicRng, Scheduler, Trace, ValidatedSchedule};

fn sample_scenario() -> Scenario {
    Scenario {
        name: "pkt-loss-then-clock-skew".into(),
        seed: 777,
        steps: vec![
            ScenarioStep { at_ns: 0, fault_id: "pkt-loss".into(), action: StepAction::Arm },
            ScenarioStep { at_ns: 2_000, fault_id: "clock-skew".into(), action: StepAction::Arm },
            ScenarioStep { at_ns: 5_000, fault_id: "pkt-loss".into(), action: StepAction::Disarm },
            ScenarioStep { at_ns: 8_000, fault_id: "clock-skew".into(), action: StepAction::Disarm },
        ],
    }
}

fn run_once(scenario: Scenario) -> Trace {
    let seed = scenario.seed;
    let schedule = ValidatedSchedule::validate(scenario).expect("well formed scenario");
    let mut scheduler = Scheduler::new(&schedule, 0);
    let mut rng = DeterministicRng::from_seed(seed);
    let mut trace = Trace::new(schedule.name(), schedule.seed());

    // Advance in uneven, arbitrary chunks, on purpose. Determinism has to
    // hold regardless of how the caller happens to drive the clock, wall
    // time during a real run is never going to line up on neat 1000ns
    // boundaries either.
    let step_sizes = [300u64, 900, 1_400, 2_000, 3_000, 5_000];
    let mut i = 0;
    while !scheduler.is_finished() {
        let delta = step_sizes[i % step_sizes.len()];
        i += 1;
        let due: Vec<_> = scheduler.advance(delta).to_vec();
        let now = scheduler.now_ns();
        for step in due {
            // rng draw here is a stand-in for whatever a real injector will
            // eventually do with jitter/probability at fire time, the point
            // of this test is that the draw sequence itself is reproducible
            let _jitter = rng.gen_range_u64(0, 1_000);
            trace.record(step, now);
        }
    }

    trace
}

#[test]
fn same_seed_same_scenario_produces_identical_trace() {
    let trace_a = run_once(sample_scenario());
    let trace_b = run_once(sample_scenario());
    assert!(trace_a.matches_schedule(&trace_b));
    assert_eq!(trace_a.events.len(), 4);
}

#[test]
fn recorded_trace_survives_a_round_trip_to_disk() {
    let trace = run_once(sample_scenario());
    let path = std::env::temp_dir().join("blackswan-determinism-integration-test.json");

    trace.save(&path).expect("save trace");
    let replayed = Trace::load(&path).expect("load trace");
    std::fs::remove_file(&path).ok();

    assert!(trace.matches_schedule(&replayed));
}
