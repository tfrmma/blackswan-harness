mod build;
mod config;

use blackswan_core::{FaultContext, FaultInjector, Scenario, SystemClock};
use blackswan_replay::{Runner, Trace, ValidatedSchedule};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "blackswan", version, about = "Deterministic chaos engineering for OMS/SOR")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a scenario against real fault injectors
    Run {
        /// Path to the scenario config (TOML)
        #[arg(short, long)]
        config: PathBuf,
        /// Virtual clock tick size in nanoseconds
        #[arg(long, default_value_t = 1_000_000)]
        tick_ns: u64,
        /// Where to save the recorded trace
        #[arg(long)]
        trace_out: Option<PathBuf>,
    },
    /// Re-run a scenario and confirm it reproduces a previously recorded trace
    Replay {
        /// Path to the scenario config (TOML)
        #[arg(short, long)]
        config: PathBuf,
        /// Virtual clock tick size in nanoseconds
        #[arg(long, default_value_t = 1_000_000)]
        tick_ns: u64,
        /// Previously recorded trace to compare this run against
        #[arg(long)]
        against: PathBuf,
    },
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("{msg}");
    std::process::exit(1);
}

fn load_config(path: &PathBuf) -> config::Config {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| die(format!("reading {}: {e}", path.display())));
    toml::from_str(&text).unwrap_or_else(|e| die(format!("parsing {}: {e}", path.display())))
}

fn build_scenario_and_injectors(cfg: config::Config) -> (Scenario, HashMap<String, Box<dyn FaultInjector>>) {
    let scenario = Scenario { name: cfg.name, seed: cfg.seed, steps: cfg.schedule };
    let injectors = cfg
        .injectors
        .into_iter()
        .map(|(id, ic)| {
            let injector = build::build_injector(&id, ic);
            (id, injector)
        })
        .collect();
    (scenario, injectors)
}

fn print_trace_summary(trace: &Trace) {
    println!("scenario: {} (seed {})", trace.scenario_name, trace.seed);
    for event in &trace.events {
        println!("  {:>14} ns  {:<20} {:?}", event.step.at_ns, event.step.fault_id, event.step.action);
    }
}

fn execute_scenario(config_path: &PathBuf, tick_ns: u64, realtime: bool) -> Trace {
    let cfg = load_config(config_path);
    let (scenario, injectors) = build_scenario_and_injectors(cfg);
    let seed = scenario.seed;

    let schedule = ValidatedSchedule::validate(scenario).unwrap_or_else(|e| die(format!("invalid scenario: {e:?}")));

    let ctx = FaultContext { clock: Arc::new(SystemClock), seed };
    let mut runner =
        Runner::new(&schedule, injectors, ctx).unwrap_or_else(|e| die(format!("setting up runner: {e:?}")));

    let result = if realtime { runner.run_realtime(tick_ns) } else { runner.run(tick_ns) };
    result.unwrap_or_else(|e| die(format!("run failed: {e:?}")))
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Run { config, tick_ns, trace_out } => {
            let trace = execute_scenario(&config, tick_ns, true);
            print_trace_summary(&trace);

            if let Some(out) = trace_out {
                trace.save(&out).unwrap_or_else(|e| die(format!("saving trace: {e:?}")));
                println!("trace saved to {}", out.display());
            }
        }
        Command::Replay { config, tick_ns, against } => {
            let baseline =
                Trace::load(&against).unwrap_or_else(|e| die(format!("loading baseline {}: {e:?}", against.display())));

            let trace = execute_scenario(&config, tick_ns, false);
            print_trace_summary(&trace);

            if trace.matches_schedule(&baseline) {
                println!("MATCH: this run reproduces {}", against.display());
            } else {
                die(format!("MISMATCH: this run does not reproduce {}", against.display()));
            }
        }
    }
}
