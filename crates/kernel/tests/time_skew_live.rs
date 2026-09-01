// Launches real skewed child processes via Linux time namespaces, needs
// root in this sandbox (unshare(CLONE_NEWTIME) requires it here, not
// independently re-verified against an unprivileged configuration).
// Ignored by default.
#![cfg(target_os = "linux")]

use blackswan_core::{FaultContext, FaultInjector, SystemClock};
use blackswan_kernel::TimeSkewInjector;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

const READ_CLOCKS_SCRIPT: &str = "\
import time
print(time.clock_gettime(time.CLOCK_MONOTONIC))
print(time.clock_gettime(time.CLOCK_BOOTTIME))
";

fn read_own_clocks() -> (f64, f64) {
    let mut mono_ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let mut boot_ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono_ts);
        libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut boot_ts);
    }
    (
        mono_ts.tv_sec as f64 + mono_ts.tv_nsec as f64 / 1e9,
        boot_ts.tv_sec as f64 + boot_ts.tv_nsec as f64 / 1e9,
    )
}

#[test]
#[ignore]
fn armed_child_actually_observes_the_configured_offset() {
    let (baseline_mono, baseline_boot) = read_own_clocks();

    let mut injector = TimeSkewInjector::new(
        "time-skew-test",
        vec!["python3".into(), "-c".into(), READ_CLOCKS_SCRIPT.into()],
        1_000,
        1_000,
    )
    .with_captured_stdout();
    let ctx = FaultContext { clock: Arc::new(SystemClock), seed: 1 };

    injector.arm(&ctx).expect("arm time skew injector, needs root");
    assert!(injector.is_armed());

    let pid = injector.pid().expect("child should have a pid once armed");
    assert!(std::path::Path::new(&format!("/proc/{pid}")).exists(), "child process should be alive");

    let mut stdout = injector.take_stdout().expect("stdout should be captured");
    let mut output = String::new();
    stdout.read_to_string(&mut output).expect("read child stdout");

    let mut lines = output.lines();
    let child_mono: f64 = lines.next().expect("first line: monotonic").parse().expect("parse monotonic");
    let child_boot: f64 = lines.next().expect("second line: boottime").parse().expect("parse boottime");

    injector.disarm().expect("disarm time skew injector");
    assert!(!injector.is_armed());
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "child process should be gone after disarm"
    );

    // generous tolerance, this test process itself has to fork/exec python3
    // and that takes real wall time too, the point is confirming the ~1000s
    // offset landed, not measuring exact scheduling latency
    let tolerance = 10.0;
    assert!(
        (child_mono - (baseline_mono + 1_000.0)).abs() < tolerance,
        "expected child monotonic clock near baseline+1000s, baseline={baseline_mono}, child={child_mono}"
    );
    assert!(
        (child_boot - (baseline_boot + 1_000.0)).abs() < tolerance,
        "expected child boottime clock near baseline+1000s, baseline={baseline_boot}, child={child_boot}"
    );
}

#[test]
#[ignore]
fn disarm_terminates_a_still_running_child() {
    let mut injector = TimeSkewInjector::new("time-skew-kill-test", vec!["sleep".into(), "100".into()], 0, 0);
    let ctx = FaultContext { clock: Arc::new(SystemClock), seed: 1 };

    injector.arm(&ctx).expect("arm time skew injector, needs root");
    let pid = injector.pid().expect("child should have a pid once armed");

    std::thread::sleep(Duration::from_millis(100));
    assert!(std::path::Path::new(&format!("/proc/{pid}")).exists(), "sleep 100 should still be running");

    injector.disarm().expect("disarm should kill the still-running sleep");
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "sleep 100 should be gone after disarm killed it"
    );

    // safe to call twice, matches the trait contract
    injector.disarm().expect("second disarm should be a no-op, not an error");
}

#[test]
#[ignore]
fn arm_is_idempotent() {
    let mut injector = TimeSkewInjector::new("time-skew-idempotent-test", vec!["sleep".into(), "100".into()], 0, 0);
    let ctx = FaultContext { clock: Arc::new(SystemClock), seed: 1 };

    injector.arm(&ctx).expect("first arm");
    let pid_first = injector.pid();

    injector.arm(&ctx).expect("second arm should be a no-op, not spawn another child");
    let pid_second = injector.pid();

    assert_eq!(pid_first, pid_second, "arming twice shouldn't spawn a second process");

    injector.disarm().expect("cleanup");
}
