// Spawns real child processes and puts them under real cgroup memory
// pressure, needs root (cgroup.procs writes and, on v1, creating child
// cgroups both require it in most configurations). Ignored by default.
//
// Uses python3 as the memory-allocating test target since it's simple and
// almost always present on a dev/CI box, this is a test-only dependency,
// not something the crate itself needs.
//
// Only verified against this sandbox's actual delegated hierarchy, the
// legacy v1 memory cgroup, not v2 unified, that path isn't reachable here,
// see the README's Known limitations.
#![cfg(target_os = "linux")]

use blackswan_core::{FaultContext, FaultInjector, SystemClock};
use blackswan_kernel::{CgroupMemoryPressureInjector, PressureMode};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::sync::Arc;

const ALLOC_SCRIPT: &str = "\
import time
time.sleep(0.5)
data = bytearray(64 * 1024 * 1024)
for i in range(0, len(data), 4096):
    data[i] = 1
print('survived', flush=True)
";

fn spawn_allocator() -> std::process::Child {
    Command::new("python3")
        .arg("-c")
        .arg(ALLOC_SCRIPT)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn python3, needed for this test")
}

#[test]
#[ignore]
fn tight_limit_oom_kills_the_target_process() {
    let mut child = spawn_allocator();

    let mut injector = CgroupMemoryPressureInjector::new(
        "cgroup-mem-oom-test",
        child.id(),
        8 * 1024 * 1024, // 8MB, well under the 64MB the script tries to touch
        PressureMode::Hard,
    );
    let ctx = FaultContext {
        clock: Arc::new(SystemClock),
        seed: 1,
    };

    injector
        .arm(&ctx)
        .expect("arm cgroup memory pressure injector, needs root");
    assert!(injector.is_armed());

    let status = child.wait().expect("wait on child");
    injector.disarm().expect("disarm cgroup memory pressure injector");

    // SIGKILL is signal 9, the kernel's oom killer sends exactly that
    assert_eq!(
        status.signal(),
        Some(9),
        "expected the allocator to be OOM-killed under an 8MB limit, got status {status:?}"
    );
}

#[test]
#[ignore]
fn disarm_before_allocation_lets_the_process_survive() {
    let mut child = spawn_allocator();

    let mut injector = CgroupMemoryPressureInjector::new(
        "cgroup-mem-disarm-test",
        child.id(),
        8 * 1024 * 1024,
        PressureMode::Hard,
    );
    let ctx = FaultContext {
        clock: Arc::new(SystemClock),
        seed: 1,
    };

    injector
        .arm(&ctx)
        .expect("arm cgroup memory pressure injector, needs root");
    // disarm well before the script's 500ms sleep elapses and it actually
    // tries to allocate, this is the case that actually exercises whether
    // disarm's limit-file write takes effect in time
    injector.disarm().expect("disarm cgroup memory pressure injector");
    assert!(!injector.is_armed());

    let status = child.wait().expect("wait on child");
    assert!(
        status.success(),
        "expected the allocator to survive after disarm, got status {status:?}"
    );
}
