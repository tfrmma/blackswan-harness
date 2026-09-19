// Confirms HarnessError::ArmFailed actually propagates cleanly on a real
// failure, not just gets asserted about in theory, only the happy path had
// live coverage until now. Picked XdpPacketLossInjector as the
// representative example: every XDP-based injector in this crate calls the
// exact same program.attach(&iface, ...) internally and would fail the
// exact same way, one example is enough evidence for a shared code path.
//
// Still needs root/CAP_BPF like the other live tests here: program.load()
// (the BPF verifier step) runs before program.attach() ever sees the bogus
// interface name, so reaching the failure this test checks for needs the
// same privilege as arming for real would.
#![cfg(target_os = "linux")]

use blackswan_core::{FaultContext, FaultInjector, HarnessError, SystemClock};
use blackswan_kernel::XdpPacketLossInjector;
use std::sync::Arc;

#[test]
#[ignore]
fn arm_against_a_nonexistent_interface_fails_cleanly() {
    let mut injector = XdpPacketLossInjector::new("arm-failed-test", "definitely-not-a-real-iface-xyz", 2);
    let ctx = FaultContext {
        clock: Arc::new(SystemClock),
        seed: 1,
    };

    let Err(err) = injector.arm(&ctx) else {
        panic!("arming against a nonexistent interface should fail, got Ok");
    };

    match err {
        HarnessError::ArmFailed(id, reason) => {
            assert_eq!(id, "arm-failed-test");
            assert!(!reason.is_empty(), "the failure reason shouldn't be empty");
        }
        other => panic!("expected ArmFailed, got a different variant: {other:?}"),
    }

    assert!(!injector.is_armed(), "a failed arm must not leave is_armed() true");

    // disarm on a never-successfully-armed injector should still be safe,
    // same "never armed" no-op contract the other injectors already have
    injector
        .disarm()
        .expect("disarm after a failed arm should still be a safe no-op");
}
