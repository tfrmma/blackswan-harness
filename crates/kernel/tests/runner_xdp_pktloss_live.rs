// Full pipeline: Scenario -> ValidatedSchedule -> Runner -> Scheduler ->
// real XDP fault, instead of calling arm()/disarm() by hand like
// xdp_pktloss_live.rs does. That test proves the injector itself works,
// this one proves the Runner wiring against it. Needs root plus
// CAP_BPF/CAP_NET_ADMIN, ignored by default, run explicitly with
// `cargo test -- --ignored`.
#![cfg(target_os = "linux")]

use blackswan_core::{FaultContext, FaultInjector, Scenario, ScenarioStep, StepAction, SystemClock};
use blackswan_kernel::XdpPacketLossInjector;
use blackswan_replay::{Runner, ValidatedSchedule};
use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::Duration;

#[test]
#[ignore]
fn scenario_arms_real_xdp_fault_through_the_runner_and_teardown_disarms_it() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    let recv_addr = receiver.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

    // only an Arm step on purpose, teardown on Runner drop is what disarms
    // it, that's the thing this test actually wants to exercise
    let scenario = Scenario {
        name: "runner-xdp-pktloss".into(),
        seed: 42,
        steps: vec![ScenarioStep { at_ns: 0, fault_id: "xdp-pktloss".into(), action: StepAction::Arm }],
    };
    let schedule = ValidatedSchedule::validate(scenario).expect("well formed scenario");

    let mut injectors: HashMap<String, Box<dyn FaultInjector>> = HashMap::new();
    injectors.insert("xdp-pktloss".into(), Box::new(XdpPacketLossInjector::new("xdp-pktloss", "lo", 3)));

    let ctx = FaultContext { clock: Arc::new(SystemClock), seed: 42 };

    {
        let mut runner = Runner::new(&schedule, injectors, ctx).expect("runner setup");
        let trace = runner
            .run(1_000)
            .expect("run scenario, needs root + CAP_BPF/CAP_NET_ADMIN");

        assert_eq!(trace.events.len(), 1);
        assert_eq!(runner.is_armed("xdp-pktloss"), Some(true));

        let sent = 9u8;
        for i in 0..sent {
            sender.send_to(&[i], recv_addr).expect("send udp packet");
            std::thread::sleep(Duration::from_millis(5));
        }

        let mut received = 0;
        let mut buf = [0u8; 8];
        while receiver.recv(&mut buf).is_ok() {
            received += 1;
        }
        assert_eq!(received, 6, "runner-armed fault should drop exactly 3 of 9 packets");
    } // runner dropped here, its teardown guard disarms xdp-pktloss

    let sent = 9u8;
    for i in 0..sent {
        sender.send_to(&[i], recv_addr).expect("send udp packet");
    }
    let mut received_after = 0usize;
    let mut buf = [0u8; 8];
    while receiver.recv(&mut buf).is_ok() {
        received_after += 1;
    }
    assert_eq!(
        received_after, sent as usize,
        "runner teardown on drop should have disarmed the fault"
    );
}
