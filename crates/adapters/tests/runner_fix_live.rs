// Full pipeline: Scenario -> ValidatedSchedule -> Runner -> Scheduler ->
// real FixFaultInjector, same integration shape as
// blackswan-kernel's runner_xdp_pktloss_live.rs but proving layer 2 plugs
// into the same orchestration layer 1 does, not just that FixFaultInjector
// works in isolation. No root needed, plain TCP.

use blackswan_adapters::fix::message::compute_checksum;
use blackswan_adapters::fix::{parse, FixFaultInjector, FixSilentReject};
use blackswan_core::{FaultInjector, Scenario, ScenarioStep, StepAction, SystemClock};
use blackswan_replay::{Runner, ValidatedSchedule};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

fn build_execution_report(ord_status: &str, exec_type: &str) -> Vec<u8> {
    let body = format!("35=8\x0139={ord_status}\x01150={exec_type}\x01");
    let header = format!("8=FIX.4.4\x019={}\x01", body.len());
    let mut full = format!("{header}{body}").into_bytes();
    let sum = compute_checksum(&full);
    full.extend_from_slice(format!("10={sum:03}\x01").as_bytes());
    full
}

fn build_new_order_single() -> Vec<u8> {
    let body = "35=D\x0111=order-1\x01";
    let header = format!("8=FIX.4.4\x019={}\x01", body.len());
    let mut full = format!("{header}{body}").into_bytes();
    let sum = compute_checksum(&full);
    full.extend_from_slice(format!("10={sum:03}\x01").as_bytes());
    full
}

#[test]
fn scenario_arms_a_real_fix_fault_through_the_runner() {
    let (port_tx, port_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake exchange");
        port_tx.send(listener.local_addr().unwrap().port()).unwrap();
        let (mut stream, _) = listener.accept().expect("accept from proxy");

        let mut buf = [0u8; 512];
        stream.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let _ = stream.read(&mut buf); // drain the client's order

        stream.write_all(&build_execution_report("0", "0")).unwrap();
        stream.write_all(&build_execution_report("8", "8")).unwrap();
    });
    let exchange_port = port_rx.recv_timeout(Duration::from_secs(2)).expect("fake exchange bound");

    // only an Arm step, mirrors runner_xdp_pktloss_live's structure: the
    // Runner's drop-guard teardown on scope exit is what disarms this
    let scenario = Scenario {
        name: "runner-fix-silent-reject".into(),
        seed: 7,
        steps: vec![ScenarioStep { at_ns: 0, fault_id: "fix-silent-reject".into(), action: StepAction::Arm }],
    };
    let schedule = ValidatedSchedule::validate(scenario).expect("well formed scenario");

    let listen_port = 18999;
    let injector = FixFaultInjector::new(
        "fix-silent-reject",
        format!("127.0.0.1:{listen_port}"),
        format!("127.0.0.1:{exchange_port}"),
        Arc::new(FixSilentReject),
    );
    let mut injectors: HashMap<String, Box<dyn FaultInjector>> = HashMap::new();
    injectors.insert("fix-silent-reject".into(), Box::new(injector));

    let ctx = blackswan_core::FaultContext { clock: Arc::new(SystemClock), seed: 7 };

    {
        let mut runner = Runner::new(&schedule, injectors, ctx).expect("runner setup");
        let trace = runner.run(1_000).expect("run scenario");
        assert_eq!(trace.events.len(), 1);
        assert_eq!(runner.is_armed("fix-silent-reject"), Some(true));

        std::thread::sleep(Duration::from_millis(50));
        let mut client = TcpStream::connect(("127.0.0.1", listen_port)).expect("connect to proxy");
        client.write_all(&build_new_order_single()).expect("send order");

        client.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        while std::time::Instant::now() < deadline {
            match client.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => {}
            }
        }

        let msg = parse(&buf).expect("received bytes should be a valid FIX message");
        assert!(msg.is(39, b"0"), "expected only the ack through the runner-armed proxy");
    } // runner dropped here, teardown guard disarms fix-silent-reject
}
