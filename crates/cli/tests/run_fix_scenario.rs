// Runs the actual compiled binary as a subprocess against a real fake
// exchange, the same thing verified by hand while building this, now
// automated. No root needed, plain TCP.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

fn cli_binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().expect("current test exe path");
    path.pop(); // deps/
    path.pop(); // debug/
    path.push("blackswan");
    path
}

fn build_new_order_single(cl_ord_id: &str) -> Vec<u8> {
    let body = format!("35=D\x0111={cl_ord_id}\x01");
    let header = format!("8=FIX.4.4\x019={}\x01", body.len());
    let mut full = format!("{header}{body}").into_bytes();
    let sum = full.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    full.extend_from_slice(format!("10={sum:03}\x01").as_bytes());
    full
}

#[test]
fn cli_run_drives_a_real_fix_rate_limit_scenario_end_to_end() {
    let exchange_port = 19101;
    let listen_port = 19100;

    let (count_tx, count_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", exchange_port)).expect("bind fake exchange");
        let (mut stream, _) = listener.accept().expect("accept from cli proxy");
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

        let mut received = 0;
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => received += buf[..n].windows(4).filter(|w| *w == b"35=D").count(),
                Err(_) => break,
            }
        }
        count_tx.send(received).unwrap();
    });

    let config_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/fix-rate-limit-throttle.toml");
    let trace_path = std::env::temp_dir().join("cli-integration-test-trace.json");

    let mut child = Command::new(cli_binary())
        .args(["run", "--config", config_path, "--trace-out"])
        .arg(&trace_path)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn blackswan run");

    std::thread::sleep(Duration::from_millis(500));

    let mut client = TcpStream::connect(("127.0.0.1", listen_port)).expect("connect to cli-managed proxy");
    for i in 0..5 {
        client.write_all(&build_new_order_single(&format!("order-{i}"))).expect("send order");
        std::thread::sleep(Duration::from_millis(300));
    }
    drop(client);

    let status = child.wait().expect("wait for blackswan run to finish");
    assert!(status.success(), "blackswan run exited with {status:?}");

    let received = count_rx.recv_timeout(Duration::from_secs(3)).expect("fake exchange result");
    assert_eq!(received, 3, "threshold=3 in the example config should let exactly 3 of 5 orders through");

    let trace_json = std::fs::read_to_string(&trace_path).expect("read saved trace");
    assert!(trace_json.contains("\"fault_id\": \"throttle\""));
    std::fs::remove_file(&trace_path).ok();
}
