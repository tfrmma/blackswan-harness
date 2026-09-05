// Real TCP sockets end to end: a fake exchange, a fake client, and a real
// FixFaultInjector proxy in between. No root needed, plain loopback TCP,
// unlike the kernel crate's live tests these aren't #[ignore]d.

use blackswan_adapters::fix::framing::find_complete_message;
use blackswan_adapters::fix::message::compute_checksum;
use blackswan_adapters::fix::{FixAckWithoutExecution, FixFaultInjector, FixRateLimitThrottle, FixSilentReject};
use blackswan_core::{FaultContext, FaultInjector, SystemClock};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

// Fixed but distinct ports per test rather than :0, the proxy's listen
// address has to be known before a client can connect to it, and each test
// needs its own so they don't collide if run concurrently.
static NEXT_LISTEN_PORT: AtomicU16 = AtomicU16::new(18901);
fn next_listen_port() -> u16 {
    NEXT_LISTEN_PORT.fetch_add(1, Ordering::SeqCst)
}

fn build_execution_report(ord_status: &str, exec_type: &str) -> Vec<u8> {
    let body = format!("35=8\x0139={ord_status}\x01150={exec_type}\x01");
    let header = format!("8=FIX.4.4\x019={}\x01", body.len());
    let mut full = format!("{header}{body}").into_bytes();
    let sum = compute_checksum(&full);
    full.extend_from_slice(format!("10={sum:03}\x01").as_bytes());
    full
}

fn build_new_order_single(cl_ord_id: &str) -> Vec<u8> {
    let body = format!("35=D\x0111={cl_ord_id}\x01");
    let header = format!("8=FIX.4.4\x019={}\x01", body.len());
    let mut full = format!("{header}{body}").into_bytes();
    let sum = compute_checksum(&full);
    full.extend_from_slice(format!("10={sum:03}\x01").as_bytes());
    full
}

// Reads whatever complete FIX messages arrive within `wait`, returns their
// raw bytes. Not a fixed count, tests decide how many they expected based
// on the length of the returned vec.
fn read_available_messages(stream: &mut TcpStream, wait: Duration) -> Vec<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let deadline = std::time::Instant::now() + wait;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];

    while std::time::Instant::now() < deadline {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }

    let mut messages = Vec::new();
    while let Ok(Some(len)) = find_complete_message(&buf) {
        messages.push(buf.drain(..len).collect());
    }
    messages
}

// Binds an ephemeral port, sends back the port over `port_tx` once bound,
// accepts one connection, drains whatever the client sends first, then
// writes `to_send` in order and returns.
fn spawn_fake_exchange_that_sends(port_tx: std::sync::mpsc::Sender<u16>, to_send: Vec<Vec<u8>>) {
    std::thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake exchange");
        port_tx.send(listener.local_addr().unwrap().port()).unwrap();

        let (mut stream, _) = listener.accept().expect("accept from proxy");
        let _ = read_available_messages(&mut stream, Duration::from_millis(200));

        for msg in to_send {
            stream.write_all(&msg).expect("write from fake exchange");
        }
    });
}

// Binds an ephemeral port, accepts one connection, records every complete
// message it receives for `record_for`, sends nothing back.
fn spawn_fake_exchange_that_counts(
    port_tx: std::sync::mpsc::Sender<u16>,
    result_tx: std::sync::mpsc::Sender<usize>,
    record_for: Duration,
) {
    std::thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake exchange");
        port_tx.send(listener.local_addr().unwrap().port()).unwrap();

        let (mut stream, _) = listener.accept().expect("accept from proxy");
        let received = read_available_messages(&mut stream, record_for);
        result_tx.send(received.len()).unwrap();
    });
}

#[test]
fn silent_reject_drops_the_rejected_execution_report_but_forwards_the_ack() {
    let (port_tx, port_rx) = std::sync::mpsc::channel();
    spawn_fake_exchange_that_sends(
        port_tx,
        vec![build_execution_report("0", "0"), build_execution_report("8", "8")],
    );
    let exchange_port = port_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("fake exchange bound");

    let listen_port = next_listen_port();
    let mut injector = FixFaultInjector::new(
        "fix-silent-reject-test",
        format!("127.0.0.1:{listen_port}"),
        format!("127.0.0.1:{exchange_port}"),
        Arc::new(FixSilentReject),
    );

    let ctx = FaultContext {
        clock: Arc::new(SystemClock),
        seed: 1,
    };
    injector.arm(&ctx).expect("arm fix silent reject injector");
    std::thread::sleep(Duration::from_millis(50));

    let mut client = TcpStream::connect(("127.0.0.1", listen_port)).expect("connect to proxy");
    client
        .write_all(&build_new_order_single("order-1"))
        .expect("send order");

    let received = read_available_messages(&mut client, Duration::from_millis(500));
    injector.disarm().expect("disarm");

    assert_eq!(
        received.len(),
        1,
        "expected only the ack through, got {} messages",
        received.len()
    );
    let parsed = blackswan_adapters::fix::parse(&received[0]).unwrap();
    assert!(
        parsed.is(39, b"0"),
        "the message that arrived should be the New/ack, not the reject"
    );
}

#[test]
fn ack_without_execution_drops_the_fill_but_forwards_the_ack() {
    let (port_tx, port_rx) = std::sync::mpsc::channel();
    spawn_fake_exchange_that_sends(
        port_tx,
        vec![build_execution_report("0", "0"), build_execution_report("2", "F")],
    );
    let exchange_port = port_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("fake exchange bound");

    let listen_port = next_listen_port();
    let mut injector = FixFaultInjector::new(
        "fix-ack-without-execution-test",
        format!("127.0.0.1:{listen_port}"),
        format!("127.0.0.1:{exchange_port}"),
        Arc::new(FixAckWithoutExecution),
    );

    let ctx = FaultContext {
        clock: Arc::new(SystemClock),
        seed: 1,
    };
    injector.arm(&ctx).expect("arm fix ack-without-execution injector");
    std::thread::sleep(Duration::from_millis(50));

    let mut client = TcpStream::connect(("127.0.0.1", listen_port)).expect("connect to proxy");
    client
        .write_all(&build_new_order_single("order-2"))
        .expect("send order");

    let received = read_available_messages(&mut client, Duration::from_millis(500));
    injector.disarm().expect("disarm");

    assert_eq!(
        received.len(),
        1,
        "expected only the ack through, got {} messages",
        received.len()
    );
    let parsed = blackswan_adapters::fix::parse(&received[0]).unwrap();
    assert!(
        parsed.is(150, b"0"),
        "the message that arrived should be the New/ack, not the fill"
    );
}

#[test]
fn rate_limit_throttle_drops_outbound_messages_past_threshold() {
    let (port_tx, port_rx) = std::sync::mpsc::channel();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    spawn_fake_exchange_that_counts(port_tx, result_tx, Duration::from_millis(600));
    let exchange_port = port_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("fake exchange bound");

    let listen_port = next_listen_port();
    let mut injector = FixFaultInjector::new(
        "fix-rate-limit-throttle-test",
        format!("127.0.0.1:{listen_port}"),
        format!("127.0.0.1:{exchange_port}"),
        Arc::new(FixRateLimitThrottle::new(2)),
    );

    let ctx = FaultContext {
        clock: Arc::new(SystemClock),
        seed: 1,
    };
    injector.arm(&ctx).expect("arm fix rate limit throttle injector");
    std::thread::sleep(Duration::from_millis(50));

    let mut client = TcpStream::connect(("127.0.0.1", listen_port)).expect("connect to proxy");
    for i in 0..5 {
        client
            .write_all(&build_new_order_single(&format!("order-{i}")))
            .expect("send order");
        std::thread::sleep(Duration::from_millis(20));
    }

    let received_by_exchange = result_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("fake exchange result");
    injector.disarm().expect("disarm");

    assert_eq!(
        received_by_exchange, 2,
        "expected only 2 of 5 orders to reach the exchange, threshold was 2"
    );
}
