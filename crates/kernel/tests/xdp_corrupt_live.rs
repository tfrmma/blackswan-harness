// Loads and attaches a real XDP corruption program to loopback, needs root
// plus CAP_BPF/CAP_NET_ADMIN. Ignored by default, run explicitly with
// `cargo test -- --ignored`.
//
// Offset 60 with a 64-byte payload is chosen so the corrupted byte lands
// inside our payload regardless of whether XDP sees a real Ethernet header
// on `lo` or not (Ethernet+IPv4+UDP headers = 42 bytes, IPv4+UDP alone =
// 28 bytes, and 60 falls inside the payload window under both), rather than
// assuming a specific frame layout on the loopback interface that isn't
// actually documented anywhere I could find.
//
// Touches the same shared "lo" interface as the other live kernel tests, run
// with `--test-threads=1` if running more than one of these in a single
// invocation.
#![cfg(target_os = "linux")]

use blackswan_core::{FaultContext, FaultInjector, SystemClock};
use blackswan_kernel::XdpCorruptionInjector;
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::Duration;

const PAYLOAD_LEN: usize = 64;
const FILL_BYTE: u8 = 0xAA;
const MASK: u8 = 0xFF;

fn count_differing_bytes(buf: &[u8]) -> usize {
    buf.iter().filter(|&&b| b != FILL_BYTE).count()
}

#[test]
#[ignore]
fn xdp_corruption_flips_exactly_one_byte_on_the_configured_fraction() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    let recv_addr = receiver.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

    let mut injector = XdpCorruptionInjector::new("xdp-corrupt-test", "lo", 3, 60, MASK);
    let ctx = FaultContext { clock: Arc::new(SystemClock), seed: 1 };

    injector.arm(&ctx).expect("arm xdp corruption injector, needs root + CAP_BPF/CAP_NET_ADMIN");
    assert!(injector.is_armed());

    let payload = [FILL_BYTE; PAYLOAD_LEN];
    let sent = 9;
    let mut diffs_per_packet = Vec::new();

    for _ in 0..sent {
        sender.send_to(&payload, recv_addr).expect("send udp packet");
        std::thread::sleep(Duration::from_millis(5));

        let mut buf = [0u8; PAYLOAD_LEN];
        match receiver.recv(&mut buf) {
            Ok(n) => diffs_per_packet.push(count_differing_bytes(&buf[..n])),
            Err(_) => diffs_per_packet.push(usize::MAX), // sentinel: packet never arrived
        }
    }

    injector.disarm().expect("disarm xdp corruption injector");
    assert!(!injector.is_armed());

    // every 3rd packet (index 2, 5, 8 zero-based) should show exactly one
    // flipped byte, the rest should be untouched, none should be dropped
    for (i, diffs) in diffs_per_packet.iter().enumerate() {
        let expect_corrupted = (i + 1) % 3 == 0;
        assert_ne!(*diffs, usize::MAX, "packet {i} never arrived, corruption shouldn't drop packets");
        if expect_corrupted {
            assert_eq!(*diffs, 1, "packet {i} (every 3rd) should have exactly one flipped byte, got {diffs}");
        } else {
            assert_eq!(*diffs, 0, "packet {i} shouldn't be touched, got {diffs} differing bytes");
        }
    }

    // after disarm, nothing should be touched anymore
    for _ in 0..sent {
        sender.send_to(&payload, recv_addr).expect("send udp packet");
    }
    let mut buf = [0u8; PAYLOAD_LEN];
    let mut received_after = 0;
    while let Ok(n) = receiver.recv(&mut buf) {
        assert_eq!(count_differing_bytes(&buf[..n]), 0, "disarm should stop all corruption");
        received_after += 1;
    }
    assert_eq!(received_after, sent, "disarm should not drop packets either");
}
