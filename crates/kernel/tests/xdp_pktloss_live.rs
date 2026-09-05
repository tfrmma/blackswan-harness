// Loads and attaches a real XDP program to the loopback interface, needs
// root plus CAP_BPF/CAP_NET_ADMIN. Not something a plain `cargo test` in
// someone's normal dev environment or CI should do unprompted, so this is
// ignored by default. Run explicitly with `cargo test -- --ignored`.
#![cfg(target_os = "linux")]

use blackswan_core::{FaultContext, FaultInjector, SystemClock};
use blackswan_kernel::XdpPacketLossInjector;
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::Duration;

#[test]
#[ignore]
fn xdp_packet_loss_drops_exactly_the_configured_fraction() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    let recv_addr = receiver.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

    let mut injector = XdpPacketLossInjector::new("xdp-pktloss-test", "lo", 3);
    let ctx = FaultContext {
        clock: Arc::new(SystemClock),
        seed: 1,
    };

    injector
        .arm(&ctx)
        .expect("arm xdp injector, needs root + CAP_BPF/CAP_NET_ADMIN");
    assert!(injector.is_armed());

    let sent = 9u8;
    for i in 0..sent {
        sender.send_to(&[i], recv_addr).expect("send udp packet");
        // small gap so packets don't get coalesced by the loopback driver
        std::thread::sleep(Duration::from_millis(5));
    }

    let mut received = 0;
    let mut buf = [0u8; 8];
    while receiver.recv(&mut buf).is_ok() {
        received += 1;
    }

    injector.disarm().expect("disarm xdp injector");
    assert!(!injector.is_armed());

    // drop_every_n = 3 over 9 packets drops exactly 3 (every 3rd), the
    // kernel program has zero randomness so this isn't a "roughly" check.
    assert_eq!(
        received, 6,
        "expected exactly 3 of 9 packets dropped, got {received} received"
    );

    // after disarm the fault must actually be off, not just flagged off
    for i in 0..sent {
        sender.send_to(&[i], recv_addr).expect("send udp packet");
    }
    let mut received_after_disarm = 0usize;
    while receiver.recv(&mut buf).is_ok() {
        received_after_disarm += 1;
    }
    assert_eq!(received_after_disarm, sent as usize, "disarm should stop all drops");
}
