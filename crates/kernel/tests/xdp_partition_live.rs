// Loads and attaches a real XDP partition program to loopback, needs root
// plus CAP_BPF/CAP_NET_ADMIN. Ignored by default. Touches the same shared
// "lo" interface as the other live kernel tests, run with
// `--test-threads=1` if running more than one of these together.
#![cfg(target_os = "linux")]

use blackswan_core::{FaultContext, FaultInjector, SystemClock};
use blackswan_kernel::XdpPartitionInjector;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

#[test]
#[ignore]
fn xdp_partition_blocks_only_the_configured_peer_port() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    let recv_addr = receiver.local_addr().unwrap();

    // two distinct "peers", identified by source port, both on 127.0.0.1
    let blocked_peer = UdpSocket::bind("127.0.0.1:0").expect("bind blocked peer");
    let other_peer = UdpSocket::bind("127.0.0.1:0").expect("bind other peer");
    let blocked_port = blocked_peer.local_addr().unwrap().port();

    let mut injector =
        XdpPartitionInjector::new("xdp-partition-test", "lo", Ipv4Addr::new(127, 0, 0, 1), blocked_port);
    let ctx = FaultContext { clock: Arc::new(SystemClock), seed: 1 };

    injector.arm(&ctx).expect("arm xdp partition injector, needs root + CAP_BPF/CAP_NET_ADMIN");
    assert!(injector.is_armed());

    blocked_peer.send_to(b"from-blocked-peer", recv_addr).expect("send from blocked peer");
    other_peer.send_to(b"from-other-peer", recv_addr).expect("send from other peer");

    let mut buf = [0u8; 64];
    let mut received = Vec::new();
    while let Ok(n) = receiver.recv(&mut buf) {
        received.push(String::from_utf8_lossy(&buf[..n]).to_string());
    }

    injector.disarm().expect("disarm xdp partition injector");
    assert!(!injector.is_armed());

    assert_eq!(received.len(), 1, "exactly one peer's packet should have gotten through, got {received:?}");
    assert_eq!(received[0], "from-other-peer", "the non-blocked peer's packet should be the one that arrived");

    // after disarm, both peers should reach the receiver
    blocked_peer.send_to(b"from-blocked-peer", recv_addr).expect("send from blocked peer");
    other_peer.send_to(b"from-other-peer", recv_addr).expect("send from other peer");

    let mut received_after = 0;
    while receiver.recv(&mut buf).is_ok() {
        received_after += 1;
    }
    assert_eq!(received_after, 2, "disarm should let both peers through again");
}
