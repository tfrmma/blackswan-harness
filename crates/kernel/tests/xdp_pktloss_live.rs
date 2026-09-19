// Loads and attaches a real XDP program to the loopback interface, needs
// root plus CAP_BPF/CAP_NET_ADMIN. Not something a plain `cargo test` in
// someone's normal dev environment or CI should do unprompted, so this is
// ignored by default. Run explicitly with `cargo test -- --ignored`.
#![cfg(target_os = "linux")]

use blackswan_core::{FaultContext, FaultInjector, SystemClock};
use blackswan_kernel::XdpPacketLossInjector;
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;
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

// SO_RCVBUFFORCE (root only, bypasses net.core.rmem_max) so a burst of
// thousands of packets can't get lost to an ordinary socket buffer limit
// and get mistaken for an XDP drop, this is ruling out an unrelated cause,
// not testing anything about XDP itself.
fn set_rcvbuf_force(sock: &UdpSocket, bytes: i32) {
    let fd = sock.as_raw_fd();
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            &bytes as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as u32,
        )
    };
    assert_eq!(ret, 0, "setsockopt SO_RCVBUFFORCE failed, needs root/CAP_NET_ADMIN");
}

// The other test above spaces packets 5ms apart, deliberately gentle. This
// one is the opposite on purpose: no spacing at all, fired from 8 threads
// at once, to actually exercise xdp_pktloss.c's __sync_fetch_and_add under
// real bursty concurrency rather than assuming an atomic op "should" hold
// up and never checking. TOTAL divides DROP_EVERY_N evenly so there's no
// remainder to reason about, arrival order doesn't matter either, the
// counter's exactness only depends on every increment landing exactly
// once, which is exactly what this is checking for.
#[test]
#[ignore]
fn xdp_packet_loss_drops_exactly_the_configured_fraction_under_concurrent_bursty_load() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 875;
    const TOTAL: usize = THREADS * PER_THREAD; // 7000
    const DROP_EVERY_N: u32 = 7; // 7000 / 7 = 1000 exact drops

    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    set_rcvbuf_force(&receiver, 8 * 1024 * 1024);
    receiver.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let recv_addr = receiver.local_addr().unwrap();

    let mut injector = XdpPacketLossInjector::new("xdp-pktloss-load-test", "lo", DROP_EVERY_N);
    let ctx = FaultContext {
        clock: Arc::new(SystemClock),
        seed: 1,
    };
    injector
        .arm(&ctx)
        .expect("arm xdp injector, needs root + CAP_BPF/CAP_NET_ADMIN");
    assert!(injector.is_armed());

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            std::thread::spawn(move || {
                let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
                for i in 0..PER_THREAD {
                    sender
                        .send_to(&(i as u32).to_le_bytes(), recv_addr)
                        .expect("send udp packet");
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("sender thread panicked");
    }

    let mut received = 0usize;
    let mut buf = [0u8; 16];
    while receiver.recv(&mut buf).is_ok() {
        received += 1;
    }

    injector.disarm().expect("disarm xdp injector");

    let expected_drops = TOTAL / DROP_EVERY_N as usize;
    assert_eq!(
        received,
        TOTAL - expected_drops,
        "expected exactly {expected_drops} of {TOTAL} packets dropped under concurrent load, got {received} received"
    );
}
