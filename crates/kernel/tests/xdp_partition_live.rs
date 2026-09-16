// Loads and attaches a real XDP partition program to loopback, needs root
// plus CAP_BPF/CAP_NET_ADMIN. Ignored by default. Touches the same shared
// "lo" interface as the other live kernel tests, run with
// `--test-threads=1` if running more than one of these together.
#![cfg(target_os = "linux")]

use blackswan_core::{FaultContext, FaultInjector, SystemClock};
use blackswan_kernel::XdpPartitionInjector;
use std::ffi::CString;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::unix::io::RawFd;
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

    let mut injector = XdpPartitionInjector::new("xdp-partition-test", "lo", Ipv4Addr::new(127, 0, 0, 1), blocked_port);
    let ctx = FaultContext {
        clock: Arc::new(SystemClock),
        seed: 1,
    };

    injector
        .arm(&ctx)
        .expect("arm xdp partition injector, needs root + CAP_BPF/CAP_NET_ADMIN");
    assert!(injector.is_armed());

    blocked_peer
        .send_to(b"from-blocked-peer", recv_addr)
        .expect("send from blocked peer");
    other_peer
        .send_to(b"from-other-peer", recv_addr)
        .expect("send from other peer");

    let mut buf = [0u8; 64];
    let mut received = Vec::new();
    while let Ok(n) = receiver.recv(&mut buf) {
        received.push(String::from_utf8_lossy(&buf[..n]).to_string());
    }

    injector.disarm().expect("disarm xdp partition injector");
    assert!(!injector.is_armed());

    assert_eq!(
        received.len(),
        1,
        "exactly one peer's packet should have gotten through, got {received:?}"
    );
    assert_eq!(
        received[0], "from-other-peer",
        "the non-blocked peer's packet should be the one that arrived"
    );

    // after disarm, both peers should reach the receiver
    blocked_peer
        .send_to(b"from-blocked-peer", recv_addr)
        .expect("send from blocked peer");
    other_peer
        .send_to(b"from-other-peer", recv_addr)
        .expect("send from other peer");

    let mut received_after = 0;
    while receiver.recv(&mut buf).is_ok() {
        received_after += 1;
    }
    assert_eq!(received_after, 2, "disarm should let both peers through again");
}

// Confirms the fragmentation fix in xdp_partition.c: shrinks lo's MTU so a
// UDP datagram actually fragments at a real kernel boundary (RFC 791
// section 3.2 requires every non-final fragment's IP payload to be a
// multiple of 8 bytes), then sends a payload deliberately built so a
// non-initial fragment's first two bytes collide, bit for bit, with the
// blocked port, the exact scenario the fix guards against. The 976-byte
// first-fragment size for MTU 1000 was confirmed against a real tcpdump
// capture on this setup, not assumed from the RFC alone. Needs root, same
// as the other live kernel tests, and mutates lo's MTU for the run,
// restored via MtuGuard even on panic.
#[test]
#[ignore]
fn xdp_partition_never_drops_a_non_initial_fragment_on_byte_collision() {
    const MTU: usize = 1000;
    const IP_HDR: usize = 20;
    const UDP_HDR: usize = 8;
    let frag1_ip_payload = (MTU - IP_HDR) / 8 * 8; // 976, verified via tcpdump at this MTU
    let collision_offset = frag1_ip_payload - UDP_HDR; // where fragment 2's payload starts, 968

    struct MtuGuard(String);
    impl Drop for MtuGuard {
        fn drop(&mut self) {
            let _ = std::fs::write("/sys/class/net/lo/mtu", &self.0);
        }
    }
    let original_mtu = std::fs::read_to_string("/sys/class/net/lo/mtu").expect("read lo mtu");
    let _mtu_guard = MtuGuard(original_mtu);
    std::fs::write("/sys/class/net/lo/mtu", MTU.to_string()).expect("shrink lo mtu, needs root");

    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let recv_addr = receiver.local_addr().unwrap();

    let blocked_peer = UdpSocket::bind("127.0.0.1:0").expect("bind blocked peer");
    let other_peer = UdpSocket::bind("127.0.0.1:0").expect("bind other peer");
    let blocked_port = blocked_peer.local_addr().unwrap().port();

    // other_peer's payload: filler everywhere except
    // [collision_offset..collision_offset + 2], set to the blocked port's
    // big endian bytes, exactly what udphdr.source would hold. Long enough
    // that the collision point lands inside the second fragment, not the
    // first (which is fine to match on, it's the real header).
    let mut other_payload = vec![0xABu8; collision_offset + 400];
    other_payload[collision_offset..collision_offset + 2].copy_from_slice(&blocked_port.to_be_bytes());
    let blocked_payload = vec![0xCDu8; collision_offset + 400];

    let mut injector =
        XdpPartitionInjector::new("xdp-partition-frag-test", "lo", Ipv4Addr::new(127, 0, 0, 1), blocked_port);
    let ctx = FaultContext { clock: Arc::new(SystemClock), seed: 1 };
    injector.arm(&ctx).expect("arm xdp partition injector, needs root + CAP_BPF/CAP_NET_ADMIN");
    assert!(injector.is_armed());

    blocked_peer.send_to(&blocked_payload, recv_addr).expect("send fragmented payload, blocked peer");
    other_peer.send_to(&other_payload, recv_addr).expect("send fragmented payload, other peer, colliding fragment");

    let mut buf = vec![0u8; 8192];
    let mut received = Vec::new();
    while let Ok(n) = receiver.recv(&mut buf) {
        received.push(buf[..n].to_vec());
    }

    injector.disarm().expect("disarm xdp partition injector");

    assert_eq!(received.len(), 1, "only the non-blocked peer's fragmented datagram should reassemble and arrive");
    assert_eq!(
        received[0], other_payload,
        "delivered datagram must be byte exact, a dropped non-initial fragment corrupts reassembly"
    );
}

// This sandbox can't create a real 8021q VLAN subinterface to test end to
// end socket delivery (`ip link add ... type vlan` fails with "Unknown
// device type", confirmed, no modprobe/loadable modules here at all), so
// these use a raw AF_PACKET socket as the observer instead of a UdpSocket.
// XDP_DROP happens before netif_receive_skb, a raw packet socket bound to
// lo never sees a dropped frame arrive that way, whereas XDP_PASS lets it
// continue into netif_receive_skb, where any raw socket tap on the
// interface (this is exactly what tcpdump uses) sees it regardless of
// whether anything further up the stack knows what to do with an untagged
// base device receiving a tagged frame. The tricky part, found the hard
// way: ptype_all taps also fire on the *outgoing* side of send(), before
// XDP ever runs, independent of its verdict, so a naive capture sees its
// own just-sent frame either way and proves nothing. sll_pkttype tells
// the two apart (PACKET_OUTGOING vs everything else, see raw_recv_contains
// below), verified against /usr/include/linux/if_packet.h.

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 { u16::from_be_bytes([chunk[0], chunk[1]]) } else { u16::from_be_bytes([chunk[0], 0]) };
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_vlan_udp_frame(vlan_ids: &[u16], src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; 12]; // zeroed dst + src mac, matches real lo frames
    for &vid in vlan_ids {
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&vid.to_be_bytes());
    }
    frame.extend_from_slice(&0x0800u16.to_be_bytes());

    let udp_len = 8 + payload.len();
    let ip_total_len = 20 + udp_len;
    let mut ip_hdr = vec![0x45, 0x00];
    ip_hdr.extend_from_slice(&(ip_total_len as u16).to_be_bytes());
    ip_hdr.extend_from_slice(&0u16.to_be_bytes()); // identification
    ip_hdr.extend_from_slice(&0x4000u16.to_be_bytes()); // DF set, no fragmentation here
    ip_hdr.push(64); // ttl
    ip_hdr.push(17); // udp
    ip_hdr.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    ip_hdr.extend_from_slice(&Ipv4Addr::new(127, 0, 0, 1).octets());
    ip_hdr.extend_from_slice(&Ipv4Addr::new(127, 0, 0, 1).octets());
    let cksum = ip_checksum(&ip_hdr);
    ip_hdr[10..12].copy_from_slice(&cksum.to_be_bytes());

    frame.extend_from_slice(&ip_hdr);
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes()); // udp checksum, 0 is a valid "none" over IPv4
    frame.extend_from_slice(payload);
    frame
}

fn if_index(name: &str) -> u32 {
    let cname = CString::new(name).unwrap();
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    assert_ne!(idx, 0, "if_nametoindex({name}) failed");
    idx
}

const ETH_P_ALL: u16 = 0x0003;

fn open_raw_socket(ifindex: u32, rcv_timeout: Option<Duration>) -> RawFd {
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_ALL.to_be() as i32) };
    assert!(fd >= 0, "socket(AF_PACKET, SOCK_RAW) failed, needs root/CAP_NET_RAW");

    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = ETH_P_ALL.to_be();
    addr.sll_ifindex = ifindex as i32;
    let ret = unsafe {
        libc::bind(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32)
    };
    assert_eq!(ret, 0, "bind AF_PACKET socket to interface failed");

    if let Some(timeout) = rcv_timeout {
        let tv = libc::timeval { tv_sec: timeout.as_secs() as libc::time_t, tv_usec: timeout.subsec_micros() as i64 };
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };
        assert_eq!(ret, 0, "setsockopt SO_RCVTIMEO failed");
    }
    fd
}

fn raw_send(fd: RawFd, frame: &[u8]) {
    let n = unsafe { libc::send(fd, frame.as_ptr() as *const libc::c_void, frame.len(), 0) };
    assert_eq!(n as usize, frame.len(), "raw send didn't write the whole frame");
}

const PACKET_OUTGOING: u8 = 4; // verified against /usr/include/linux/if_packet.h

// drains the capture socket until SO_RCVTIMEO fires, true if any genuinely
// *received* frame (sll_pkttype != PACKET_OUTGOING, this filters out the
// ptype_all TX side tap, which fires on send() regardless of what XDP
// later decides on the RX side, confirmed the hard way, first version of
// this test saw its own outgoing frames and never actually exercised XDP)
// contained `needle` as a contiguous byte sequence
fn raw_recv_contains(fd: RawFd, needle: &[u8]) -> bool {
    let mut buf = vec![0u8; 2048];
    loop {
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut addrlen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut addr as *mut _ as *mut libc::sockaddr,
                &mut addrlen,
            )
        };
        if n < 0 {
            return false; // SO_RCVTIMEO fired, nothing more waiting
        }
        if addr.sll_pkttype == PACKET_OUTGOING {
            continue;
        }
        if n > 0 && buf[..n as usize].windows(needle.len()).any(|w| w == needle) {
            return true;
        }
    }
}

fn vlan_tag_peeling_matches_or_passes(vlan_ids: &[u16]) {
    let ifindex = if_index("lo");
    let capture = open_raw_socket(ifindex, Some(Duration::from_millis(300)));
    let sender = open_raw_socket(ifindex, None);

    let blocked_port: u16 = 41000;
    let other_port: u16 = 41001;
    let blocked_marker = b"BLOCKED-VLAN-FRAG-MARKER-9f3a";
    let other_marker = b"ALLOWED-VLAN-FRAG-MARKER-9f3a";

    let mut injector =
        XdpPartitionInjector::new("xdp-partition-vlan-test", "lo", Ipv4Addr::new(127, 0, 0, 1), blocked_port);
    let ctx = FaultContext { clock: Arc::new(SystemClock), seed: 1 };
    injector.arm(&ctx).expect("arm xdp partition injector, needs root + CAP_BPF/CAP_NET_ADMIN");
    assert!(injector.is_armed());

    let blocked_frame = build_vlan_udp_frame(vlan_ids, blocked_port, 9999, blocked_marker);
    let other_frame = build_vlan_udp_frame(vlan_ids, other_port, 9999, other_marker);
    raw_send(sender, &blocked_frame);
    raw_send(sender, &other_frame);

    assert!(
        !raw_recv_contains(capture, blocked_marker),
        "blocked peer's tagged frame reached netif_receive_skb, XDP should have dropped it after peeling {} tag(s)",
        vlan_ids.len()
    );
    let capture2 = open_raw_socket(ifindex, Some(Duration::from_millis(300)));
    raw_send(sender, &other_frame);
    assert!(
        raw_recv_contains(capture2, other_marker),
        "other peer's tagged frame never reached netif_receive_skb, XDP wrongly dropped it after peeling {} tag(s)",
        vlan_ids.len()
    );

    injector.disarm().expect("disarm xdp partition injector");
    let capture3 = open_raw_socket(ifindex, Some(Duration::from_millis(300)));
    raw_send(sender, &blocked_frame);
    assert!(raw_recv_contains(capture3, blocked_marker), "disarm should let the previously blocked peer through again");

    unsafe {
        libc::close(capture);
        libc::close(capture2);
        libc::close(capture3);
        libc::close(sender);
    }
}

#[test]
#[ignore]
fn xdp_partition_peels_a_single_8021q_tag() {
    vlan_tag_peeling_matches_or_passes(&[42]);
}

#[test]
#[ignore]
fn xdp_partition_raw_capture_harness_sees_a_plain_drop() {
    // same raw AF_PACKET harness as the VLAN tests above, no tag at all,
    // confirms the harness itself (and the PACKET_OUTGOING filtering) is
    // sound independent of anything VLAN specific
    vlan_tag_peeling_matches_or_passes(&[]);
}

#[test]
#[ignore]
fn xdp_partition_peels_a_qinq_double_tag() {
    vlan_tag_peeling_matches_or_passes(&[100, 42]);
}
