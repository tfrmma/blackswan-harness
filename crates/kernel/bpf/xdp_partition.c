// XDP network partition (split-brain) injector. Unconditionally drops every
// inbound packet whose source IP (and, if configured, source port) matches
// one configured peer, simulating "this host can no longer hear from that
// peer" rather than a probabilistic loss rate. Pure match/no-match, no
// modulus or counter needed, the config itself is the only thing that
// varies a run.
//
// Verified against a real loopback capture that `lo` frames carry a real
// 14 byte Ethernet header (zeroed MAC addresses, EtherType 0x0800) followed
// by a normal IPv4 header, this isn't assumed. Peels up to two 802.1Q/
// 802.1ad tags before checking for IPv4 or IPv6, verified with hand-crafted
// raw frames injected over `lo` (see xdp_partition_live.rs), loopback
// itself never tags anything. IPv6 handles exactly one Fragment extension
// header, same fail-safe pass as the v4 path for anything in the
// extension chain it doesn't walk.
//
// Separate program from xdp_pktloss/xdp_corrupt, same one-program-per-
// interface limitation, see the TODO in lib.rs.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct blackswan_bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

// linux/if_vlan.h (the UAPI one) only has the ioctl plumbing, checked, no
// vlan_hdr. This is the kernel's real, non-UAPI layout: 2 byte TCI
// (priority + VID), 2 byte ethertype of whatever's actually underneath.
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

// RFC 8200 section 4.5, also not in any UAPI header (same situation as
// vlan_hdr above): next header, 1 byte reserved, then a 16 bit field
// packing a 13 bit fragment offset + 2 reserved bits + the M flag, then a
// 32 bit identification.
struct ipv6_frag_hdr {
    __u8 nexthdr;
    __u8 reserved;
    __be16 frag_off_and_flags;
    __be32 identification;
};

struct blackswan_bpf_map_def SEC("maps") partition_enabled = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

// network byte order, same as ip->saddr
struct blackswan_bpf_map_def SEC("maps") partition_src_ip = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

// network byte order 16 bytes, same as ip6->saddr.s6_addr. Unset (all
// zero, ::) same as an unset partition_src_ip defaulting to 0.0.0.0,
// never a real peer address in practice, same risk profile as the v4 map
struct blackswan_bpf_map_def SEC("maps") partition_src_ip6 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = 16,
    .max_entries = 1,
};

// host byte order, 0 means match any source port once the IP matches
struct blackswan_bpf_map_def SEC("maps") partition_src_port = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

// shared by the v4 and v6 paths, second real duplication of this exact
// four line block is what earned it a function, same call blackswan_util's
// set_u32_map got on the Rust side
static __always_inline int extract_src_port(void *l4, void *data_end, __u8 proto, __u16 *out_port)
{
    if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return -1;
        *out_port = bpf_ntohs(udp->source);
        return 0;
    }
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return -1;
        *out_port = bpf_ntohs(tcp->source);
        return 0;
    }
    return -1; // port configured but this protocol has no port field to check
}

SEC("xdp")
int xdp_partition(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u32 *enabled = bpf_map_lookup_elem(&partition_enabled, &key);
    if (!enabled || *enabled == 0)
        return XDP_PASS;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    void *l3 = (void *)(eth + 1);

    // up to one 802.1Q/802.1ad tag, then one more for QinQ double tagging.
    // Unrolled by hand instead of a loop with #pragma unroll: this repo
    // already targets the older non-CO-RE map style, not worth betting on
    // bounded loop support or the unroll pragma actually firing on
    // whatever clang the build uses.
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vlan = l3;
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;
        h_proto = vlan->h_vlan_encapsulated_proto;
        l3 = (void *)(vlan + 1);

        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr *vlan2 = l3;
            if ((void *)(vlan2 + 1) > data_end)
                return XDP_PASS;
            h_proto = vlan2->h_vlan_encapsulated_proto;
            l3 = (void *)(vlan2 + 1);
        }
    }

    __u32 *want_port;
    __u16 src_port;

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = l3;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        // ip->ihl is a 4 bit field, header length in 32 bit words, don't
        // assume it's always the minimum 5 just because that's what
        // loopback happens to send with no options
        if (ip->ihl < 5)
            return XDP_PASS;
        void *l4 = (void *)ip + (ip->ihl * 4);
        if (l4 > data_end)
            return XDP_PASS;

        __u32 *want_ip = bpf_map_lookup_elem(&partition_src_ip, &key);
        if (!want_ip || ip->saddr != *want_ip)
            return XDP_PASS;

        want_port = bpf_map_lookup_elem(&partition_src_port, &key);
        if (!want_port)
            return XDP_PASS;
        if (*want_port == 0)
            return XDP_DROP; // IP matched, any port, that's enough

        // frag_off packs a 13 bit fragment offset into its low bits,
        // network byte order, verified against the real struct iphdr
        // (linux/ip.h): a nonzero offset means this is a non-initial
        // fragment, there's no L4 header at this offset at all, just raw
        // payload from further into the original datagram. Reading it as
        // a udphdr/tcphdr would be matching a configured port against
        // bytes that were never a port. IP-only matching above is
        // unaffected, every fragment carries the same source IP.
        if (bpf_ntohs(ip->frag_off) & 0x1FFF)
            return XDP_PASS;

        if (extract_src_port(l4, data_end, ip->protocol, &src_port) < 0)
            return XDP_PASS;
    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = l3;
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        unsigned char *want_ip6 = bpf_map_lookup_elem(&partition_src_ip6, &key);
        if (!want_ip6 || __builtin_memcmp(ip6->saddr.s6_addr, want_ip6, 16) != 0)
            return XDP_PASS;

        want_port = bpf_map_lookup_elem(&partition_src_port, &key);
        if (!want_port)
            return XDP_PASS;
        if (*want_port == 0)
            return XDP_DROP; // IP matched, any port, that's enough

        __u8 nexthdr = ip6->nexthdr;
        void *l4 = (void *)(ip6 + 1);

        // exactly one Fragment extension header (RFC 8200 section 4.5),
        // the v6 equivalent of the v4 fragmentation check above. Anything
        // else in the extension header chain (Hop-by-Hop, Routing,
        // Destination Options, ESP/AH...) isn't walked, safely passed
        // instead, see README Known limitations.
        if (nexthdr == IPPROTO_FRAGMENT) {
            struct ipv6_frag_hdr *frag = l4;
            if ((void *)(frag + 1) > data_end)
                return XDP_PASS;
            if (bpf_ntohs(frag->frag_off_and_flags) >> 3)
                return XDP_PASS; // non-initial fragment, no L4 header here
            nexthdr = frag->nexthdr;
            l4 = (void *)(frag + 1);
        }

        if (extract_src_port(l4, data_end, nexthdr, &src_port) < 0)
            return XDP_PASS;
    } else {
        return XDP_PASS;
    }

    if (src_port == (__u16)*want_port)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
