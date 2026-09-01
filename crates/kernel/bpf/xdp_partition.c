// XDP network partition (split-brain) injector. Unconditionally drops every
// inbound packet whose source IP (and, if configured, source port) matches
// one configured peer, simulating "this host can no longer hear from that
// peer" rather than a probabilistic loss rate. Pure match/no-match, no
// modulus or counter needed, the config itself is the only thing that
// varies a run.
//
// Verified against a real loopback capture that `lo` frames carry a real
// 14 byte Ethernet header (zeroed MAC addresses, EtherType 0x0800) followed
// by a normal IPv4 header, this isn't assumed.
//
// Separate program from xdp_pktloss/xdp_corrupt, same one-program-per-
// interface limitation, see the TODO in lib.rs.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

struct bpf_map_def SEC("maps") partition_enabled = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

// network byte order, same as ip->saddr
struct bpf_map_def SEC("maps") partition_src_ip = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

// host byte order, 0 means match any source port once the IP matches
struct bpf_map_def SEC("maps") partition_src_port = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

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
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // ip->ihl is a 4 bit field, header length in 32 bit words, don't assume
    // it's always the minimum 5 just because that's what loopback happens
    // to send with no options
    if (ip->ihl < 5)
        return XDP_PASS;
    void *l4 = (void *)ip + (ip->ihl * 4);
    if (l4 > data_end)
        return XDP_PASS;

    __u32 *want_ip = bpf_map_lookup_elem(&partition_src_ip, &key);
    if (!want_ip || ip->saddr != *want_ip)
        return XDP_PASS;

    __u32 *want_port = bpf_map_lookup_elem(&partition_src_port, &key);
    if (!want_port)
        return XDP_PASS;

    if (*want_port == 0)
        return XDP_DROP; // IP matched, any port, that's enough

    __u16 src_port;
    if (ip->protocol == 17) { // IPPROTO_UDP, IANA protocol number, fixed
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(udp->source);
    } else if (ip->protocol == 6) { // IPPROTO_TCP, IANA protocol number, fixed
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(tcp->source);
    } else {
        // a port was configured but this protocol has no port field to
        // check, don't drop something we can't actually confirm matches
        return XDP_PASS;
    }

    if (src_port == (__u16)*want_port)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
