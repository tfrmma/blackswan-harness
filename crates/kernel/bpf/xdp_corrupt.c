// XDP byte-level corruption injector. Same principle as xdp_pktloss.c: zero
// randomness in the kernel, every decision about which packet gets touched
// and how comes from userspace. Every Nth packet gets one byte XORed at a
// fixed offset with a fixed mask, both set from userspace at load time, so a
// run is exactly as reproducible as everything else here.
//
// Separate program from xdp_pktloss, XDP only supports one program attached
// per interface per attach mode, this doesn't stack with
// XdpPacketLossInjector on the same interface yet, see the TODO in lib.rs.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

// 0 disables corruption entirely, N corrupts every Nth packet.
struct bpf_map_def SEC("maps") corrupt_every_n = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

// Byte offset from the start of the frame to flip. Masked to 0xFFF below
// before use, both so it stays inside any packet XDP will realistically see
// and because the verifier needs a provably bounded value here, it can't
// reason about an arbitrary u32 loaded from a map.
struct bpf_map_def SEC("maps") corrupt_offset = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

// XOR mask applied to the byte at corrupt_offset, only the low 8 bits used.
struct bpf_map_def SEC("maps") corrupt_mask = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

// Own counter, deliberately not shared with xdp_pktloss.c's, these are
// separate programs with independent moduli and shouldn't interfere with
// each other's determinism if both ever end up loaded side by side.
struct bpf_map_def SEC("maps") packet_count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

SEC("xdp")
int xdp_corrupt(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u32 *n = bpf_map_lookup_elem(&corrupt_every_n, &key);
    if (!n || *n == 0)
        return XDP_PASS;

    __u64 *count = bpf_map_lookup_elem(&packet_count, &key);
    if (!count)
        return XDP_PASS;

    __u64 c = __sync_fetch_and_add(count, 1) + 1;
    if (c % *n != 0)
        return XDP_PASS;

    __u32 *offset = bpf_map_lookup_elem(&corrupt_offset, &key);
    __u32 *mask = bpf_map_lookup_elem(&corrupt_mask, &key);
    if (!offset || !mask)
        return XDP_PASS;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 off = *offset & 0xFFF; // bound the range so the verifier can prove it
    __u8 *byte = (__u8 *)data + off;

    // verifier needs this exact shape, a computed pointer plus an explicit
    // comparison against data_end right before the access
    if ((void *)(byte + 1) > data_end)
        return XDP_PASS;

    *byte ^= (__u8)(*mask);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
