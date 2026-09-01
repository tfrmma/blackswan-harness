// XDP packet loss injector. Deliberately has zero randomness in the kernel,
// bpf_get_prandom_u32() would break the bit-exact replay guarantee the whole
// determinism engine (blackswan-replay) exists to provide. Instead this just
// counts packets and drops whenever the counter falls in a window userspace
// controls, userspace is the only thing that ever decides "drop or not" and
// it does so using the same DeterministicRng seed as everything else.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// libbpf 1.x dropped struct bpf_map_def from its own headers (BTF-only maps
// as of v1.0), so it's declared here directly, same layout it's always had.
// Using the legacy form on purpose: it needs zero BTF, which sidesteps a
// real incompatibility between clang 18's BTF encoding and the aya-obj
// version paired with the aya release this toolchain can actually build
// (verified: the modern SEC(".maps") + BTF form fails to parse with
// "error parsing ELF data", the legacy form parses cleanly, see the commit
// history / PR description for the actual verifier output).
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

// Single u32 config value: drop every Nth packet, 0 disables the fault
// entirely. Simpler than a probability threshold and, unlike a probability
// check, gives an exact drop count for a given packet count, which is what
// the replay comparison in a test scenario actually wants to assert on.
struct bpf_map_def SEC("maps") drop_every_n = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

// Single global counter, incremented atomically. Started with a per-CPU
// array here (cheaper, no atomic needed) but that makes the drop pattern
// per-CPU rather than globally exact on multi-queue NICs or multi-core
// boxes, which directly undermines the determinism guarantee this whole
// project is built around. __sync_fetch_and_add lowers to a real BPF atomic
// instruction, supported since kernel 5.12 for this map type, costs a bit
// more than the per-CPU version but the correctness is worth it here.
struct bpf_map_def SEC("maps") packet_count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

SEC("xdp")
int xdp_pktloss(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u32 *n = bpf_map_lookup_elem(&drop_every_n, &key);
    if (!n || *n == 0)
        return XDP_PASS;

    __u64 *count = bpf_map_lookup_elem(&packet_count, &key);
    if (!count)
        return XDP_PASS;

    __u64 c = __sync_fetch_and_add(count, 1) + 1;

    if (c % *n == 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
