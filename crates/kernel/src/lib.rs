// Layer 1: kernel-level fault injection. XDP for packet loss, byte
// corruption, and network partition, cgroups for memory pressure, and time
// namespaces for clock skew, are the real injectors, see xdp_pktloss,
// xdp_corrupt, xdp_partition, cgroup_mem, and time_skew. Layer 1 is
// complete as of this module.

pub mod bpf_util;
pub mod cgroup_mem;
pub mod time_skew;
pub mod xdp_corrupt;
pub mod xdp_partition;
pub mod xdp_pktloss;

pub use cgroup_mem::{CgroupMemoryPressureInjector, PressureMode};
pub use time_skew::TimeSkewInjector;
pub use xdp_corrupt::XdpCorruptionInjector;
pub use xdp_partition::XdpPartitionInjector;
pub use xdp_pktloss::XdpPacketLossInjector;

// TODO: none of XdpPacketLossInjector, XdpCorruptionInjector, and
// XdpPartitionInjector can be attached to the same interface at the same
// time yet, XDP only supports one program per interface per attach mode
// (native/generic/offload), a second attach() replaces the first rather
// than stacking. Now that there are three of these, the shared shape is
// getting clearer: probably a single dispatcher program with independent
// per-fault config maps, worth doing before a fourth XDP-based fault shows
// up rather than after.
