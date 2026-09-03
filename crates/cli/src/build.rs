use crate::config::{InjectorConfig, PressureModeConfig};
use blackswan_adapters::fix::{FixAckWithoutExecution, FixFaultInjector, FixRateLimitThrottle, FixSilentReject};
use blackswan_core::FaultInjector;
use blackswan_kernel::{
    CgroupMemoryPressureInjector, PressureMode, TimeSkewInjector, XdpCorruptionInjector,
    XdpPacketLossInjector, XdpPartitionInjector,
};
use std::sync::Arc;

// Turns one config entry into the real injector it names. All the FIX
// variants build the same FixFaultInjector with a different ProtocolAdapter,
// matching how that crate is actually structured (composition, not one
// injector struct per FIX fault).
pub fn build_injector(id: &str, config: InjectorConfig) -> Box<dyn FaultInjector> {
    match config {
        InjectorConfig::XdpPacketLoss { iface, drop_every_n } => {
            Box::new(XdpPacketLossInjector::new(id, iface, drop_every_n))
        }
        InjectorConfig::XdpCorruption { iface, corrupt_every_n, offset, mask } => {
            Box::new(XdpCorruptionInjector::new(id, iface, corrupt_every_n, offset, mask))
        }
        InjectorConfig::XdpPartition { iface, src_ip, src_port } => {
            Box::new(XdpPartitionInjector::new(id, iface, src_ip, src_port))
        }
        InjectorConfig::CgroupMemoryPressure { pid, limit_bytes, mode } => {
            let mode = match mode {
                PressureModeConfig::Hard => PressureMode::Hard,
                PressureModeConfig::Soft => PressureMode::Soft,
            };
            Box::new(CgroupMemoryPressureInjector::new(id, pid, limit_bytes, mode))
        }
        InjectorConfig::TimeSkew { argv, monotonic_offset_secs, boottime_offset_secs } => {
            Box::new(TimeSkewInjector::new(id, argv, monotonic_offset_secs, boottime_offset_secs))
        }
        InjectorConfig::FixSilentReject { listen_addr, upstream_addr } => {
            Box::new(FixFaultInjector::new(id, listen_addr, upstream_addr, Arc::new(FixSilentReject)))
        }
        InjectorConfig::FixAckWithoutExecution { listen_addr, upstream_addr } => {
            Box::new(FixFaultInjector::new(id, listen_addr, upstream_addr, Arc::new(FixAckWithoutExecution)))
        }
        InjectorConfig::FixRateLimitThrottle { listen_addr, upstream_addr, threshold } => {
            Box::new(FixFaultInjector::new(
                id,
                listen_addr,
                upstream_addr,
                Arc::new(FixRateLimitThrottle::new(threshold)),
            ))
        }
    }
}
