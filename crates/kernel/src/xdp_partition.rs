use crate::bpf_util::set_u32_map;
use aya::programs::{Xdp, XdpFlags};
use aya::Bpf;
use blackswan_core::{FaultContext, FaultInjector, HarnessError};
use std::convert::TryInto;
use std::net::Ipv4Addr;

const XDP_PARTITION_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp_partition.o"));
const PROGRAM_NAME: &str = "xdp_partition";
const ENABLED_MAP: &str = "partition_enabled";
const SRC_IP_MAP: &str = "partition_src_ip";
const SRC_PORT_MAP: &str = "partition_src_port";

// Network partition ("split-brain") via XDP: unconditionally drops every
// inbound packet whose source IP, and optionally source port, matches one
// configured peer. No modulus, no counter, pure match/no-match, so unlike
// packet loss and corruption there's nothing here that needs the
// determinism engine beyond the config itself, the config is the entire
// behavior.
//
// src_port of 0 means "any port from that IP", a coarser host-level cut
// rather than isolating one specific connection.
//
// Separate program from XdpPacketLossInjector/XdpCorruptionInjector, can't
// attach alongside either on the same interface yet, see the TODO in
// lib.rs.
pub struct XdpPartitionInjector {
    id: String,
    iface: String,
    src_ip: Ipv4Addr,
    src_port: u16,
    bpf: Option<Bpf>,
    armed: bool,
}

impl XdpPartitionInjector {
    pub fn new(id: impl Into<String>, iface: impl Into<String>, src_ip: Ipv4Addr, src_port: u16) -> Self {
        Self { id: id.into(), iface: iface.into(), src_ip, src_port, bpf: None, armed: false }
    }

    fn ensure_loaded(&mut self) -> Result<(), HarnessError> {
        if self.bpf.is_some() {
            return Ok(());
        }

        let mut bpf = Bpf::load(XDP_PARTITION_OBJ)
            .map_err(|e| HarnessError::ArmFailed(self.id.clone(), e.to_string()))?;

        {
            let program: &mut Xdp = bpf
                .program_mut(PROGRAM_NAME)
                .ok_or_else(|| {
                    HarnessError::ArmFailed(self.id.clone(), format!("no program named {PROGRAM_NAME} in object"))
                })?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| {
                    HarnessError::ArmFailed(self.id.clone(), e.to_string())
                })?;

            program.load().map_err(|e| HarnessError::ArmFailed(self.id.clone(), e.to_string()))?;
            program
                .attach(&self.iface, XdpFlags::default())
                .map_err(|e| HarnessError::ArmFailed(self.id.clone(), e.to_string()))?;
        }

        self.bpf = Some(bpf);

        let bpf = self.bpf.as_mut().expect("just assigned above");
        // ip->saddr is compared as raw network-byte-order bytes on the
        // kernel side, Ipv4Addr::octets() gives us those same bytes, from_ne_bytes
        // reassembles them into the matching u32 representation on this
        // (little-endian) host without a htonl/ntohl round trip
        let ip_as_stored = u32::from_ne_bytes(self.src_ip.octets());
        set_u32_map(bpf, &self.id, SRC_IP_MAP, ip_as_stored)?;
        set_u32_map(bpf, &self.id, SRC_PORT_MAP, self.src_port as u32)?;
        Ok(())
    }
}

impl FaultInjector for XdpPartitionInjector {
    fn id(&self) -> &str {
        &self.id
    }

    fn arm(&mut self, _ctx: &FaultContext) -> Result<(), HarnessError> {
        self.ensure_loaded()?;
        let bpf = self.bpf.as_mut().expect("just loaded above");
        set_u32_map(bpf, &self.id, ENABLED_MAP, 1)?;
        self.armed = true;
        Ok(())
    }

    fn disarm(&mut self) -> Result<(), HarnessError> {
        let Some(bpf) = self.bpf.as_mut() else {
            self.armed = false;
            return Ok(());
        };
        set_u32_map(bpf, &self.id, ENABLED_MAP, 0)?;
        self.armed = false;
        Ok(())
    }

    fn is_armed(&self) -> bool {
        self.armed
    }
}
