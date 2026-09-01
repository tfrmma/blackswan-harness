use crate::bpf_util::set_u32_map;
use aya::programs::{Xdp, XdpFlags};
use aya::Bpf;
use blackswan_core::{FaultContext, FaultInjector, HarnessError};
use std::convert::TryInto;

const XDP_PKTLOSS_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp_pktloss.o"));
const PROGRAM_NAME: &str = "xdp_pktloss";
const MAP_NAME: &str = "drop_every_n";

// Deterministic packet loss via XDP. No randomness in the kernel program on
// purpose, see bpf/xdp_pktloss.c, it counts packets and drops on a fixed
// modulus that userspace controls. arm()/disarm() only ever toggle that
// modulus, the XDP hook itself stays attached once loaded so repeated
// arm/disarm cycles don't hammer the kernel with attach/detach netlink
// calls.
pub struct XdpPacketLossInjector {
    id: String,
    iface: String,
    drop_every_n: u32,
    bpf: Option<Bpf>,
    armed: bool,
}

impl XdpPacketLossInjector {
    pub fn new(id: impl Into<String>, iface: impl Into<String>, drop_every_n: u32) -> Self {
        Self { id: id.into(), iface: iface.into(), drop_every_n, bpf: None, armed: false }
    }

    fn ensure_loaded(&mut self) -> Result<(), HarnessError> {
        if self.bpf.is_some() {
            return Ok(());
        }

        let mut bpf = Bpf::load(XDP_PKTLOSS_OBJ)
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
        Ok(())
    }
}

impl FaultInjector for XdpPacketLossInjector {
    fn id(&self) -> &str {
        &self.id
    }

    fn arm(&mut self, _ctx: &FaultContext) -> Result<(), HarnessError> {
        self.ensure_loaded()?;
        let bpf = self.bpf.as_mut().expect("just loaded above");
        set_u32_map(bpf, &self.id, MAP_NAME, self.drop_every_n)?;
        self.armed = true;
        Ok(())
    }

    fn disarm(&mut self) -> Result<(), HarnessError> {
        let Some(bpf) = self.bpf.as_mut() else {
            // never armed, matches the "safe to call twice" contract
            self.armed = false;
            return Ok(());
        };
        set_u32_map(bpf, &self.id, MAP_NAME, 0)?;
        self.armed = false;
        Ok(())
    }

    fn is_armed(&self) -> bool {
        self.armed
    }
}
