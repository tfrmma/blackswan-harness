use crate::bpf_util::set_u32_map;
use aya::programs::{Xdp, XdpFlags};
use aya::Bpf;
use blackswan_core::{FaultContext, FaultInjector, HarnessError};
use std::convert::TryInto;

const XDP_CORRUPT_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp_corrupt.o"));
const PROGRAM_NAME: &str = "xdp_corrupt";
const EVERY_N_MAP: &str = "corrupt_every_n";
const OFFSET_MAP: &str = "corrupt_offset";
const MASK_MAP: &str = "corrupt_mask";

// Deterministic byte-level corruption via XDP. Same shape as
// XdpPacketLossInjector: no randomness in the kernel, arm()/disarm() only
// toggle corrupt_every_n, the hook stays attached once loaded. offset and
// mask are fixed for the injector's lifetime, written once at load time
// rather than on every arm().
//
// Separate program from XdpPacketLossInjector's, can't both be attached to
// the same interface at once yet, see the TODO in lib.rs.
pub struct XdpCorruptionInjector {
    id: String,
    iface: String,
    corrupt_every_n: u32,
    offset: u32,
    mask: u8,
    bpf: Option<Bpf>,
    armed: bool,
}

impl XdpCorruptionInjector {
    pub fn new(id: impl Into<String>, iface: impl Into<String>, corrupt_every_n: u32, offset: u32, mask: u8) -> Self {
        Self {
            id: id.into(),
            iface: iface.into(),
            corrupt_every_n,
            offset,
            mask,
            bpf: None,
            armed: false,
        }
    }

    fn ensure_loaded(&mut self) -> Result<(), HarnessError> {
        if self.bpf.is_some() {
            return Ok(());
        }

        let mut bpf =
            Bpf::load(XDP_CORRUPT_OBJ).map_err(|e| HarnessError::ArmFailed(self.id.clone(), e.to_string()))?;

        {
            let program: &mut Xdp = bpf
                .program_mut(PROGRAM_NAME)
                .ok_or_else(|| {
                    HarnessError::ArmFailed(self.id.clone(), format!("no program named {PROGRAM_NAME} in object"))
                })?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| HarnessError::ArmFailed(self.id.clone(), e.to_string()))?;

            program
                .load()
                .map_err(|e| HarnessError::ArmFailed(self.id.clone(), e.to_string()))?;
            program
                .attach(&self.iface, XdpFlags::default())
                .map_err(|e| HarnessError::ArmFailed(self.id.clone(), e.to_string()))?;
        }

        self.bpf = Some(bpf);

        let bpf = self.bpf.as_mut().expect("just assigned above");
        set_u32_map(bpf, &self.id, OFFSET_MAP, self.offset)?;
        set_u32_map(bpf, &self.id, MASK_MAP, self.mask as u32)?;
        Ok(())
    }
}

impl FaultInjector for XdpCorruptionInjector {
    fn id(&self) -> &str {
        &self.id
    }

    fn arm(&mut self, _ctx: &FaultContext) -> Result<(), HarnessError> {
        self.ensure_loaded()?;
        let bpf = self.bpf.as_mut().expect("just loaded above");
        set_u32_map(bpf, &self.id, EVERY_N_MAP, self.corrupt_every_n)?;
        self.armed = true;
        Ok(())
    }

    fn disarm(&mut self) -> Result<(), HarnessError> {
        let Some(bpf) = self.bpf.as_mut() else {
            self.armed = false;
            return Ok(());
        };
        set_u32_map(bpf, &self.id, EVERY_N_MAP, 0)?;
        self.armed = false;
        Ok(())
    }

    fn is_armed(&self) -> bool {
        self.armed
    }
}
