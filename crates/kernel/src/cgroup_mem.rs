use blackswan_core::{FaultContext, FaultInjector, HarnessError};
use std::fs;
use std::path::PathBuf;

// Hard mirrors cgroup v2 memory.max / v1 memory.limit_in_bytes: OOM-kills
// the target on breach. Soft mirrors memory.high / memory.soft_limit_in_bytes:
// biases reclaim under pressure without killing anything. This is memory
// pressure at the OS level, not a JVM/CLR-specific "force a GC pause" hook,
// inducing GC pauses in a managed target is a real side effect of this but
// isn't runtime-instrumented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureMode {
    Hard,
    Soft,
}

// Memory pressure via cgroups. Creates a child cgroup, moves the target pid
// into it, writes a byte limit to the controller's limit file. Detects v1
// vs v2 at arm time rather than assuming one, real machines run either
// depending on distro/systemd version, and this sandbox itself only has the
// memory controller delegated on the legacy v1 hierarchy, not v2 unified
// (verified against /sys/fs/cgroup/unified/cgroup.controllers directly, not
// assumed). See the README's Known limitations for how far the v2 path has
// actually been exercised.
pub struct CgroupMemoryPressureInjector {
    id: String,
    pid: u32,
    limit_bytes: u64,
    mode: PressureMode,
    // set once at arm() time and kept after disarm(): (cgroup dir, limit
    // file name, "unlimited" sentinel for that file). disarm() reuses this
    // instead of re-deriving v1 vs v2 from the path, one source of truth
    // for which file we wrote. Separate from `armed`, infrastructure
    // existing and the fault being currently active aren't the same thing,
    // same split XdpPacketLossInjector uses between `bpf` and `armed`.
    setup: Option<(PathBuf, &'static str, &'static str)>,
    armed: bool,
}

impl CgroupMemoryPressureInjector {
    pub fn new(id: impl Into<String>, pid: u32, limit_bytes: u64, mode: PressureMode) -> Self {
        Self { id: id.into(), pid, limit_bytes, mode, setup: None, armed: false }
    }

    fn locate_subtree(&self) -> Result<PathBuf, HarnessError> {
        let v1_root = PathBuf::from("/sys/fs/cgroup/memory");
        if v1_root.join("memory.limit_in_bytes").exists() {
            return Ok(v1_root);
        }

        let our_cgroup = fs::read_to_string("/proc/self/cgroup").map_err(HarnessError::Io)?;
        let v2_path = our_cgroup
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .ok_or_else(|| {
                HarnessError::ArmFailed(self.id.clone(), "no v2 cgroup entry in /proc/self/cgroup".into())
            })?;
        let v2_root = PathBuf::from("/sys/fs/cgroup/unified").join(v2_path.trim_start_matches('/'));
        if v2_root.join("memory.max").exists() {
            return Ok(v2_root);
        }

        Err(HarnessError::ArmFailed(
            self.id.clone(),
            "no usable memory controller on either v1 or v2 cgroup hierarchy".into(),
        ))
    }

    fn ensure_setup(&mut self) -> Result<(), HarnessError> {
        if self.setup.is_some() {
            return Ok(());
        }

        let subtree = self.locate_subtree()?;
        let is_v1 = subtree.join("memory.limit_in_bytes").exists();

        let (limit_file, unlimited): (&'static str, &'static str) = match (is_v1, self.mode) {
            (true, PressureMode::Hard) => ("memory.limit_in_bytes", "9223372036854775807"),
            (true, PressureMode::Soft) => ("memory.soft_limit_in_bytes", "9223372036854775807"),
            (false, PressureMode::Hard) => ("memory.max", "max"),
            (false, PressureMode::Soft) => ("memory.high", "max"),
        };

        let child = subtree.join(format!("blackswan-{}", self.id));
        fs::create_dir_all(&child).map_err(|e| {
            HarnessError::ArmFailed(self.id.clone(), format!("creating cgroup {}: {e}", child.display()))
        })?;

        if !is_v1 {
            // memory controller has to be enabled in the parent's
            // subtree_control before a v2 child's memory.max/high means
            // anything, best effort, some setups delegate it pre-enabled
            let _ = fs::write(subtree.join("cgroup.subtree_control"), "+memory");
        }

        fs::write(child.join("cgroup.procs"), self.pid.to_string()).map_err(|e| {
            HarnessError::ArmFailed(self.id.clone(), format!("moving pid {} into cgroup: {e}", self.pid))
        })?;

        self.setup = Some((child, limit_file, unlimited));
        Ok(())
    }
}

impl FaultInjector for CgroupMemoryPressureInjector {
    fn id(&self) -> &str {
        &self.id
    }

    fn arm(&mut self, _ctx: &FaultContext) -> Result<(), HarnessError> {
        self.ensure_setup()?;
        let (path, limit_file, _) = self.setup.as_ref().expect("just set up above");

        fs::write(path.join(limit_file), self.limit_bytes.to_string())
            .map_err(|e| HarnessError::ArmFailed(self.id.clone(), format!("writing {limit_file}: {e}")))?;

        self.armed = true;
        Ok(())
    }

    fn disarm(&mut self) -> Result<(), HarnessError> {
        let Some((path, limit_file, unlimited)) = &self.setup else {
            self.armed = false;
            return Ok(());
        };

        // lift the limit rather than moving the pid back out, same
        // "neutralize in place" pattern the XDP injectors use
        fs::write(path.join(limit_file), unlimited)
            .map_err(|e| HarnessError::DisarmFailed(self.id.clone(), format!("writing {limit_file}: {e}")))?;

        self.armed = false;
        Ok(())
    }

    fn is_armed(&self) -> bool {
        self.armed
    }
}
