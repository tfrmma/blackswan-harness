use blackswan_core::{FaultContext, FaultInjector, HarnessError};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

// Clock skew via Linux time namespaces. Fundamentally different lifecycle
// from every other injector in this crate: time namespaces can only be
// configured for a process at its own exec(), never retroactively (verified
// empirically in this sandbox, not just read off the man page: a process
// that calls unshare(CLONE_NEWTIME), writes offsets to its own
// /proc/self/timens_offsets, and then execs itself ends up in the skewed
// namespace, but there's no operation that skews a process that's already
// running). There's no target pid to attach to, arm() launches its own
// supervised child inside a freshly configured namespace and disarm()
// terminates it, see the note on FaultInjector::disarm in blackswan_core
// for why that's still a valid interpretation of the trait.
//
// Only CLOCK_MONOTONIC and CLOCK_BOOTTIME are affected. This is a hard
// kernel limitation, not a gap in this implementation: time_namespaces(7)
// is explicit that CLOCK_REALTIME is never virtualized, by design, for
// complexity and overhead reasons. Nothing here can skew wall-clock time.
pub struct TimeSkewInjector {
    id: String,
    argv: Vec<String>,
    monotonic_offset_secs: i64,
    boottime_offset_secs: i64,
    capture_stdout: bool,
    child: Option<Child>,
}

impl TimeSkewInjector {
    pub fn new(
        id: impl Into<String>,
        argv: Vec<String>,
        monotonic_offset_secs: i64,
        boottime_offset_secs: i64,
    ) -> Self {
        Self {
            id: id.into(),
            argv,
            monotonic_offset_secs,
            boottime_offset_secs,
            capture_stdout: false,
            child: None,
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    // Off by default: a real supervised target's stdout should just flow
    // through normally, piping it unconditionally without draining risks
    // blocking the target once it fills the OS pipe buffer. Only turn this
    // on for short diagnostic/verification runs where something is actually
    // going to read take_stdout().
    pub fn with_captured_stdout(mut self) -> Self {
        self.capture_stdout = true;
        self
    }

    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.as_mut().and_then(|c| c.stdout.take())
    }
}

impl FaultInjector for TimeSkewInjector {
    fn id(&self) -> &str {
        &self.id
    }

    fn arm(&mut self, _ctx: &FaultContext) -> Result<(), HarnessError> {
        if self.child.is_some() {
            return Ok(()); // idempotent, matches the trait contract
        }

        let Some((program, args)) = self.argv.split_first() else {
            return Err(HarnessError::ArmFailed(self.id.clone(), "argv is empty, nothing to launch".into()));
        };

        // built before fork, the pre_exec closure below runs between fork()
        // and exec() and can only call async-signal-safe functions, no
        // allocation, so this has to already exist as plain bytes by then
        let offsets_buf = format!(
            "monotonic {} 0\nboottime {} 0\n",
            self.monotonic_offset_secs, self.boottime_offset_secs
        )
        .into_bytes();

        let mut cmd = Command::new(program);
        cmd.args(args);
        if self.capture_stdout {
            cmd.stdout(std::process::Stdio::piped());
        }

        // SAFETY: this closure only calls unshare(2) and raw open/write/close
        // via libc on a buffer that was fully built before fork(), no libstd
        // allocation (no String/format!/std::fs) happens between fork and
        // exec, satisfying the async-signal-safety requirement pre_exec
        // documents.
        unsafe {
            cmd.pre_exec(move || {
                if libc::unshare(libc::CLONE_NEWTIME) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                const PATH: &[u8] = b"/proc/self/timens_offsets\0";
                let fd = libc::open(PATH.as_ptr() as *const libc::c_char, libc::O_WRONLY);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let ret = libc::write(fd, offsets_buf.as_ptr() as *const libc::c_void, offsets_buf.len());
                libc::close(fd);

                if ret < 0 {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(())
            });
        }

        let child = cmd
            .spawn()
            .map_err(|e| HarnessError::ArmFailed(self.id.clone(), format!("spawning skewed process: {e}")))?;

        self.child = Some(child);
        Ok(())
    }

    fn disarm(&mut self) -> Result<(), HarnessError> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };

        // process already exited on its own, nothing to kill, not an error
        if let Ok(Some(_)) = child.try_wait() {
            return Ok(());
        }

        child
            .kill()
            .map_err(|e| HarnessError::DisarmFailed(self.id.clone(), format!("killing skewed process: {e}")))?;
        let _ = child.wait(); // reap, avoid leaving a zombie

        Ok(())
    }

    fn is_armed(&self) -> bool {
        self.child.is_some()
    }
}
