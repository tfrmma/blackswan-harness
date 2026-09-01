use std::sync::atomic::{AtomicU64, Ordering};

// Abstraction over time so the replay engine can drive a deterministic virtual
// clock instead of wall time. Real-time faults (latency injection, clock skew)
// need to know "now" without caring whether that's the OS clock or a replayed
// trace.
pub trait Clock: Send + Sync {
    fn now_ns(&self) -> u64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ns(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos() as u64
    }
}

// Monotonically increasing virtual clock for deterministic replay. Advances only
// when the runner tells it to, never on its own. This is what makes a recorded
// fault schedule reproducible regardless of how long the previous step actually
// took to execute in wall time.
pub struct VirtualClock {
    ns: AtomicU64,
}

impl VirtualClock {
    pub fn new(start_ns: u64) -> Self {
        Self { ns: AtomicU64::new(start_ns) }
    }

    pub fn advance(&self, delta_ns: u64) {
        self.ns.fetch_add(delta_ns, Ordering::SeqCst);
    }
}

impl Clock for VirtualClock {
    fn now_ns(&self) -> u64 {
        self.ns.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_clock_only_moves_when_told() {
        let clock = VirtualClock::new(1_000);
        assert_eq!(clock.now_ns(), 1_000);
        clock.advance(500);
        assert_eq!(clock.now_ns(), 1_500);
    }
}
