use super::proxy::FixProxy;
use blackswan_core::{FaultContext, FaultInjector, HarnessError, ProtocolAdapter};
use std::sync::atomic::Ordering;
use std::sync::Arc;

// Wraps a FixProxy as a FaultInjector. The proxy (the mechanism) starts on
// first arm() and stays running across arm/disarm cycles, exactly like an
// XDP hook stays attached, only the enabled flag toggles. Which fault
// actually happens is entirely up to whichever ProtocolAdapter this was
// constructed with, this type has no fault-specific logic of its own.
pub struct FixFaultInjector {
    id: String,
    proxy: FixProxy,
    armed: bool,
}

impl FixFaultInjector {
    pub fn new(
        id: impl Into<String>,
        listen_addr: impl Into<String>,
        upstream_addr: impl Into<String>,
        adapter: Arc<dyn ProtocolAdapter>,
    ) -> Self {
        Self {
            id: id.into(),
            proxy: FixProxy::new(listen_addr, upstream_addr, adapter),
            armed: false,
        }
    }
}

impl FaultInjector for FixFaultInjector {
    fn id(&self) -> &str {
        &self.id
    }

    fn arm(&mut self, _ctx: &FaultContext) -> Result<(), HarnessError> {
        self.proxy.start()?;
        self.proxy.enabled_flag().store(true, Ordering::SeqCst);
        self.armed = true;
        Ok(())
    }

    fn disarm(&mut self) -> Result<(), HarnessError> {
        self.proxy.enabled_flag().store(false, Ordering::SeqCst);
        self.armed = false;
        Ok(())
    }

    fn is_armed(&self) -> bool {
        self.armed
    }
}
