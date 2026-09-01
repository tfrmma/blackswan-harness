use crate::error::HarnessError;

// Raw wire message intercepted at the adapter boundary. Kept as opaque bytes at
// this layer, the adapter itself owns the parsing for its protocol.
pub struct RawMessage {
    pub bytes: Vec<u8>,
    pub direction: Direction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

// What an adapter decides to do with an intercepted message.
pub enum InterceptAction {
    Forward,
    Drop,
    Mutate(Vec<u8>),
    Delay(u64), // ns
}

// Protocol-aware fault injection, this is where FIX, exchange WS/REST, etc plug
// in. Each adapter owns the parsing for its protocol and decides how to realize
// semantic faults (silent reject, ack without execution, throttling) in terms
// that actually make sense for that protocol, kernel-level chaos can't touch
// this.
pub trait ProtocolAdapter: Send + Sync {
    fn name(&self) -> &str;

    fn intercept(&self, msg: &RawMessage) -> Result<InterceptAction, HarnessError>;
}
