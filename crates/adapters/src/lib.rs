// Layer 2: protocol-aware adapters. Each adapter parses one wire protocol and
// implements ProtocolAdapter to realize exchange-semantic faults, silent
// reject, ack without execution, sudden rate-limit throttling, that kernel
// level chaos can't express because it doesn't understand the protocol.
//
// FIX 4.0-4.4 dialect (the 3-field header: BeginString, BodyLength,
// MsgType), FIXT.1.1/5.0's extended header isn't supported, see Known
// limitations.

pub mod fix;

// TODO: only three fault behaviors and three MsgTypes (ExecutionReport,
// Reject, OrderCancelReject) are covered so far. Real candidates for more
// FIX coverage: NewOrderSingle/OrderCancelReplaceRequest mutation (Mutate
// action exists on InterceptAction, nothing uses it yet), sequence number
// gaps (force a ResendRequest), logon/heartbeat session-level faults.
//
// TODO: FIX is the only protocol implemented. The two other obvious targets
// for this layer are a WebSocket adapter (most crypto exchange retail/algo
// APIs) and a plain REST adapter (order entry over HTTP, rate limits
// expressed as real 429s instead of FIX BusinessMessageReject). Neither
// shares FixProxy's TCP-with-length-prefixed-framing shape closely enough
// to guess the right abstraction from one example, build the next one on
// its own merits rather than forcing it through FixProxy.
