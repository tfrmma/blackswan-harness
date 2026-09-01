pub mod adapter;
pub mod fields;
pub mod framing;
pub mod injector;
pub mod message;
pub mod proxy;

pub use adapter::{FixAckWithoutExecution, FixRateLimitThrottle, FixSilentReject};
pub use injector::FixFaultInjector;
pub use message::{parse, FixMessage, ParseError};
pub use proxy::FixProxy;

// TODO: NewOrderSingle (D) is only used to build test traffic so far, no
// fault reads or mutates a client's outbound order fields yet (price/qty
// mutation, wrong side, stale ClOrdID replay would all be real exchange-
// side bugs to chase). OrderCancelRequest (F) and
// OrderCancelReplaceRequest (G) aren't touched at all.
