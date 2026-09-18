pub mod adapter;
pub mod fields;
pub mod framing;
pub mod injector;
pub mod message;
pub mod proxy;

pub use adapter::{FixAckWithoutExecution, FixExecutionReportPriceMutation, FixRateLimitThrottle, FixSilentReject};
pub use injector::FixFaultInjector;
pub use message::{parse, set_field, FixMessage, ParseError};
pub use proxy::FixProxy;

// TODO: OrderCancelRequest (F) and OrderCancelReplaceRequest (G) aren't
// touched at all yet. Wrong-side mutation and stale ClOrdID replay
// (FixExecutionReportPriceMutation's siblings that mod.rs used to list
// here before either existed) are still just ideas, not built, same "only
// once there's a second real use" bar the rest of this crate holds to.
