use super::fields::*;
use super::message::parse;
use blackswan_core::{Direction, HarnessError, InterceptAction, ProtocolAdapter, RawMessage};
use std::sync::atomic::{AtomicU64, Ordering};

// Drops session-level Reject (35=3), OrderCancelReject (35=9), and
// ExecutionReport messages carrying a rejected OrdStatus/ExecType, inbound
// only (exchange -> client). The order looks live to the client because it
// never finds out the exchange actually rejected it.
pub struct FixSilentReject;

impl ProtocolAdapter for FixSilentReject {
    fn name(&self) -> &str {
        "fix-silent-reject"
    }

    fn intercept(&self, msg: &RawMessage) -> Result<InterceptAction, HarnessError> {
        if msg.direction != Direction::Inbound {
            return Ok(InterceptAction::Forward);
        }

        let parsed = parse(&msg.bytes)
            .map_err(|e| HarnessError::AdapterRejected(self.name().to_string(), format!("{e:?}")))?;

        let is_rejection = parsed.is(TAG_MSG_TYPE, MSG_TYPE_REJECT)
            || parsed.is(TAG_MSG_TYPE, MSG_TYPE_ORDER_CANCEL_REJECT)
            || (parsed.is(TAG_MSG_TYPE, MSG_TYPE_EXECUTION_REPORT)
                && (parsed.is(TAG_ORD_STATUS, ORD_STATUS_REJECTED) || parsed.is(TAG_EXEC_TYPE, EXEC_TYPE_REJECTED)));

        Ok(if is_rejection { InterceptAction::Drop } else { InterceptAction::Forward })
    }
}

// Drops ExecutionReport messages that indicate an actual fill (ExecType=F
// or OrdStatus in {PartiallyFilled, Filled}), inbound only, while letting
// the initial New/Ack through. The client sees its order accepted and then
// hears nothing further about it ever actually trading.
pub struct FixAckWithoutExecution;

impl ProtocolAdapter for FixAckWithoutExecution {
    fn name(&self) -> &str {
        "fix-ack-without-execution"
    }

    fn intercept(&self, msg: &RawMessage) -> Result<InterceptAction, HarnessError> {
        if msg.direction != Direction::Inbound {
            return Ok(InterceptAction::Forward);
        }

        let parsed = parse(&msg.bytes)
            .map_err(|e| HarnessError::AdapterRejected(self.name().to_string(), format!("{e:?}")))?;

        if !parsed.is(TAG_MSG_TYPE, MSG_TYPE_EXECUTION_REPORT) {
            return Ok(InterceptAction::Forward);
        }

        let is_fill = parsed.is(TAG_EXEC_TYPE, EXEC_TYPE_TRADE)
            || parsed.is(TAG_ORD_STATUS, ORD_STATUS_PARTIALLY_FILLED)
            || parsed.is(TAG_ORD_STATUS, ORD_STATUS_FILLED);

        Ok(if is_fill { InterceptAction::Drop } else { InterceptAction::Forward })
    }
}

// Drops outbound (client -> exchange) messages once more than
// `threshold` have passed through since the injector was armed, silently,
// matching how a lot of real gateways behave under rate limiting: the
// request just never arrives, no reject comes back. Counter is an atomic
// because ProtocolAdapter::intercept takes &self, not &mut self, matching
// the same pattern VirtualClock uses in blackswan-core.
pub struct FixRateLimitThrottle {
    threshold: u64,
    count: AtomicU64,
}

impl FixRateLimitThrottle {
    pub fn new(threshold: u64) -> Self {
        Self { threshold, count: AtomicU64::new(0) }
    }
}

impl ProtocolAdapter for FixRateLimitThrottle {
    fn name(&self) -> &str {
        "fix-rate-limit-throttle"
    }

    fn intercept(&self, msg: &RawMessage) -> Result<InterceptAction, HarnessError> {
        if msg.direction != Direction::Outbound {
            return Ok(InterceptAction::Forward);
        }

        let seen = self.count.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(if seen > self.threshold { InterceptAction::Drop } else { InterceptAction::Forward })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_execution_report(ord_status: &str, exec_type: &str) -> Vec<u8> {
        // minimal but well-formed ExecutionReport, body length and checksum
        // computed by hand and cross-checked against message.rs's own
        // compute_checksum in the test below, not asserted blind
        let body = format!("35=8\x0139={ord_status}\x01150={exec_type}\x01");
        let header = format!("8=FIX.4.4\x019={}\x01", body.len());
        let mut full = format!("{header}{body}").into_bytes();
        let sum = crate::fix::message::compute_checksum(&full);
        full.extend_from_slice(format!("10={sum:03}\x01").as_bytes());
        full
    }

    fn inbound(bytes: Vec<u8>) -> RawMessage {
        RawMessage { bytes, direction: Direction::Inbound }
    }

    fn outbound(bytes: Vec<u8>) -> RawMessage {
        RawMessage { bytes, direction: Direction::Outbound }
    }

    #[test]
    fn silent_reject_drops_rejected_execution_report() {
        let adapter = FixSilentReject;
        let msg = inbound(reference_execution_report("8", "8"));
        assert!(matches!(adapter.intercept(&msg).unwrap(), InterceptAction::Drop));
    }

    #[test]
    fn silent_reject_forwards_a_new_ack() {
        let adapter = FixSilentReject;
        let msg = inbound(reference_execution_report("0", "0"));
        assert!(matches!(adapter.intercept(&msg).unwrap(), InterceptAction::Forward));
    }

    #[test]
    fn silent_reject_ignores_outbound_traffic() {
        let adapter = FixSilentReject;
        let msg = outbound(reference_execution_report("8", "8"));
        assert!(matches!(adapter.intercept(&msg).unwrap(), InterceptAction::Forward));
    }

    #[test]
    fn ack_without_execution_drops_a_fill_but_not_the_ack() {
        let adapter = FixAckWithoutExecution;

        let ack = inbound(reference_execution_report("0", "0"));
        assert!(matches!(adapter.intercept(&ack).unwrap(), InterceptAction::Forward));

        let fill = inbound(reference_execution_report("2", "F"));
        assert!(matches!(adapter.intercept(&fill).unwrap(), InterceptAction::Drop));
    }

    #[test]
    fn rate_limit_throttle_allows_up_to_threshold_then_drops() {
        let adapter = FixRateLimitThrottle::new(2);
        let msg = || outbound(reference_execution_report("0", "0"));

        assert!(matches!(adapter.intercept(&msg()).unwrap(), InterceptAction::Forward)); // 1
        assert!(matches!(adapter.intercept(&msg()).unwrap(), InterceptAction::Forward)); // 2
        assert!(matches!(adapter.intercept(&msg()).unwrap(), InterceptAction::Drop)); // 3, over threshold
        assert!(matches!(adapter.intercept(&msg()).unwrap(), InterceptAction::Drop)); // 4, still over
    }

    #[test]
    fn rate_limit_throttle_ignores_inbound_traffic() {
        let adapter = FixRateLimitThrottle::new(0);
        let msg = inbound(reference_execution_report("0", "0"));
        assert!(matches!(adapter.intercept(&msg).unwrap(), InterceptAction::Forward));
    }
}
