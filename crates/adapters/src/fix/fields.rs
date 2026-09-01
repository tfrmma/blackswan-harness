// Tag numbers and known field values actually used by this crate's fault
// logic, verified against real FIX dictionaries (Wikipedia's worked example,
// OnixS, b2bits fixopaedia, Zero Hash's public FIX docs), not guessed. Not
// a full dictionary, only what silent-reject / ack-without-execution /
// rate-limit-throttle need to read.

pub const TAG_BEGIN_STRING: u32 = 8;
pub const TAG_BODY_LENGTH: u32 = 9;
pub const TAG_MSG_TYPE: u32 = 35;
pub const TAG_MSG_SEQ_NUM: u32 = 34;
pub const TAG_ORD_STATUS: u32 = 39;
pub const TAG_EXEC_TYPE: u32 = 150;
pub const TAG_CHECKSUM: u32 = 10;

// MsgType (35) values relevant here. FIX 4.0-4.4 all use the same 3-field
// header (8, 9, 35) and the same codes for these, this crate doesn't
// support the FIXT.1.1/5.0 extended header yet, see Known limitations.
pub const MSG_TYPE_NEW_ORDER_SINGLE: &[u8] = b"D";
pub const MSG_TYPE_EXECUTION_REPORT: &[u8] = b"8";
pub const MSG_TYPE_ORDER_CANCEL_REJECT: &[u8] = b"9";
pub const MSG_TYPE_REJECT: &[u8] = b"3"; // session-level reject
pub const MSG_TYPE_BUSINESS_MESSAGE_REJECT: &[u8] = b"j";

// OrdStatus (39) values used by the fault rules.
pub const ORD_STATUS_NEW: &[u8] = b"0";
pub const ORD_STATUS_PARTIALLY_FILLED: &[u8] = b"1";
pub const ORD_STATUS_FILLED: &[u8] = b"2";
pub const ORD_STATUS_REJECTED: &[u8] = b"8";

// ExecType (150) values used by the fault rules.
pub const EXEC_TYPE_NEW: &[u8] = b"0";
pub const EXEC_TYPE_TRADE: &[u8] = b"F";
pub const EXEC_TYPE_REJECTED: &[u8] = b"8";
