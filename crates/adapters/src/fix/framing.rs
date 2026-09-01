use super::message::ParseError;

const SOH: u8 = 0x01;

// Looks for one complete FIX message at the start of `buf`. Returns the
// length of that message (from the first byte of "8=" through the SOH that
// ends the "10=XXX" checksum field) if the buffer holds one, or None if
// more bytes are needed.
//
// Assumes `buf` starts exactly at a message boundary, a caller that always
// consumes exactly the returned length on success maintains that
// invariant. Doesn't scan forward to resync after garbage, an out-of-sync
// stream is a protocol violation this surfaces as an error rather than
// silently guessing where the next message might start.
pub fn find_complete_message(buf: &[u8]) -> Result<Option<usize>, ParseError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    if !buf.starts_with(b"8=") {
        return Err(ParseError::MalformedTag);
    }

    let Some(tag8_end) = buf.iter().position(|&b| b == SOH) else {
        return Ok(None); // BeginString not fully received yet
    };

    let rest = &buf[tag8_end + 1..];
    if rest.len() >= 2 && !rest.starts_with(b"9=") {
        return Err(ParseError::MalformedTag); // tag 9 must immediately follow tag 8
    }

    let Some(tag9_end_rel) = rest.iter().position(|&b| b == SOH) else {
        return Ok(None); // BodyLength not fully received yet
    };

    let body_length_str =
        std::str::from_utf8(&rest[2..tag9_end_rel]).map_err(|_| ParseError::MalformedTag)?;
    let body_length: usize = body_length_str.parse().map_err(|_| ParseError::MalformedTag)?;

    let header_len = tag8_end + 1 + tag9_end_rel + 1; // through the SOH ending tag 9
    let checksum_trailer_len = 7; // "10=" + 3 digits + SOH, fixed width per spec
    let total_len = header_len + body_length + checksum_trailer_len;

    if buf.len() < total_len {
        return Ok(None);
    }

    Ok(Some(total_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_message() -> Vec<u8> {
        let with_pipes = "8=FIX.4.2|9=65|35=A|49=SERVER|56=CLIENT|34=177|52=20090107-18:15:16|98=0|108=30|10=062|";
        with_pipes.bytes().map(|b| if b == b'|' { SOH } else { b }).collect()
    }

    #[test]
    fn finds_exact_length_of_a_single_complete_message() {
        let msg = reference_message();
        let found = find_complete_message(&msg).unwrap().unwrap();
        assert_eq!(found, msg.len());
    }

    #[test]
    fn finds_only_the_first_of_two_concatenated_messages() {
        let one = reference_message();
        let mut two = one.clone();
        two.extend_from_slice(&one);

        let found = find_complete_message(&two).unwrap().unwrap();
        assert_eq!(found, one.len());

        // and the remainder is itself a complete, correctly framed message
        let remainder = &two[found..];
        let found_again = find_complete_message(remainder).unwrap().unwrap();
        assert_eq!(found_again, one.len());
    }

    #[test]
    fn returns_none_for_a_truncated_message() {
        let msg = reference_message();
        let truncated = &msg[..msg.len() - 10];
        assert_eq!(find_complete_message(truncated).unwrap(), None);
    }

    #[test]
    fn returns_none_for_just_a_partial_begin_string() {
        assert_eq!(find_complete_message(b"8=FIX.4").unwrap(), None);
    }

    #[test]
    fn rejects_a_buffer_not_starting_with_tag_8() {
        assert!(find_complete_message(b"35=D\x01").is_err());
    }
}
