const SOH: u8 = 0x01;

// Read-only view over a parsed FIX message. Field order is preserved
// (Vec, not a map), set_field below relies on that to reconstruct a
// message with everything but the target tag's value unchanged.
#[derive(Debug)]
pub struct FixMessage<'a> {
    fields: Vec<(u32, &'a [u8])>,
}

impl<'a> FixMessage<'a> {
    // First value for a tag, order matters for repeating groups but none
    // of the fields this crate reads (35, 39, 150) are ever repeated, so
    // first-match is correct here.
    pub fn get(&self, tag: u32) -> Option<&'a [u8]> {
        self.fields.iter().find(|(t, _)| *t == tag).map(|(_, v)| *v)
    }

    pub fn is(&self, tag: u32, expected: &[u8]) -> bool {
        self.get(tag) == Some(expected)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    MissingSoh,
    MalformedTag,
}

// Parses SOH-delimited tag=value pairs. Doesn't validate BodyLength or
// checksum, that's framing's job (framing.rs) since it has to run before a
// complete message even exists to parse. Doesn't understand repeating
// groups, not needed for the fields this crate reads.
pub fn parse(bytes: &[u8]) -> Result<FixMessage<'_>, ParseError> {
    if bytes.is_empty() {
        return Err(ParseError::Empty);
    }

    let mut fields = Vec::new();
    for field in bytes.split(|&b| b == SOH) {
        if field.is_empty() {
            continue; // trailing SOH produces one empty split, not an error
        }
        let eq = field.iter().position(|&b| b == b'=').ok_or(ParseError::MalformedTag)?;
        let tag_str = std::str::from_utf8(&field[..eq]).map_err(|_| ParseError::MalformedTag)?;
        let tag: u32 = tag_str.parse().map_err(|_| ParseError::MalformedTag)?;
        fields.push((tag, &field[eq + 1..]));
    }

    if fields.is_empty() {
        return Err(ParseError::MissingSoh);
    }

    Ok(FixMessage { fields })
}

// Sum of every byte in the message (SOH bytes count as value 1 each) except
// the checksum field's own tag=value=SOH, mod 256, per the FIX spec.
// Callers pass everything up to and including the SOH before "10=".
pub fn compute_checksum(bytes_before_checksum_field: &[u8]) -> u8 {
    bytes_before_checksum_field
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b))
}

pub fn format_checksum(sum: u8) -> String {
    format!("{sum:03}")
}

// Re-encodes `bytes` with `tag`'s value replaced by `new_value`,
// recomputing BodyLength (9) and CheckSum (10) so the result is a valid,
// self-consistent FIX message, not just bytes that happen to look like
// one. BeginString (8) carries over unchanged. Mutating 8, 9, or 10
// directly through this isn't meaningful, they're structural and get
// recomputed regardless of what's passed for them. Caller's job to
// confirm `tag` is actually present first (FixExecutionReportPriceMutation
// does), this just leaves the message otherwise unchanged if it isn't,
// nothing to replace.
pub fn set_field(bytes: &[u8], tag: u32, new_value: &[u8]) -> Result<Vec<u8>, ParseError> {
    let parsed = parse(bytes)?;
    // framing.rs only ever hands parse() a message that already had a
    // well-formed "8=...\x019=NNN\x01" prefix, tag 8 missing here would
    // mean framing's own invariant broke, not something to recover from
    let begin_string = parsed
        .get(8)
        .expect("framed message always has tag 8, framing.rs guarantees it");

    let mut body = Vec::new();
    for &(t, v) in &parsed.fields {
        if t == 8 || t == 9 || t == 10 {
            continue; // structural, recomputed below, never copied verbatim
        }
        let value = if t == tag { new_value } else { v };
        body.extend_from_slice(t.to_string().as_bytes());
        body.push(b'=');
        body.extend_from_slice(value);
        body.push(SOH);
    }

    let mut full = Vec::new();
    full.extend_from_slice(b"8=");
    full.extend_from_slice(begin_string);
    full.push(SOH);
    full.extend_from_slice(format!("9={}", body.len()).as_bytes());
    full.push(SOH);
    full.extend_from_slice(&body);

    let checksum = compute_checksum(&full);
    full.extend_from_slice(format!("10={checksum:03}").as_bytes());
    full.push(SOH);

    Ok(full)
}

#[cfg(test)]
mod tests {
    use super::*;

    // From Wikipedia's FIX article, a real worked example with a known
    // correct checksum, not a message this crate invented:
    // 8=FIX.4.2|9=65|35=A|49=SERVER|56=CLIENT|34=177|52=20090107-18:15:16|98=0|108=30|10=062|
    fn reference_message() -> Vec<u8> {
        let with_pipes = "8=FIX.4.2|9=65|35=A|49=SERVER|56=CLIENT|34=177|52=20090107-18:15:16|98=0|108=30|10=062|";
        with_pipes.bytes().map(|b| if b == b'|' { SOH } else { b }).collect()
    }

    #[test]
    fn parses_reference_message_fields() {
        let raw = reference_message();
        let msg = parse(&raw).unwrap();
        assert!(msg.is(8, b"FIX.4.2"));
        assert!(msg.is(9, b"65"));
        assert!(msg.is(35, b"A"));
        assert!(msg.is(49, b"SERVER"));
        assert!(msg.is(56, b"CLIENT"));
        assert!(msg.is(10, b"062"));
    }

    #[test]
    fn checksum_matches_the_known_correct_value() {
        let full = reference_message();
        // everything up to and including the SOH right before "10="
        let checksum_field_start = full.windows(4).rposition(|w| w == [SOH, b'1', b'0', b'=']).unwrap() + 1;
        let sum = compute_checksum(&full[..checksum_field_start]);
        assert_eq!(format_checksum(sum), "062");
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(parse(&[]).unwrap_err(), ParseError::Empty);
    }

    #[test]
    fn rejects_field_without_equals() {
        let bad = b"35D\x01".to_vec();
        assert_eq!(parse(&bad).unwrap_err(), ParseError::MalformedTag);
    }

    #[test]
    fn set_field_replaces_the_value_and_recomputes_length_and_checksum() {
        let body = "35=8\x0139=1\x01150=F\x0144=100.50\x01";
        let header = format!("8=FIX.4.4\x019={}\x01", body.len());
        let mut original = format!("{header}{body}").into_bytes();
        let sum = compute_checksum(&original);
        original.extend_from_slice(format!("10={sum:03}\x01").as_bytes());

        let mutated = set_field(&original, 44, b"999.99").unwrap();
        let reparsed = parse(&mutated).unwrap();

        assert!(reparsed.is(44, b"999.99"));
        // everything else untouched
        assert!(reparsed.is(35, b"8"));
        assert!(reparsed.is(39, b"1"));
        assert!(reparsed.is(150, b"F"));
        assert!(reparsed.is(8, b"FIX.4.4"));

        // BodyLength and CheckSum are recomputed against the mutated
        // bytes, not just carried over from the original, verified
        // independently rather than trusting set_field's own arithmetic
        let tag9_value = reparsed.get(9).unwrap();
        let declared_body_len: usize = std::str::from_utf8(tag9_value).unwrap().parse().unwrap();
        let first_soh = mutated.iter().position(|&b| b == SOH).unwrap();
        let second_soh = first_soh + 1 + mutated[first_soh + 1..].iter().position(|&b| b == SOH).unwrap();
        let header_len = second_soh + 1; // through the SOH ending tag 9
        let checksum_field_start = mutated.windows(4).rposition(|w| w == [SOH, b'1', b'0', b'=']).unwrap() + 1;
        assert_eq!(declared_body_len, checksum_field_start - header_len);

        let expected_checksum = compute_checksum(&mutated[..checksum_field_start]);
        assert!(reparsed.is(10, format_checksum(expected_checksum).as_bytes()));
    }

    #[test]
    fn set_field_on_a_tag_not_present_leaves_the_message_otherwise_valid() {
        let original = reference_message();
        // tag 999 isn't in the reference message at all, set_field doesn't
        // require presence, just replaces zero occurrences
        let mutated = set_field(&original, 999, b"whatever").unwrap();
        let reparsed = parse(&mutated).unwrap();
        assert!(reparsed.get(999).is_none());
        assert!(reparsed.is(35, b"A")); // original fields still intact
    }
}
