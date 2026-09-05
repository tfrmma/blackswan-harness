const SOH: u8 = 0x01;

// Read-only view over a parsed FIX message. Doesn't own a serializer, none
// of the fault rules in this crate mutate a message, they only decide
// Forward/Drop, so the original bytes go out unchanged when forwarded.
// Add a serializer if a Mutate-based fault ever needs one, don't build it
// speculatively.
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
}
