use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Represents potential errors encountered when parsing IP address specifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Indicates that the specified range format (e.g., `start-end`) is invalid
    /// or violates logical constraints (like start > end).
    InvalidRange,

    /// Indicates that the wildcard format (`base mask`) contains invalid components
    /// or too many parts.
    InvalidWildcard,

    /// Used when the input string does not match any recognized IP representation
    /// (IP address, CIDR, Range, or Wildcard).
    InvalidFormat,
}

/// Represents a parsed and standardized network address specification.
///
/// The input string can represent several distinct types of addresses:
/// a single IP, a CIDR block, a numerical range, or a wildcard broadcast scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedAddress {
    /// A single IPv4 address (e.g., "192.168.1.1").
    Ip(Ipv4Addr),

    /// An IPv4 CIDR network block (e.g., "192.168.1.0/24").
    Cidr(Ipv4Net),

    /// A simple inclusive range defined by two IP addresses
    /// (e.g., "192.168.1.10-192.168.1.20").
    Range(Ipv4Addr, Ipv4Addr),

    /// Represents a wildcard address specification in `base mask` format
    /// (e.g., "10.0.0.0 0.0.0.255").
    Wildcard(Ipv4Addr, Ipv4Addr),
}

/// Attempts to parse an input string into a canonical `ParsedAddress` representation.
///
/// The parsing follows a specific hierarchy of checks:
/// 1. IPv4 Address (single IP)
/// 2. CIDR Block (`/N`)
/// 3. Range (`start-end`)
/// 4. Wildcard (`base mask`)
///
/// Returns `Ok(ParsedAddress)` if parsing is successful, otherwise returns a detailed
/// `ParseError` describing the failure mode.
///
/// # Parameters
/// * `s`: The input string slice to be parsed.
///
/// # Errors
/// Returns `ParseError::InvalidFormat`, `ParseError::InvalidRange`, or `ParseError::InvalidWildcard`
/// if the format is incorrect, fails type conversion, or violates logical constraints.
pub fn parse(s: &str) -> Result<ParsedAddress, ParseError> {
    // Remove leading/trailing whitespace
    let s = s.trim();

    // Attempt IPv4 address check
    if let Ok(ip) = Ipv4Addr::from_str(s) {
        return Ok(ParsedAddress::Ip(ip));
    }

    // Attempt CIDR block check
    if let Ok(net) = Ipv4Net::from_str(s) {
        return Ok(ParsedAddress::Cidr(net));
    }

    // Attempt Range check
    if let Some((start, end)) = parse_range(s)? {
        return Ok(ParsedAddress::Range(start, end));
    }

    // Attempt Wildcard check
    if let Some((base, wildcard)) = parse_wildcard(s)? {
        return Ok(ParsedAddress::Wildcard(base, wildcard));
    }

    // Does not match any format
    Err(ParseError::InvalidFormat)
}

/// Private helper function to parse a range string `start-end`.
fn parse_range(s: &str) -> Result<Option<(Ipv4Addr, Ipv4Addr)>, ParseError> {
    // Must contain '-' to be considered a range
    let Some((start, end)) = s.split_once('-') else {
        return Ok(None);
    };

    // Starting IP
    let start = start
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| ParseError::InvalidRange)?;

    // Ending IP
    let end = end
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| ParseError::InvalidRange)?;

    // Start > End is invalid
    if u32::from(start) > u32::from(end) {
        return Err(ParseError::InvalidRange);
    }

    Ok(Some((start, end)))
}

/// Private helper function to parse a wildcard string `base mask`.
fn parse_wildcard(s: &str) -> Result<Option<(Ipv4Addr, Ipv4Addr)>, ParseError> {
    // Split by whitespace
    let mut parts = s.split_whitespace();

    // Base address
    let Some(base) = parts.next() else {
        return Ok(None);
    };

    // Wildcard mask
    let Some(mask) = parts.next() else {
        return Ok(None);
    };

    // Too many components/parts
    if parts.next().is_some() {
        return Err(ParseError::InvalidWildcard);
    }

    // Convert base address
    let base = base
        .parse::<Ipv4Addr>()
        .map_err(|_| ParseError::InvalidWildcard)?;

    // Convert wildcard mask
    let wildcard = mask
        .parse::<Ipv4Addr>()
        .map_err(|_| ParseError::InvalidWildcard)?;

    Ok(Some((base, wildcard)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // IP Check
    #[test]
    fn test_parse_ip() {
        let result = parse("192.168.1.1").unwrap();

        assert!(matches!(result, ParsedAddress::Ip(_)));
    }

    // CIDR Check
    #[test]
    fn test_parse_cidr() {
        let result = parse("192.168.1.0/24").unwrap();

        assert!(matches!(result, ParsedAddress::Cidr(_)));
    }

    // Range Check
    #[test]
    fn test_parse_range() {
        let result = parse("192.168.1.10-192.168.1.20").unwrap();

        assert!(matches!(result, ParsedAddress::Range(_, _)));
    }

    // Wildcard Check
    #[test]
    fn test_parse_wildcard() {
        let result = parse("10.0.0.0 0.0.0.255").unwrap();

        assert!(matches!(result, ParsedAddress::Wildcard(_, _)));
    }

    // Invalid Input
    #[test]
    fn test_parse_invalid() {
        assert!(parse("xxx").is_err());
    }

    // Empty string
    #[test]
    fn test_parse_empty() {
        assert!(parse("").is_err());
    }

    // Reverse Range
    #[test]
    fn test_parse_reverse_range() {
        assert!(parse("192.168.1.20-192.168.1.10").is_err());
    }

    // Invalid Range Start Address
    #[test]
    fn test_parse_invalid_range_start() {
        assert!(parse("aaa-192.168.1.10").is_err());
    }

    // Invalid Range End Address
    #[test]
    fn test_parse_invalid_range_end() {
        assert!(parse("192.168.1.10-bbb").is_err());
    }

    // Invalid Wildcard
    #[test]
    fn test_parse_invalid_wildcard() {
        assert!(parse("10.0.0.0 xxx").is_err());
    }

    // Too many parts/components
    #[test]
    fn test_parse_too_many_parts() {
        assert!(parse("10.0.0.0 0.0.0.255 extra").is_err());
    }

    // Verify IP value
    #[test]
    fn test_parse_ip_exact_value() {
        let result = parse("192.168.1.1").unwrap();

        match result {
            ParsedAddress::Ip(ip) => {
                assert_eq!(ip, "192.168.1.1".parse::<Ipv4Addr>().unwrap());
            }
            _ => panic!(),
        }
    }

    // Verify CIDR value
    #[test]
    fn test_parse_cidr_exact_value() {
        let result = parse("192.168.1.0/24").unwrap();

        match result {
            ParsedAddress::Cidr(net) => {
                assert_eq!(net.to_string(), "192.168.1.0/24");
            }
            _ => panic!(),
        }
    }
}
