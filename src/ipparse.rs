use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    InvalidRange,
    InvalidNetmask,
    InvalidFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedAddress {
    Ip(Ipv4Addr),
    Cidr(Ipv4Net),
    Range(Ipv4Addr, Ipv4Addr),
    Netmask(Ipv4Addr, Ipv4Addr),
}

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

    if s.contains(' ') {
        let (base, mask) = parse_netmask(s)?;
        return Ok(ParsedAddress::Netmask(base, mask));
    }

    // Does not match any format
    Err(ParseError::InvalidFormat)
}

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

fn parse_netmask(s: &str) -> Result<(Ipv4Addr, Ipv4Addr), ParseError> {
    let mut parts = s.split_whitespace();

    let base = parts.next().ok_or(ParseError::InvalidNetmask)?;

    let mask = parts.next().ok_or(ParseError::InvalidNetmask)?;

    if parts.next().is_some() {
        return Err(ParseError::InvalidNetmask);
    }

    let base = base.parse().map_err(|_| ParseError::InvalidNetmask)?;

    let mask = mask.parse().map_err(|_| ParseError::InvalidNetmask)?;

    if !is_valid_subnet_mask(mask) {
        return Err(ParseError::InvalidNetmask);
    }

    Ok((base, mask))
}

fn is_valid_subnet_mask(mask: Ipv4Addr) -> bool {
    let m = u32::from(mask);

    let mut seen_zero = false;

    for bit in (0..32).rev() {
        let set = (m & (1 << bit)) != 0;

        if seen_zero && set {
            return false;
        }

        if !set {
            seen_zero = true;
        }
    }

    true
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

    // Too many parts/components
    #[test]
    fn test_parse_too_many_parts() {
        assert!(parse("10.0.0.0/8 extra").is_err());
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

    #[test]
    fn test_valid_subnet_masks() {
        assert!(is_valid_subnet_mask("255.0.0.0".parse().unwrap()));
        assert!(is_valid_subnet_mask("255.255.0.0".parse().unwrap()));
        assert!(is_valid_subnet_mask("255.255.255.0".parse().unwrap()));
        assert!(is_valid_subnet_mask("255.255.255.255".parse().unwrap()));
        assert!(is_valid_subnet_mask("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn test_invalid_subnet_masks() {
        assert!(!is_valid_subnet_mask("255.0.255.0".parse().unwrap()));
        assert!(!is_valid_subnet_mask("255.255.0.255".parse().unwrap()));
        assert!(!is_valid_subnet_mask("255.0.255.255".parse().unwrap()));
    }
}
