//! A robust library for managing sets of IP addresses using various notations, including CIDR blocks,
//! continuous ranges (e.g., start-end), single IPv4 addresses, and wildcards.
//!
//! It provides type-safe methods to parse address strings from multiple formats and perform standard set operations
//! such as checking containment or intersection between sets.

mod addressset;
pub mod ipparse;

use addressset::{cidr_overlap, range_to_cidrs, wildcard_to_cidrs};

use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

use ipparse::{ParseError, ParsedAddress};

/// Represents a collection of IP addresses defined by one or more distinct network notations.
///
/// Internally, the set stores its components as a vector of `ipnet::Ipv4Net` objects. This internal representation
/// standardizes the data structure and simplifies complex operations like containment checks and overlap detection.
#[derive(Debug, Clone)]
pub struct AddressSet {
    cidrs: Vec<Ipv4Net>,
}

impl AddressSet {
    /// Parses an address string into a complete `AddressSet`.
    ///
    /// The input string is highly flexible and can correctly represent several common IP notations:
    /// single IP addresses (e.g., "192.168.1.1"), CIDR blocks (e.g., "192.168.1.0/24"), ranges
    /// (e.g., "192.168.1.1-192.168.1.255"), or explicit wildcard notation (e.g., "10.0.0.0 0.0.0.255").
    ///
    /// # Arguments
    /// * `s` - The address string to parse.
    ///
    /// # Returns
    /// A `Result` containing the populated `AddressSet` or a `ParseError` if the input string format is invalid.
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        ipparse::parse(s)?.try_into()
    }

    /// Creates an empty `AddressSet` containing no addresses.
    pub fn empty() -> Self {
        Self { cidrs: vec![] }
    }

    /// Creates an `AddressSet` containing a single, specific IP address.
    pub fn from_ip(ip: Ipv4Addr) -> Self {
        Self {
            cidrs: vec![Ipv4Net::new(ip, 32).unwrap()],
        }
    }

    /// Creates an `AddressSet` containing a single network defined precisely by the provided CIDR block.
    pub fn from_cidr(net: Ipv4Net) -> Self {
        Self { cidrs: vec![net] }
    }

    /// Creates an `AddressSet` covering all addresses within a specified IP range (inclusive).
    ///
    /// This function automatically expands the continuous range into one or more minimal CIDR blocks.
    pub fn from_range(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self {
            cidrs: range_to_cidrs(start, end),
        }
    }

    /// Creates an `AddressSet` covering all addresses within a specified wildcard block.
    ///
    /// A wildcard block is defined by its starting base IP and the highest endpoint address of the range.
    pub fn from_wildcard(base: Ipv4Addr, wildcard: Ipv4Addr) -> Self {
        Self {
            cidrs: wildcard_to_cidrs(base, wildcard),
        }
    }

    /// Checks if a given single IP address is contained within the set.
    ///
    /// # Arguments
    /// * `ip` - The `Ipv4Addr` to check for containment.
    ///
    /// # Returns
    /// `true` if the IP belongs to any network segment stored in the set; otherwise, `false`.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        self.cidrs.iter().any(|net| net.contains(&ip))
    }

    /// Checks if this set overlaps with another provided address set.
    ///
    /// Overlap means that at least one common IP address exists between the two sets.
    pub fn intersects(&self, other: &Self) -> bool {
        self.cidrs
            .iter()
            .any(|a| other.cidrs.iter().any(|b| cidr_overlap(a, b)))
    }

    /// Checks if every address within the `other` set is fully contained (a subset of) this set (`self`).
    ///
    /// This performs a strict subset check: all components of `other` must be completely covered by networks in `self`.
    pub fn contains_set(&self, other: &Self) -> bool {
        other.cidrs.iter().all(|b| {
            self.cidrs.iter().any(|a| {
                // Simplified logic used for robust comparison (checking start/end bounds).
                let a_start = u32::from(a.network());
                let a_end = u32::from(a.broadcast());

                let b_start = u32::from(b.network());
                let b_end = u32::from(b.broadcast());

                // Check if network A fully encapsulates network B based on range bounds comparison.
                a_start <= b_start && b_end <= a_end
            })
        })
    }
}

impl TryFrom<ParsedAddress> for AddressSet {
    type Error = ParseError;

    /// Attempts to convert an `ipparse::ParsedAddress` object into a fully formed `AddressSet`.
    ///
    /// This conversion uses the type information embedded within `ParsedAddress` (e.g., IP, CIDR, Range, or Wildcard)
    /// to correctly initialize and construct the corresponding `AddressSet` structure.
    fn try_from(value: ParsedAddress) -> Result<Self, Self::Error> {
        Ok(match value {
            ParsedAddress::Ip(ip) => Self::from_ip(ip),
            ParsedAddress::Cidr(net) => Self::from_cidr(net),
            ParsedAddress::Range(start, end) => Self::from_range(start, end),
            ParsedAddress::Wildcard(base, wc) => Self::from_wildcard(base, wc),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_host() {
        let a = AddressSet::from_ip("192.168.1.1".parse().unwrap());

        assert!(a.contains("192.168.1.1".parse().unwrap()));

        assert!(!a.contains("192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_contains_cidr() {
        let a = AddressSet::from_cidr("192.168.1.0/24".parse().unwrap());

        assert!(a.contains("192.168.1.10".parse().unwrap()));

        assert!(a.contains("192.168.1.255".parse().unwrap()));

        assert!(!a.contains("192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn test_intersects_cidr() {
        let a = AddressSet::from_cidr("192.168.1.0/24".parse().unwrap());

        let b = AddressSet::from_cidr("192.168.1.128/25".parse().unwrap());

        assert!(a.intersects(&b));
    }

    #[test]
    fn test_disjoint_cidr() {
        let a = AddressSet::from_cidr("192.168.1.0/25".parse().unwrap());

        let b = AddressSet::from_cidr("192.168.1.128/25".parse().unwrap());

        assert!(!a.intersects(&b));
    }

    #[test]
    fn test_range_contains() {
        let a = AddressSet::from_range(
            "192.168.1.10".parse().unwrap(),
            "192.168.1.20".parse().unwrap(),
        );

        assert!(a.contains("192.168.1.10".parse().unwrap()));

        assert!(a.contains("192.168.1.15".parse().unwrap()));

        assert!(a.contains("192.168.1.20".parse().unwrap()));

        assert!(!a.contains("192.168.1.21".parse().unwrap()));
    }

    #[test]
    fn test_range_intersects() {
        let a = AddressSet::from_range(
            "192.168.1.10".parse().unwrap(),
            "192.168.1.20".parse().unwrap(),
        );

        let b = AddressSet::from_range(
            "192.168.1.15".parse().unwrap(),
            "192.168.1.30".parse().unwrap(),
        );

        assert!(a.intersects(&b));
    }

    #[test]
    fn test_range_disjoint() {
        let a = AddressSet::from_range(
            "192.168.1.10".parse().unwrap(),
            "192.168.1.20".parse().unwrap(),
        );

        let b = AddressSet::from_range(
            "192.168.1.21".parse().unwrap(),
            "192.168.1.30".parse().unwrap(),
        );

        assert!(!a.intersects(&b));
    }

    #[test]
    fn test_wildcard_contains() {
        let a =
            AddressSet::from_wildcard("10.0.0.0".parse().unwrap(), "0.0.0.255".parse().unwrap());

        assert!(a.contains("10.0.0.1".parse().unwrap()));

        assert!(a.contains("10.0.0.200".parse().unwrap()));

        assert!(!a.contains("10.0.1.1".parse().unwrap()));
    }

    #[test]
    fn test_wildcard_intersects() {
        let a =
            AddressSet::from_wildcard("10.0.0.0".parse().unwrap(), "0.0.0.255".parse().unwrap());

        let b = AddressSet::from_cidr("10.0.0.128/25".parse().unwrap());

        assert!(a.intersects(&b));
    }

    #[test]
    fn test_contains_set() {
        let a = AddressSet::from_cidr("192.168.1.0/24".parse().unwrap());

        let b = AddressSet::from_cidr("192.168.1.128/25".parse().unwrap());

        assert!(a.contains_set(&b));
        assert!(!b.contains_set(&a));
    }

    #[test]
    fn test_host_subset() {
        let a = AddressSet::from_cidr("192.168.1.0/24".parse().unwrap());

        let b = AddressSet::from_ip("192.168.1.1".parse().unwrap());

        assert!(a.contains_set(&b));
    }

    #[test]
    fn test_parse_ip() {
        let set = AddressSet::parse("192.168.1.1").unwrap();

        assert!(set.contains("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_parse_cidr() {
        let set = AddressSet::parse("192.168.1.0/24").unwrap();

        assert!(set.contains("192.168.1.100".parse().unwrap()));
    }

    #[test]
    fn test_parse_range() {
        let set = AddressSet::parse("192.168.1.10-192.168.1.20").unwrap();

        assert!(set.contains("192.168.1.15".parse().unwrap()));
    }

    #[test]
    fn test_parse_wildcard() {
        let set = AddressSet::parse("10.0.0.0 0.0.0.255").unwrap();

        assert!(set.contains("10.0.0.100".parse().unwrap()));
    }

    #[test]
    fn test_parse_invalid() {
        assert!(AddressSet::parse("xxx").is_err());
    }

    #[test]
    fn test_parse_reverse_range() {
        assert!(AddressSet::parse("192.168.1.20-192.168.1.10").is_err());
    }
}
