//! This module provides the [`AddressSet`] type, which represents a set of IPv4 addresses.
//!
//! An `AddressSet` can be constructed from various formats (IP, CIDR, range, netmask)
//! and provides efficient methods for checking inclusion and merging sets.
//! It automatically normalizes the underlying representation to use the minimal
//! number of CIDR blocks.

use crate::cidr::{cidr_overlap, range_to_cidrs};
use crate::ipparse::parse;
pub use crate::ipparse::{ParseError, ParsedAddress};

use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

/// A set of IPv4 addresses, represented internally as a minimal collection of CIDR blocks.
///
/// `AddressSet` allows you to handle networks of any shape, from a single IP
/// to multiple disjoint ranges and CIDRs.
#[derive(Debug, Clone)]
pub struct AddressSet {
    cidrs: Vec<Ipv4Net>,
}

impl AddressSet {
    /// Parses a string into an [`AddressSet`].
    ///
    /// The string can be a single IP, a CIDR block, a range, or a netmask.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the string format is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use ips::addressset::AddressSet;
    ///
    /// let set = AddressSet::parse("192.168.1.0/24").unwrap();
    /// assert!(set.contains_ip("192.168.1.1".parse().unwrap()));
    /// ```
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        parse(s)?.try_into()
    }

    /// Creates an empty [`AddressSet`].
    pub fn empty() -> Self {
        Self { cidrs: vec![] }
    }

    /// Creates an [`AddressSet`] containing a single IPv4 address.
    pub fn from_ip(ip: Ipv4Addr) -> Self {
        Self {
            cidrs: vec![Ipv4Net::new(ip, 32).unwrap()],
        }
    }

    /// Creates an [`AddressSet`] from a CIDR network.
    pub fn from_cidr(net: Ipv4Net) -> Self {
        let net = Ipv4Net::new(net.network(), net.prefix_len()).unwrap();

        Self { cidrs: vec![net] }
    }

    /// Creates an [`AddressSet`] from a range of IPv4 addresses.
    ///
    /// The range is inclusive of both `start` and `end` addresses.
    pub fn from_range(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self {
            cidrs: range_to_cidrs(start, end),
        }
    }

    /// Creates an [`AddressSet`] from a base address and a subnet mask.
    ///
    /// # Panics
    ///
    /// Panics if the provided `mask` is not a valid contiguous subnet mask.
    pub fn from_netmask(base: Ipv4Addr, mask: Ipv4Addr) -> Self {
        let mask_u32 = u32::from(mask);

        let prefix = mask_u32.leading_ones() as u8;

        let reconstructed = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };

        assert_eq!(mask_u32, reconstructed, "invalid subnet mask: {}", mask);

        let network = Ipv4Addr::from(u32::from(base) & mask_u32);

        Self::from_cidr(
            Ipv4Net::new(network, prefix)
                .expect("validated netmask should always produce valid CIDR"),
        )
    }

    /// Returns `true` if the given IP address is contained within the set.
    pub fn contains_ip(&self, ip: Ipv4Addr) -> bool {
        self.cidrs.iter().any(|net| net.contains(&ip))
    }

    /// Returns `true` if the given [`AddressSet`] is a subset of this set.
    pub fn contains(&self, other: &Self) -> bool {
        other.cidrs.iter().all(|b| {
            self.cidrs.iter().any(|a| {
                let a_start = u32::from(a.network());
                let a_end = u32::from(a.broadcast());

                let b_start = u32::from(b.network());
                let b_end = u32::from(b.broadcast());

                a_start <= b_start && b_end <= a_end
            })
        })
    }

    /// Merges another [`AddressSet`] into this one and normalizes the result.
    pub fn insert(&mut self, other: AddressSet) {
        self.cidrs.extend(other.cidrs);
        self.normalize();
    }

    /// Returns a slice of the CIDR blocks that represent this set.
    pub fn cidrs(&self) -> &[Ipv4Net] {
        &self.cidrs
    }

    /// Returns the single IP address contained in the set, if it consists of exactly one host.
    ///
    /// Returns `None` if the set is empty, contains multiple addresses, or is a network larger than /32.
    pub fn host(&self) -> Option<Ipv4Addr> {
        if self.cidrs.len() != 1 {
            return None;
        }

        let net = &self.cidrs[0];

        if net.prefix_len() == 32 {
            Some(net.addr())
        } else {
            None
        }
    }

    /// Normalizes the internal representation of the set.
    ///
    /// This process involves:
    /// 1. Sorting the CIDR blocks.
    /// 2. Removing redundant blocks (subsets of others).
    /// 3. Merging adjacent blocks into larger CIDRs where possible.
    pub fn normalize(&mut self) {
        loop {
            let before = self.cidrs.len();

            self.cidrs.sort_by_key(|n| u32::from(n.network()));

            let mut out = Vec::new();

            for net in self.cidrs.iter().copied() {
                let mut current = net;

                let mut i = 0;

                while i < out.len() {
                    let existing = out[i];

                    if cidr_overlap(&existing, &current) {
                        current = existing;
                        out.remove(i);
                        continue;
                    }

                    if cidr_overlap(&current, &existing) {
                        out.remove(i);
                        continue;
                    }

                    if let Some(merged) = try_merge(&existing, &current) {
                        current = merged;
                        out.remove(i);
                        i = 0;
                        continue;
                    }

                    i += 1;
                }

                out.push(current);
            }

            self.cidrs = out;

            if self.cidrs.len() == before {
                break;
            }
        }
    }
}

fn try_merge(a: &Ipv4Net, b: &Ipv4Net) -> Option<Ipv4Net> {
    if a.prefix_len() != b.prefix_len() {
        return None;
    }

    let prefix = a.prefix_len();

    if prefix == 0 {
        return None;
    }

    let a_start = u32::from(a.network());
    let b_start = u32::from(b.network());

    let block_size = 1u32 << (32 - prefix);

    let adjacent = a_start + block_size == b_start || b_start + block_size == a_start;

    if !adjacent {
        return None;
    }

    let min = a_start.min(b_start);

    let supernet_size = block_size * 2;

    // 親CIDR境界に揃っているか確認
    if min % supernet_size != 0 {
        return None;
    }

    let new_prefix = prefix - 1;

    Ipv4Net::new(Ipv4Addr::from(min), new_prefix).ok()
}

impl TryFrom<ParsedAddress> for AddressSet {
    type Error = ParseError;

    fn try_from(value: ParsedAddress) -> Result<Self, Self::Error> {
        Ok(match value {
            ParsedAddress::Ip(ip) => Self::from_ip(ip),
            ParsedAddress::Cidr(net) => Self::from_cidr(net),
            ParsedAddress::Range(start, end) => Self::from_range(start, end),
            ParsedAddress::Netmask(base, mask) => Self::from_netmask(base, mask),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_host() {
        let a = AddressSet::from_ip("192.168.1.1".parse().unwrap());
        assert!(a.contains_ip("192.168.1.1".parse().unwrap()));
        assert!(!a.contains_ip("192.168.1.2".parse().unwrap()));
    }
    #[test]
    fn test_contains_cidr() {
        let a = AddressSet::from_cidr("192.168.1.0/24".parse().unwrap());
        assert!(a.contains_ip("192.168.1.10".parse().unwrap()));
        assert!(a.contains_ip("192.168.1.255".parse().unwrap()));
        assert!(!a.contains_ip("192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn test_range_contains() {
        let a = AddressSet::from_range(
            "192.168.1.10".parse().unwrap(),
            "192.168.1.20".parse().unwrap(),
        );

        assert!(a.contains_ip("192.168.1.10".parse().unwrap()));
        assert!(a.contains_ip("192.168.1.15".parse().unwrap()));
        assert!(a.contains_ip("192.168.1.20".parse().unwrap()));
        assert!(!a.contains_ip("192.168.1.21".parse().unwrap()));
    }

    #[test]
    fn test_contains() {
        let a = AddressSet::from_cidr("192.168.1.0/24".parse().unwrap());
        let b = AddressSet::from_cidr("192.168.1.128/25".parse().unwrap());
        assert!(a.contains(&b));
        assert!(!b.contains(&a));
    }

    #[test]
    fn test_host_subset() {
        let a = AddressSet::from_cidr("192.168.1.0/24".parse().unwrap());
        let b = AddressSet::from_ip("192.168.1.1".parse().unwrap());
        assert!(a.contains(&b));
    }

    #[test]
    fn test_parse_ip() {
        let set = AddressSet::parse("192.168.1.1").unwrap();
        assert!(set.contains_ip("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_parse_cidr() {
        let set = AddressSet::parse("192.168.1.0/24").unwrap();
        assert!(set.contains_ip("192.168.1.100".parse().unwrap()));
    }

    #[test]
    fn test_parse_range() {
        let set = AddressSet::parse("192.168.1.10-192.168.1.20").unwrap();
        assert!(set.contains_ip("192.168.1.15".parse().unwrap()));
    }

    #[test]
    fn test_parse_netmask() {
        let set = AddressSet::parse("10.0.0.1 255.255.255.0").unwrap();
        assert!(set.contains_ip("10.0.0.100".parse().unwrap()));
    }

    #[test]
    fn test_invalid_netmask() {
        assert!(AddressSet::parse("10.0.0.0 255.0.255.0").is_err());
    }

    #[test]
    fn test_parse_invalid() {
        assert!(AddressSet::parse("xxx").is_err());
    }

    #[test]
    fn test_parse_reverse_range() {
        assert!(AddressSet::parse("192.168.1.20-192.168.1.10").is_err());
    }

    fn net(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }

    #[test]
    fn test_normalize_remove_duplicates() {
        let mut s = AddressSet {
            cidrs: vec![net("10.0.0.0/24"), net("10.0.0.0/24")],
        };
        s.normalize();
        assert_eq!(s.cidrs.len(), 1);
    }

    #[test]
    fn test_normalize_containment() {
        let mut s = AddressSet {
            cidrs: vec![net("10.0.0.0/16"), net("10.0.1.0/24")],
        };
        s.normalize();
        assert_eq!(s.cidrs.len(), 1);
        assert_eq!(s.cidrs[0].to_string(), "10.0.0.0/16");
    }

    #[test]
    fn test_normalize_merge_adjacent() {
        let mut s = AddressSet {
            cidrs: vec![net("192.168.1.0/25"), net("192.168.1.128/25")],
        };
        s.normalize();
        assert_eq!(s.cidrs.len(), 1);
        assert_eq!(s.cidrs[0].to_string(), "192.168.1.0/24");
    }

    #[test]
    fn test_normalize_order_independence() {
        let mut s = AddressSet {
            cidrs: vec![net("10.0.1.0/24"), net("10.0.0.0/16"), net("10.0.0.0/23")],
        };
        s.normalize();
        assert_eq!(s.cidrs.len(), 1);
        assert_eq!(s.cidrs[0].to_string(), "10.0.0.0/16");
    }

    #[test]
    fn normalize_removes_duplicate_networks() {
        let mut set = AddressSet::empty();
        set.insert(AddressSet::from_cidr("10.0.0.0/24".parse().unwrap()));
        set.insert(AddressSet::from_cidr("10.0.0.0/24".parse().unwrap()));
        set.normalize();
        assert_eq!(set.cidrs().len(), 1);
    }

    #[test]
    fn normalize_removes_contained_networks() {
        let mut set = AddressSet::empty();
        set.insert(AddressSet::from_cidr("10.0.0.0/24".parse().unwrap()));
        set.insert(AddressSet::from_cidr("10.0.0.128/25".parse().unwrap()));
        set.normalize();
        assert_eq!(set.cidrs().len(), 1);
        assert_eq!(set.cidrs()[0].to_string(), "10.0.0.0/24");
    }

    #[test]
    fn normalize_keeps_disjoint_networks() {
        let mut set = AddressSet::empty();
        set.insert(AddressSet::from_cidr("10.0.0.0/25".parse().unwrap()));
        set.insert(AddressSet::from_cidr("10.0.0.128/25".parse().unwrap()));
        set.normalize();
        assert_eq!(set.cidrs().len(), 1);
    }
}
