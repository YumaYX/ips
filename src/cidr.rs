//! This module provides utility functions for working with CIDR blocks and IP ranges.
//!
//! It includes logic for detecting overlap between two CIDR networks and
//! converting a contiguous range of IP addresses into the minimal set of CIDR blocks.

use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

/// Checks if one CIDR network is a subset of another.
///
/// This function returns `true` if network `b` is entirely contained within network `a`.
///
/// # Examples
///
/// ```
/// // This is internal (pub(crate)), but for documentation purposes:
/// // let a: Ipv4Net = "10.0.0.0/24".parse().unwrap();
/// // let b: Ipv4Net = "10.0.0.128/25".parse().unwrap();
/// // assert!(cidr_overlap(&a, &b));
/// ```
pub(crate) fn cidr_overlap(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    let a_start = u32::from(a.network());
    let a_end = u32::from(a.broadcast());

    let b_start = u32::from(b.network());
    let b_end = u32::from(b.broadcast());

    a_start <= b_start && b_end <= a_end
}

/// Converts a contiguous range of IPv4 addresses into a list of CIDR blocks.
///
/// This function uses a greedy algorithm to find the largest possible CIDR blocks
/// that fit within the specified range, ensuring the resulting list is minimal.
///
/// If the `start` address is greater than the `end` address, an empty vector is returned.
///
/// # Examples
///
/// ```
/// // let cidrs = range_to_cidrs("192.168.1.0".parse().unwrap(), "192.168.1.255".parse().unwrap());
/// // assert_eq!(cidrs.len(), 1);
/// // assert_eq!(cidrs[0].to_string(), "192.168.1.0/24");
/// ```
pub(crate) fn range_to_cidrs(start: Ipv4Addr, end: Ipv4Addr) -> Vec<Ipv4Net> {
    let mut result = Vec::new();

    let mut current = u32::from(start);
    let end = u32::from(end);

    if current > end {
        return result;
    }

    while current <= end {
        let mut prefix = 32;

        loop {
            if prefix == 0 {
                break;
            }

            let candidate = prefix - 1;
            let block_size = 1u64 << (32 - candidate);

            let aligned = (current as u64).is_multiple_of(block_size);
            let fits = (current as u64) + block_size - 1 <= end as u64;

            if aligned && fits {
                prefix = candidate;
            } else {
                break;
            }
        }

        result.push(Ipv4Net::new(Ipv4Addr::from(current), prefix).unwrap());

        if prefix == 0 {
            break;
        }

        let block_size = 1u32 << (32 - prefix);

        match current.checked_add(block_size) {
            Some(next) => current = next,
            None => break,
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_overlap_same_network() {
        let a: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let b: Ipv4Net = "10.0.0.0/24".parse().unwrap();

        assert!(cidr_overlap(&a, &b));
    }

    #[test]
    fn cidr_overlap_subset() {
        let a: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let b: Ipv4Net = "10.0.0.128/25".parse().unwrap();

        assert!(cidr_overlap(&a, &b));
    }

    #[test]
    fn cidr_overlap_disjoint() {
        let a: Ipv4Net = "10.0.0.0/25".parse().unwrap();
        let b: Ipv4Net = "10.0.0.128/25".parse().unwrap();

        assert!(!cidr_overlap(&a, &b));
    }

    #[test]
    fn range_single_host() {
        let cidrs = range_to_cidrs(ip("192.168.1.1"), ip("192.168.1.1"));

        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].to_string(), "192.168.1.1/32");
    }

    #[test]
    fn range_simple_cidr() {
        let cidrs = range_to_cidrs(ip("192.168.1.0"), ip("192.168.1.255"));

        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].to_string(), "192.168.1.0/24");
    }

    #[test]
    fn range_two_hosts() {
        let cidrs = range_to_cidrs(ip("10.0.0.0"), ip("10.0.0.1"));

        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].to_string(), "10.0.0.0/31");
    }

    #[test]
    fn range_zero_address() {
        let cidrs = range_to_cidrs(ip("0.0.0.0"), ip("0.0.0.0"));

        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].to_string(), "0.0.0.0/32");
    }

    #[test]
    fn range_full_ipv4_space() {
        let cidrs = range_to_cidrs(ip("0.0.0.0"), ip("255.255.255.255"));

        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].to_string(), "0.0.0.0/0");
    }

    #[test]
    fn range_non_aligned() {
        let cidrs = range_to_cidrs(ip("10.0.0.10"), ip("10.0.0.20"));
        assert_eq!(cidrs.len(), 4);

        for addr in 10..=20 {
            assert!(
                cidrs
                    .iter()
                    .any(|n| { n.contains(&ip(&format!("10.0.0.{addr}"))) })
            );
        }

        assert!(!cidrs.iter().any(|n| { n.contains(&ip("10.0.0.21")) }));
    }
}
