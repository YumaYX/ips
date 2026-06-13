use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

// Determines if two CIDRs overlap
pub(crate) fn cidr_overlap(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    // Starting address of A
    let a_start = u32::from(a.network());

    // Ending address (broadcast) of A
    let a_end = u32::from(a.broadcast());

    // Starting address of B
    let b_start = u32::from(b.network());

    // Ending address (broadcast) of B
    let b_end = u32::from(b.broadcast());

    // Overlap check for the ranges
    a_start <= b_end && b_start <= a_end
}

// Converts a range from start IP to end IP into a minimal set of CIDRs
pub(crate) fn range_to_cidrs(start: Ipv4Addr, end: Ipv4Addr) -> Vec<Ipv4Net> {
    let mut out = vec![];

    // Currently processing address
    let mut cur = u32::from(start);

    // End address (as u32)
    let end_u32 = u32::from(end);

    while cur <= end_u32 {
        // Maximum possible block size at the current position
        let max_size = cur & (!cur + 1);

        // Remaining address count to cover
        let remaining = end_u32 - cur + 1;

        let mut size = max_size;

        // Shrink if the block size exceeds the remaining range
        while size > remaining {
            size >>= 1;
        }

        // Calculate CIDR prefix from the block size
        let prefix = 32 - size.trailing_zeros() as u8;

        // Add as a CIDR
        out.push(Ipv4Net::new(Ipv4Addr::from(cur), prefix).unwrap());

        // Move to the next range
        cur += size;
    }

    out
}

// Expands a wildcard mask representation into a set of CIDRs
pub(crate) fn wildcard_to_cidrs(base: Ipv4Addr, wildcard: Ipv4Addr) -> Vec<Ipv4Net> {
    let base = u32::from(base);
    let wc = u32::from(wildcard);

    // Recursively expands the wildcard bits
    fn recurse(base: u32, wc: u32, prefix: u8, out: &mut Vec<Ipv4Net>) {
        if prefix == 32 {
            out.push(Ipv4Net::new(Ipv4Addr::from(base), 32).unwrap());
            return;
        }

        let remaining_bits = 32 - prefix;

        // 残りの wildcard が全部 1 なら CIDR 化できる
        let remaining_mask = if remaining_bits == 32 {
            u32::MAX
        } else {
            (1u32 << remaining_bits) - 1
        };

        if wc & remaining_mask == remaining_mask {
            out.push(Ipv4Net::new(Ipv4Addr::from(base), prefix).unwrap());
            return;
        }

        let bit = 1u32 << (31 - prefix);

        if wc & bit == 0 {
            recurse(base, wc, prefix + 1, out);
        } else {
            recurse(base, wc, prefix + 1, out);
            recurse(base | bit, wc, prefix + 1, out);
        }
    }

    let mut out = vec![];

    // Start expansion from the most significant bit
    recurse(base, wc, 0, &mut out);

    out
}

#[cfg(test)]
mod tests {
    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    use super::*;

    #[test]
    fn test_wildcard_zero() {
        let cidrs = wildcard_to_cidrs(ip("10.0.0.1"), ip("0.0.0.0"));

        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].to_string(), "10.0.0.1/32");
    }

    #[test]
    fn test_wildcard_24() {
        let cidrs = wildcard_to_cidrs(ip("10.0.0.0"), ip("0.0.0.255"));

        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].to_string(), "10.0.0.0/24");
    }

    #[test]
    fn test_wildcard_16() {
        let cidrs = wildcard_to_cidrs(ip("10.0.0.0"), ip("0.0.255.255"));

        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].to_string(), "10.0.0.0/16");
    }

    #[test]
    fn test_wildcard_31() {
        let cidrs = wildcard_to_cidrs(ip("10.0.0.0"), ip("0.0.0.1"));

        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].to_string(), "10.0.0.0/31");
    }

    #[test]
    fn test_wildcard_contains_addresses() {
        let cidrs = wildcard_to_cidrs(ip("10.0.0.0"), ip("0.0.0.5"));

        assert!(cidrs.iter().any(|n| n.contains(&ip("10.0.0.0"))));
        assert!(cidrs.iter().any(|n| n.contains(&ip("10.0.0.1"))));
        assert!(cidrs.iter().any(|n| n.contains(&ip("10.0.0.4"))));
        assert!(cidrs.iter().any(|n| n.contains(&ip("10.0.0.5"))));

        assert!(!cidrs.iter().any(|n| n.contains(&ip("10.0.0.2"))));
        assert!(!cidrs.iter().any(|n| n.contains(&ip("10.0.0.3"))));
    }

    #[test]
    fn test_wildcard_full_ipv4_space() {
        let cidrs = wildcard_to_cidrs(ip("0.0.0.0"), ip("255.255.255.255"));

        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].to_string(), "0.0.0.0/0");
    }
}
