//! This module provides utilities for generating Cisco IOS style access control list (ACL) rules.
//!
//! It translates `AddressSet` definitions into the specific string format required by Cisco
//! network devices, including the use of wildcard masks for networks and the `host` keyword for single IPs.

use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

use crate::addressset::AddressSet;

/// Specifies whether the network traffic should be allowed or blocked.
#[derive(Debug, Clone, Copy)]
pub enum Action {
    /// Allow the traffic.
    Permit,
    /// Block the traffic.
    Deny,
}

/// Represents the network protocol for the ACL rule.
#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    /// Internet Protocol.
    Ip,
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Internet Control Message Protocol.
    Icmp,
}

impl Action {
    /// Returns the string representation used in Cisco configuration files.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Permit => "permit",
            Self::Deny => "deny",
        }
    }
}

impl Protocol {
    /// Returns the string representation used in Cisco configuration files.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }
}

/// Generates all possible pairs of source and destination CIDR blocks from the provided sets.
///
/// This creates a Cartesian product of all CIDR blocks within the source and destination `AddressSet`s.
///
/// # Examples
///
/// ```
/// use ips::cisco::pairs;
/// use ips::addressset::AddressSet;
///
/// let src = [AddressSet::from_ip("1.1.1.1".parse().unwrap())];
/// let dst = [AddressSet::from_ip("2.2.2.2".parse().unwrap())];
/// let result = pairs(&src, &dst);
/// assert_eq!(result.len(), 1);
/// ```
pub fn pairs(srcs: &[AddressSet], dsts: &[AddressSet]) -> Vec<(Ipv4Net, Ipv4Net)> {
    let mut out = Vec::new();

    for src in srcs {
        for s in src.cidrs() {
            for dst in dsts {
                for d in dst.cidrs() {
                    out.push((*s, *d));
                }
            }
        }
    }

    out
}

/// Renders an `Ipv4Net` block into a Cisco-compatible address string.
///
/// Single hosts are rendered as `host <ip>`, while networks are rendered as
/// `<network_address> <wildcard_mask>`.
///
/// # Examples
///
/// ```
/// use ips::cisco::render_addr;
/// use ipnet::Ipv4Net;
///
/// let host: Ipv4Net = "1.1.1.1/32".parse().unwrap();
/// assert_eq!(render_addr(&host), "host 1.1.1.1");
///
/// let net: Ipv4Net = "192.168.1.0/24".parse().unwrap();
/// assert_eq!(render_addr(&net), "192.168.1.0 0.0.0.255");
/// ```
pub fn render_addr(net: &Ipv4Net) -> String {
    if net.prefix_len() == 32 {
        return format!("host {}", net.addr());
    }

    let mask = if net.prefix_len() == 0 {
        0
    } else {
        u32::MAX << (32 - net.prefix_len())
    };

    let wildcard = !mask;

    format!("{} {}", net.network(), Ipv4Addr::from(wildcard),)
}

/// Renders a single ACL rule into a string.
///
/// The format follows the standard Cisco IOS ACL structure:
/// `<action> <protocol> <source> <destination>`
pub fn render_rule(action: Action, protocol: Protocol, src: &Ipv4Net, dst: &Ipv4Net) -> String {
    format!(
        "{} {} {} {}",
        action.as_str(),
        protocol.as_str(),
        render_addr(src),
        render_addr(dst),
    )
}

/// Renders a list of ACL rules based on provided sets of source and destination addresses.
///
/// This function generates all combinations of source and destination blocks and renders
/// each as a Cisco ACL string.
///
/// # Examples
///
/// ```
/// use ips::cisco::{render, Action, Protocol};
/// use ips::addressset::AddressSet;
///
/// let srcs = [AddressSet::from_ip("1.1.1.1".parse().unwrap())];
/// let dsts = [AddressSet::from_ip("2.2.2.2".parse().unwrap())];
/// let rules = render(Action::Permit, Protocol::Ip, &srcs, &dsts);
/// assert_eq!(rules[0], "permit ip host 1.1.1.1 host 2.2.2.2");
/// ```
pub fn render(
    action: Action,
    protocol: Protocol,
    srcs: &[AddressSet],
    dsts: &[AddressSet],
) -> Vec<String> {
    pairs(srcs, dsts)
        .into_iter()
        .map(|(src, dst)| render_rule(action, protocol, &src, &dst))
        .collect()
}
