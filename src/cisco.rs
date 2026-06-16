use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

use crate::addressset::AddressSet;

#[derive(Debug, Clone, Copy)]
pub enum Action {
    Permit,
    Deny,
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Ip,
    Tcp,
    Udp,
    Icmp,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Permit => "permit",
            Self::Deny => "deny",
        }
    }
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }
}

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

pub fn render_rule(action: Action, protocol: Protocol, src: &Ipv4Net, dst: &Ipv4Net) -> String {
    format!(
        "{} {} {} {}",
        action.as_str(),
        protocol.as_str(),
        render_addr(src),
        render_addr(dst),
    )
}

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
