use ips::addressset::{AddressSet, ParseError};
use ips::cisco::{Action, Protocol, render};

fn main() -> Result<(), ParseError> {
    let mut set = AddressSet::empty();
    set.insert(AddressSet::parse("10.0.0.1/32")?);
    set.insert(AddressSet::parse("10.0.0.3/32")?);

    let srcs = vec![set];

    let dsts = vec![
        AddressSet::parse("192.168.1.0/24")?,
        AddressSet::parse("192.168.2.10")?,
        AddressSet::parse("192.168.2.22 255.255.255.254")?,
    ];

    for line in render(Action::Permit, Protocol::Ip, &srcs, &dsts) {
        println!("{line}");
    }

    Ok(())
}
