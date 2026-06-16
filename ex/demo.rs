use ips::{AddressSet, ParseError, product};

fn main() -> Result<(), ParseError> {
    let srcs = vec![
        AddressSet::parse("10.0.0.0/24")?,
        AddressSet::parse("10.1.1.1")?,
    ];

    let dsts = vec![
        AddressSet::parse("192.168.1.0/24")?,
        AddressSet::parse("192.168.2.10")?,
        AddressSet::parse("192.168.2.22 255.255.255.254")?,
    ];

    for rule in product(&srcs, &dsts) {
        println!("{}", rule.render());
    }

    Ok(())
}
