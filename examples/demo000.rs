use ips::addressset::AddressSet;

fn main() {
    println!("--- IPv4 AddressSet Demo ---");
    let formats = vec![
        ("Host", "192.168.1.1"),
        ("CIDR", "192.168.1.0/24"),
        ("Range", "192.168.1.10-192.168.1.20"),
        ("NetMask", "192.168.1.10 255.255.255.254"),
    ];

    for (name, value) in formats {
        match AddressSet::parse(value) {
            Ok(_) => println!("✅ Successfully parsed {}: {}", name, value),
            Err(e) => println!("❌ Failed to parse {}: {} ({:?})", name, value, e),
        }
    }
}
