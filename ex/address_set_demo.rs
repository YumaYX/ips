use ips::AddressSet;
use std::net::Ipv4Addr;

fn main() {
    println!("--- IPv4 AddressSet Demo ---");

    // 1. Test parsing different formats
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

    // 2. Containment checks
    println!("\n--- Containment Checks ---");
    let network = AddressSet::parse("192.168.1.0/24").expect("Valid CIDR");
    let ip_inside: Ipv4Addr = "192.168.1.50".parse().unwrap();
    let ip_outside: Ipv4Addr = "192.168.2.1".parse().unwrap();

    println!(
        "Is {} in {}? {}",
        ip_inside,
        "192.168.1.0/24",
        network.contains(ip_inside)
    );
    println!(
        "Is {} in {}? {}",
        ip_outside,
        "192.168.1.0/24",
        network.contains(ip_outside)
    );

    // 3. Set Operations: Intersection
    println!("\n--- Intersection Checks ---");
    let set_a = AddressSet::parse("192.168.1.0/24").expect("Valid A");
    let set_b = AddressSet::parse("192.168.1.128/25").expect("Valid B");
    let set_c = AddressSet::parse("10.0.0.0/8").expect("Valid C");

    println!(
        "Set A (192.168.1.0/24) intersects Set B (192.168.1.128/25)? {}",
        set_a.intersects(&set_b)
    );
    println!(
        "Set A (192.168.1.0/24) intersects Set C (10.0.0.0/8)? {}",
        set_a.intersects(&set_c)
    );

    // 4. Set Operations: Subset/Containment
    println!("\n--- Subset Checks ---");
    println!("Does Set A contain Set B? {}", set_a.contains_set(&set_b));
    println!("Does Set B contain Set A? {}", set_b.contains_set(&set_a));
}
