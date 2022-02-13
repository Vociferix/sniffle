use sniffle::prelude::*;

fn main() {
    let mut first_dev = true;
    for dev in Device::all() {
        if !first_dev {
            println!("");
        }
        first_dev = false;
        let has_desc = if cfg!(windows) {
            let has_desc = match dev.description() {
                Some(desc) => {
                    print!("{}: ", desc);
                    true
                }
                None => {
                    print!("{}: ", dev.name());
                    false
                }
            };
            has_desc
        } else {
            print!("{}: ", dev.name());
            false
        };
        print!("<");
        let mut first = true;
        if dev.is_up() {
            first = false;
            print!("UP");
        }
        if dev.is_running() {
            if !first {
                print!(",");
            }
            first = false;
            print!("RUNNING");
        }
        if dev.is_loopback() {
            if !first {
                print!(",");
            }
            first = false;
            print!("LOOPBACK");
        }
        match dev.connection_status() {
            ConnectionStatus::Connected => {
                if !first {
                    print!(",");
                }
                print!("CONNECTED");
            }
            ConnectionStatus::Disconnected => {
                if !first {
                    print!(",");
                }
                print!("DISCONNECTED");
            }
            _ => {}
        }
        println!(">");
        if cfg!(windows) && has_desc {
            println!("  id: {}", dev.name());
        }
        for addr in dev.mac_addresses() {
            println!("  ether: {}", addr);
        }
        for addr in dev.ipv4_addresses() {
            print!("  ipv4: {}", addr.address());
            addr.netmask().map(|mask| print!("  mask: {}", mask));
            addr.broadcast().map(|brd| print!("  brd: {}", brd));
            addr.destination().map(|dst| print!("  dst: {}", dst));
            println!("");
        }
        for addr in dev.ipv6_addresses() {
            print!("  ipv6: {}", addr.address());
            addr.prefix_length().map(|pl| print!("  prefixlen: {}", pl));
            println!("");
        }
    }
}
