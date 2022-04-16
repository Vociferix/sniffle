use sniffle::prelude::*;

fn main() {
    let mut first_dev = true;
    for dev in Device::all() {
        if !first_dev {
            println!();
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
            if let Some(mask) = addr.netmask() {
                print!("  mask: {}", mask);
            }
            if let Some(brd) = addr.broadcast() {
                print!("  brd: {}", brd);
            }
            if let Some(dst) = addr.destination() {
                print!("  dst: {}", dst);
            }
            println!();
        }
        for addr in dev.ipv6_addresses() {
            print!("  ipv6: {}", addr.address());
            if let Some(pl) = addr.prefix_length() {
                print!("  prefixlen: {}", pl);
            }
            println!();
        }
    }
}
