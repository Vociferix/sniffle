use sniffle::prelude::*;
use std::io::Write;

fn dump<S: Sniff>(mut sniffer: S) -> Result<(), SniffError> {
    let stdout = std::io::stdout();
    let mut dumper = LogDumper::new(stdout.lock());
    let mut first = true;
    for pkt in sniffer.iter() {
        if !first {
            writeln!(dumper.as_inner_mut().as_inner_mut())?;
        } else {
            first = false;
        }
        pkt?.dump(&mut dumper)?;
    }
    Ok(())
}

fn main() -> Result<(), SniffError> {
    let src = std::env::args().nth(1).unwrap_or_else(|| {
        panic!("Expected one argument of either an interface name or a capture file path");
    });
    match Device::lookup(&src[..]) {
        Some(dev) => {
            let sniffer = DeviceSnifferConfig::create(dev)
                .promiscuous_mode(true)
                .immediate_mode(true)
                .open()?;
            dump(sniffer)
        }
        None => dump(FileSniffer::open(&src[..], None)?),
    }
}
