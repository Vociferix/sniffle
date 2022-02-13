use sniffle::prelude::*;

fn dump<S: Sniff>(mut sniffer: S) -> Result<(), SniffError> {
    let stdout = std::io::stdout();
    let mut dumper = DebugDumper::new(stdout.lock());
    for pkt in sniffer.iter() {
        pkt?.dump(&mut dumper)?;
    }
    Ok(())
}

fn main() -> Result<(), SniffError> {
    let src = std::env::args().skip(1).next().unwrap_or_else(|| {
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
