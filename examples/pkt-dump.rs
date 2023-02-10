use sniffle::prelude::*;
use sniffle::Error;
use tokio::io::AsyncWriteExt;

async fn dump<S: Sniff>(mut sniffer: S) -> Result<(), Error> {
    let mut dumper = LogDumper::new(tokio::io::stdout());
    let mut first = true;
    while let Some(pkt) = sniffer.sniff().await? {
        if !first {
            dumper.as_inner_mut().write_all(b"\n").await?;
        } else {
            first = false;
        }
        dumper.dump(&pkt).await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let src = std::env::args().nth(1).unwrap_or_else(|| {
        panic!("Expected one argument of either an interface name or a capture file path");
    });
    match Device::lookup(&src[..]) {
        Some(dev) => {
            let sniffer = DeviceSnifferConfig::create(dev)
                .promiscuous_mode(true)
                .immediate_mode(true)
                .open()?;
            dump(sniffer).await
        }
        None => dump(FileSniffer::open(&src[..]).await?).await,
    }
}
