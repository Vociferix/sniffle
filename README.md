# Sniffle

[API Docs](https://vociferix.github.io/docs/sniffle/sniffle/)

Sniffle is a library for parsing and crafting network packets in real time. Inspiration is
taken from a variety of existing tools and libraries, but most importantly: Wireshark (C),
Scapy (Python), and libtins (C++). Although Sniffle supports packet crafting (and thus,
potentially development of malicious software), its primary motivation is to bring the
combined safety and performance of Rust to network security applications.

Sniffle uses the Tokio `async` runtime since packet sniffing and injection is an I/O
heavy endeavor. Sniffle can be added to any project as follows in `Cargo.toml`:

> **NOTE:** Sniffle is not yet available on crates.io. The below is currnetly expositional.

```toml
[dependencies]
sniffle = "0.1"
tokio = "1.25"
```

## Sniffing Example
```rust no_run
use sniffle::prelude::*;

#[tokio::main]
async fn main() -> Result<(), SniffleError> {
    let device = Device::try_default().expect("No default network interface found!");
    let mut sniffer = DeviceSnifferConfig::create(device)
        .promiscuous_mode(true)
        .immediate_mode(true)
        .open()?;
    let mut dumper = LogDumper::new(tokio::io::stdout());

    while let Some(pkt) = sniffer.sniff().await? {
        dumper.dump(&pkt).await?;
    }

    Ok(())
}
```
