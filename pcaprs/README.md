Thin, safe wrapper around libpcap.

# Examples

```no_run
use pcaprs::{Pcap, Device};
use std::time::Duration;

let device = Device::default().unwrap();
let mut capture = Pcap::open_live(&device, 0xFFFF, true, Duration::from_secs(10)).unwrap();

println!("capturing on {}", device.name());

while let Some(packet) = capture.next_packet() {
    let packet = packet.unwrap();
    println!("{:?}", packet.data());
}
```
