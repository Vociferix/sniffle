use super::{Error, LinkType, Packet, RawPacket};
use async_trait::async_trait;

#[async_trait]
pub trait Transmit: Send {
    async fn transmit_raw(&mut self, packet: RawPacket<'_>) -> Result<(), Error>;

    fn transmission_buffer(&mut self) -> Option<&mut Vec<u8>> {
        None
    }

    async fn transmit_as(&mut self, packet: &Packet, datalink: LinkType) -> Result<(), Error> {
        let mut has_buffer = false;
        let mut buf = match self.transmission_buffer() {
            Some(buf) => {
                has_buffer = true;
                buf.clear();
                std::mem::take(buf)
            }
            None => Vec::new(),
        };
        let res = self
            .transmit_raw(packet.make_raw_with_datalink(&mut buf, datalink)?)
            .await;
        if has_buffer {
            if let Some(tbuf) = self.transmission_buffer() {
                *tbuf = buf;
            }
        }
        res
    }

    async fn transmit(&mut self, packet: &Packet) -> Result<(), Error> {
        if let Some(datalink) = packet.datalink() {
            return self.transmit_as(packet, datalink).await;
        }
        Err(Error::UnknownLinkType)
    }
}
