use super::{LinkType, Packet, Pdu, RawPacket};
use async_trait::async_trait;
use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum TransmitError {
    #[error("Malformed capture")]
    MalformedCapture,
    #[error("Attempt to transmit packet without a valid link layer")]
    UnknownLinkType,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[cfg(feature = "pcaprs")]
    #[error(transparent)]
    Pcap(#[from] pcaprs::PcapError),
    #[error(transparent)]
    User(#[from] Box<dyn std::error::Error + 'static>),
}

#[async_trait]
pub trait Transmit {
    async fn transmit_raw(&mut self, packet: RawPacket<'_>) -> Result<(), TransmitError>;

    async fn transmit(&mut self, packet: &Packet) -> Result<(), TransmitError> {
        let mut buf = Vec::new();
        packet.pdu().serialize(&mut buf)?;
        let link_type = match LinkType::from_pdu(packet.pdu()) {
            Some(link_type) => link_type,
            None => {
                return Err(TransmitError::UnknownLinkType);
            }
        };
        self.transmit_raw(RawPacket::new(
            link_type,
            packet.timestamp(),
            packet.snaplen(),
            Some(packet.len()),
            &buf[..],
            packet.share_device(),
        ))
        .await
    }
}
