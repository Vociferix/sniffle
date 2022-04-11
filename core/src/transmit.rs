use super::Packet;
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

pub trait Transmit {
    fn transmit(&mut self, packet: &Packet) -> Result<(), TransmitError>;
}
