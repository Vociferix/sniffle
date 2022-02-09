use super::{BasePDU, DissectError, Session, TempPDU, PDU};
use sniffle_ende::{encode::Encoder, nom::IResult};

pub struct RawPDU {
    base: BasePDU,
    data: Vec<u8>,
}

impl RawPDU {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            base: BasePDU::default(),
            data,
        }
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }
}

impl Clone for RawPDU {
    fn clone(&self) -> Self {
        Self {
            base: BasePDU::default(),
            data: self.data.clone(),
        }
    }
}

impl PDU for RawPDU {
    fn base_pdu(&self) -> &BasePDU {
        &self.base
    }

    fn base_pdu_mut(&mut self) -> &mut BasePDU {
        &mut self.base
    }

    fn header_len(&self) -> usize {
        self.data.len()
    }

    fn dissect<'a>(
        buf: &'a [u8],
        _session: &Session,
        _parent: Option<&mut TempPDU<'_>>,
    ) -> IResult<&'a [u8], Self, DissectError> {
        Ok((
            &buf[buf.len()..],
            Self {
                base: BasePDU::default(),
                data: Vec::from(buf),
            },
        ))
    }

    fn serialize_header<W: Encoder + ?Sized>(&self, encoder: &mut W) -> std::io::Result<()> {
        encoder.encode(&self.data[..]).map(|_| ())
    }
}
