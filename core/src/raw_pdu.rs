use super::{BasePDU, DResult, Dissect, Dump, DumpValue, NodeDumper, Session, TempPDU, PDU};
use sniffle_ende::decode::Decode;
use sniffle_ende::encode::Encoder;
use sniffle_ende::nom::combinator::{map, rest};

#[derive(Debug)]
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

impl Decode for RawPDU {
    fn decode(buf: &[u8]) -> DResult<'_, Self> {
        map(rest, |buf| Self {
            base: BasePDU::default(),
            data: Vec::from(buf),
        })(buf)
    }
}

impl Dissect for RawPDU {
    fn dissect<'a>(
        buf: &'a [u8],
        _session: &Session,
        _parent: Option<TempPDU<'_>>,
    ) -> DResult<'a, Self> {
        Self::decode(buf)
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

    fn serialize_header<'a, W: Encoder<'a> + ?Sized>(
        &self,
        encoder: &mut W,
    ) -> std::io::Result<()> {
        encoder.encode(&self.data[..]).map(|_| ())
    }

    fn dump<D: Dump + ?Sized>(&self, dumper: &mut NodeDumper<'_, D>) -> Result<(), D::Error> {
        let mut node = dumper.add_node("Raw Bytes", None)?;
        node.add_field("Data", DumpValue::Bytes(&self.data[..]), None)
    }
}
