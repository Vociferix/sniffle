use super::{BasePdu, DResult, Dissect, Dump, DumpValue, NodeDumper, Pdu, Session, TempPdu};
use sniffle_ende::decode::Decode;
use sniffle_ende::encode::Encoder;
use sniffle_ende::nom::combinator::{map, rest};

#[derive(Debug)]
pub struct RawPdu {
    base: BasePdu,
    data: Vec<u8>,
}

impl RawPdu {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            base: BasePdu::default(),
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

impl Clone for RawPdu {
    fn clone(&self) -> Self {
        Self {
            base: BasePdu::default(),
            data: self.data.clone(),
        }
    }
}

impl Decode for RawPdu {
    fn decode(buf: &[u8]) -> DResult<'_, Self> {
        map(rest, |buf| Self {
            base: BasePdu::default(),
            data: Vec::from(buf),
        })(buf)
    }
}

impl Dissect for RawPdu {
    fn dissect<'a>(
        buf: &'a [u8],
        _session: &Session,
        _parent: Option<TempPdu<'_>>,
    ) -> DResult<'a, Self> {
        Self::decode(buf)
    }
}

impl Pdu for RawPdu {
    fn base_pdu(&self) -> &BasePdu {
        &self.base
    }

    fn base_pdu_mut(&mut self) -> &mut BasePdu {
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
