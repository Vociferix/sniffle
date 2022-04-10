use super::ethertype::Ethertype;
use crate::prelude::*;
use nom::{
    combinator::{flat_map, map, rest},
    sequence::tuple,
};
use sniffle_core::MACAddress;
use utils::CountingEncoder;

#[derive(Debug, Clone)]
pub struct EthernetII {
    base: BasePDU,
    dst_addr: MACAddress,
    src_addr: MACAddress,
    ethertype: Ethertype,
    trailer: Trailer,
}

#[derive(Debug, Clone)]
enum Trailer {
    Auto,
    Zeros(usize),
    Manual(Vec<u8>),
}

dissector_table!(pub EthertypeDissectorTable, Ethertype);
dissector_table!(pub HeurDissectorTable);

register_dissector_table!(EthertypeDissectorTable);
register_dissector_table!(HeurDissectorTable);

impl EthernetII {
    pub fn new() -> Self {
        Self {
            base: BasePDU::default(),
            dst_addr: Default::default(),
            src_addr: Default::default(),
            ethertype: Ethertype(0),
            trailer: Trailer::Auto,
        }
    }

    pub fn with_addresses(dst_addr: MACAddress, src_addr: MACAddress) -> Self {
        Self {
            base: BasePDU::default(),
            dst_addr,
            src_addr,
            ethertype: Ethertype(0),
            trailer: Trailer::Auto,
        }
    }

    pub fn dst_address(&self) -> MACAddress {
        self.dst_addr
    }

    pub fn dst_address_mut(&mut self) -> &mut MACAddress {
        &mut self.dst_addr
    }

    pub fn src_address(&self) -> MACAddress {
        self.src_addr
    }

    pub fn src_address_mut(&mut self) -> &mut MACAddress {
        &mut self.src_addr
    }

    pub fn ethertype(&self) -> Ethertype {
        self.ethertype
    }

    pub fn ethertype_mut(&mut self) -> &mut Ethertype {
        &mut self.ethertype
    }

    fn auto_trailer_len(&self) -> usize {
        let inner_len = self.inner_pdu().map(|inner| inner.total_len()).unwrap_or(0);
        if inner_len < 46 {
            46 - inner_len
        } else {
            0
        }
    }

    pub fn trailer(&self) -> &[u8] {
        match &self.trailer {
            Trailer::Auto => &PADDING[..self.auto_trailer_len()],
            Trailer::Zeros(len) => &PADDING[..*len],
            Trailer::Manual(trailer) => &trailer[..],
        }
    }

    pub fn trailer_mut(&mut self) -> &mut Vec<u8> {
        let trailer = match &mut self.trailer {
            Trailer::Auto => vec![0u8; self.auto_trailer_len()],
            Trailer::Zeros(len) => vec![0u8; *len],
            Trailer::Manual(trailer) => std::mem::take(trailer),
        };
        self.trailer = Trailer::Manual(trailer);
        match &mut self.trailer {
            Trailer::Manual(trailer) => trailer,
            _ => unreachable!(),
        }
    }
}

const PADDING: [u8; 46] = [0u8; 46];

impl Dissect for EthernetII {
    fn dissect<'a>(
        buf: &'a [u8],
        session: &Session,
        parent: Option<TempPDU<'_>>,
    ) -> DResult<'a, Self> {
        flat_map(
            tuple((<[MACAddress; 2]>::decode, map(u16::decode_be, Ethertype))),
            |([dst_addr, src_addr], ethertype)| {
                let parent = parent.clone();
                move |buf: &'a [u8]| {
                    let mut eth = Self {
                        base: BasePDU::default(),
                        dst_addr,
                        src_addr,
                        ethertype,
                        trailer: Trailer::Auto,
                    };
                    let before = buf.len();
                    let (buf, (inner, trailer)) = session
                        .table_dissector::<EthertypeDissectorTable>(
                            &eth.ethertype,
                            Some(TempPDU::new(&eth, &parent)),
                        )
                        .or(session.table_dissector::<HeurDissectorTable>(
                            &(),
                            Some(TempPDU::new(&eth, &parent)),
                        ))
                        .or(map(RawPDU::decode, AnyPDU::new))
                        .and(map(rest, |trailer: &'a [u8]| {
                            let inner_len = before - trailer.len();
                            let trailer_len = if inner_len < 46 { 46 - inner_len } else { 0 };
                            let mut zeros = 0usize;
                            for byte in buf {
                                if *byte != 0 {
                                    break;
                                }
                                zeros += 1;
                            }
                            if zeros != trailer.len() {
                                Trailer::Manual(Vec::from(trailer))
                            } else if trailer_len != trailer.len() {
                                Trailer::Zeros(zeros)
                            } else {
                                Trailer::Auto
                            }
                        }))
                        .parse(buf)?;
                    eth.trailer = trailer;
                    eth.set_inner_pdu(inner);
                    Ok((buf, eth))
                }
            },
        )(buf)
    }
}

impl PDU for EthernetII {
    fn base_pdu(&self) -> &BasePDU {
        &self.base
    }

    fn base_pdu_mut(&mut self) -> &mut BasePDU {
        &mut self.base
    }

    fn header_len(&self) -> usize {
        14
    }

    fn trailer_len(&self) -> usize {
        self.trailer().len()
    }

    fn total_len(&self) -> usize {
        let inner_len = self.inner_pdu().map(|inner| inner.total_len()).unwrap_or(0);
        self.header_len()
            + inner_len
            + match &self.trailer {
                Trailer::Auto => {
                    if inner_len < 46 {
                        46 - inner_len
                    } else {
                        0
                    }
                }
                Trailer::Zeros(len) => *len,
                Trailer::Manual(trailer) => trailer.len(),
            }
    }

    fn serialize_header<'a, W: Encoder<'a> + ?Sized>(
        &self,
        encoder: &mut W,
    ) -> std::io::Result<()> {
        encoder
            .encode(&self.dst_addr)?
            .encode(&self.src_addr)?
            .encode_be(&self.ethertype.0)?;
        Ok(())
    }

    fn serialize_trailer<'a, W: Encoder<'a> + ?Sized>(
        &self,
        encoder: &mut W,
    ) -> std::io::Result<()> {
        encoder.encode(self.trailer())?;
        Ok(())
    }

    fn serialize<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> std::io::Result<()> {
        self.serialize_header(encoder)?;
        let mut writer = CountingEncoder::new(encoder);
        self.inner_pdu()
            .map(|inner| inner.serialize(&mut writer))
            .unwrap_or(Ok(()))?;
        let inner_len = writer.bytes_written();
        let encoder = writer.into_inner();
        match &self.trailer {
            Trailer::Auto => {
                encoder.encode(&PADDING[..(46 - inner_len)])?;
            }
            Trailer::Zeros(len) => {
                encoder.encode(&PADDING[..*len])?;
            }
            Trailer::Manual(trailer) => {
                encoder.encode(&trailer[..])?;
            }
        }
        Ok(())
    }

    fn dump<D: Dump + ?Sized>(&self, dumper: &mut NodeDumper<D>) -> Result<(), D::Error> {
        let mut node = dumper.add_node(
            "Ethernet II",
            Some(&format!("{}->{}", self.src_addr, self.dst_addr)[..]),
        )?;
        node.add_field(
            "Dst Address",
            DumpValue::Bytes(&self.dst_addr[..]),
            Some(&self.dst_addr.to_string()[..]),
        )?;
        node.add_field(
            "Src Address",
            DumpValue::Bytes(&self.src_addr[..]),
            Some(&self.src_addr.to_string()[..]),
        )?;
        node.add_field(
            "Ethertype",
            DumpValue::UInt(self.ethertype.0.into()),
            Some(&format!("0x{:04x}", self.ethertype.0)[..]),
        )
    }

    fn make_canonical(&mut self) {
        let ethertype = self
            .inner_pdu()
            .map(|inner| Ethertype::from_pdu(inner).unwrap_or(self.ethertype))
            .unwrap_or(self.ethertype);
        self.ethertype = ethertype;
        self.trailer = Trailer::Auto;
    }
}

impl Default for EthernetII {
    fn default() -> Self {
        Self::new()
    }
}

register_link_layer_pdu!(EthernetII, LinkType::ETHERNET);
register_dissector!(
    ethernet_ii,
    LinkTypeTable,
    LinkType::ETHERNET,
    Priority(0),
    EthernetII::dissect
);
