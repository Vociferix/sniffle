use crate::address::MACAddress;
use crate::protos::prelude::*;
use crate::utils::CountingEncoder;
use nom::{combinator::map, sequence::tuple};

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

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct Ethertype(pub u16);

struct EthertypeRange {
    begin: u16,
    end: u16,
}

pub struct EthertypeSet<const N: usize>([EthertypeRange; N]);

pub struct EthertypeIter {
    iter: std::slice::Iter<'static, EthertypeRange>,
    val: u16,
    end: u16,
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

impl PDU for EthernetII {
    fn base_pdu(&self) -> &BasePDU {
        &self.base
    }

    fn base_pdu_mut(&mut self) -> &mut BasePDU {
        &mut self.base
    }

    fn dissect<'a>(
        buf: &'a [u8],
        session: &Session,
        parent: Option<TempPDU<'_>>,
    ) -> DResult<'a, Self> {
        let (buf, mut eth) = map(
            tuple((MACAddress::decode, MACAddress::decode, u16::decode_be)),
            |hdr| Self {
                base: BasePDU::default(),
                dst_addr: hdr.0,
                src_addr: hdr.1,
                ethertype: Ethertype(hdr.2),
                trailer: Trailer::Auto,
            },
        )(buf)?;
        let before = buf.len();
        let ethertype = eth.ethertype();
        let (buf, inner) = session.table_dissect::<EthertypeDissectorTable>(
            &ethertype,
            buf,
            Some(TempPDU::new(&eth, &parent)),
        )?;
        let (buf, inner) = match inner {
            Some(inner) => (buf, inner),
            None => session.table_dissect_or_raw::<HeurDissectorTable>(
                &(),
                buf,
                Some(TempPDU::new(&eth, &parent)),
            )?,
        };
        eth.set_inner_pdu(inner);
        let inner_len = before - buf.len();
        let trailer_len = if inner_len < 46 { 46 - inner_len } else { 0 };
        let mut zeros = 0usize;
        if trailer_len == buf.len() {
            for byte in buf {
                if *byte != 0 {
                    break;
                }
                zeros += 1;
            }
            if zeros == buf.len() {
                eth.trailer = Trailer::Auto;
            } else {
                let mut trailer = vec![0u8; zeros];
                for byte in &buf[zeros..] {
                    trailer.push(*byte);
                }
                eth.trailer = Trailer::Manual(trailer);
            }
        } else {
            for byte in buf {
                if *byte != 0 {
                    break;
                }
                zeros += 1;
            }
            if zeros == buf.len() {
                eth.trailer = Trailer::Zeros(zeros);
            } else {
                let mut trailer = vec![0u8; zeros];
                for byte in &buf[zeros..] {
                    trailer.push(*byte);
                }
                eth.trailer = Trailer::Manual(trailer);
            }
        }
        Ok((buf, eth))
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

    // We will fill in the match later when more protocols are implemented,
    // so suppress this lint for now.
    #[allow(clippy::match_single_binding)]
    fn make_canonical(&mut self) {
        let ethertype = match self.inner_pdu() {
            Some(inner) => match inner.pdu_type() {
                _ => self.ethertype(),
            },
            None => self.ethertype(),
        };
        self.ethertype = ethertype;
        self.trailer = Trailer::Auto;
    }
}

impl Default for EthernetII {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! count {
    () => {{ 0 }};
    ($rg:expr) => {{ 1 }};
    ($rg:expr,) => {{ 1 }};
    ($rg1:expr, $($rgn:expr),+) => {{
        1 + count!($($rgn),+)
    }};
    ($rg1:expr, $($rgn:expr),+,) => {{
        count!($rg1, $($rgn),+)
    }};
}

macro_rules! range {
    () => {{
        EthertypeRange { begin: 0, end: 0 }
    }};
    ($val:literal) => {{
        EthertypeRange {
            begin: $val,
            end: ($val + 1),
        }
    }};
    ([$begin:literal, $end:literal]) => {{
        EthertypeRange {
            begin: $begin,
            end: ($end + 1),
        }
    }};
}

macro_rules! ethertype {
    ($name:ident = $val:literal) => {
        pub const $name: Ethertype = Ethertype($val);
    };
    ($name:ident = [$begin:literal, $end:literal]) => {
        ethertype!($name = { [ $begin, $end ] });
    };
    ($name:ident = { }) => {
        pub const $name: EthertypeSet<0> = EthertypeSet([]);
    };
    ($name:ident = { $rg:tt }) => {
        pub const $name: EthertypeSet<1> = EthertypeSet([range!($rg)]);
    };
    ($name:ident = { $rg1:tt, $($rgn:tt),+ }) => {
        pub const $name: EthertypeSet<{ count!($rg1, $($rgn),+) }> = EthertypeSet([range!($rg1), $(range!($rgn)),+]);
    };
    ($name:ident = { $rg1:tt, $($rgn:tt),+, }) => {
        ethertype!($name = { $rg1, $($rgn),+ });
    };
}

impl Ethertype {
    ethertype!(IEEE_802_3_LENGTH = [0x0000, 0x05dc]);
    ethertype!(EXPERIMENTAL = [0x0101, 0x01ff]);
    ethertype!(XEROX_PUP = 0x0200);
    ethertype!(PUP_ADDR_TRANS = { 0x0201, 0x0a01 });
    ethertype!(NIXDORF = 0x0400);
    ethertype!(XEROX_NS_IDP = 0x0600);
    ethertype!(DLOG = [0x0660, 0x0661]);
    ethertype!(IPV4 = 0x0800);
    ethertype!(X_75 = 0x0801);
    ethertype!(NBS = 0x0802);
    ethertype!(ECMA = 0x0803);
    ethertype!(CHAOSNET = 0x0804);
    ethertype!(X_25 = 0x0805);
    ethertype!(ARP = 0x0806);
    ethertype!(XNS_COMPAT = 0x0807);
    ethertype!(FRAME_RELAY_ARP = 0x0808);
    ethertype!(SYMBOLICS_PRIVATE = {
        0x081c,
        [0x8107, 0x8109],
    });
    ethertype!(XYPLEX = {
        [0x0888, 0x088a],
        [0x81b7, 0x81b9],
    });
    ethertype!(UNGERMANN_BASS_NET_DEBUG = 0x0900);
    ethertype!(XEROX_IEEE_802_3_PUP = 0x0a00);
    ethertype!(BANYAN_VINES = 0x0bad);
    ethertype!(VINES_LOOPBACK = 0x0bae);
    ethertype!(VINES_ECHO = 0x0baf);
    ethertype!(BERKELEY_TRAILER_NEGO = 0x1000);
    ethertype!(BERKELEY_TRAILER_ENCAP_IP = [0x1001, 0x100f]);
    ethertype!(VALID_SYSTEMS = 0x1600);
    ethertype!(TRILL = 0x22f3);
    ethertype!(L2_IS_IS = 0x22f4);
    ethertype!(PCS_BASIC_BLOCK = 0x4242);
    ethertype!(BBN_SIMNET = 0x5208);
    ethertype!(DEC_UNASSIGNED = {
        0x6000,
        [0x6008, 0x6009],
        [0x8039, 0x803e],
        [0x8040, 0x8042],
    });
    ethertype!(DEC_MOP_DUMP_LOAD = 0x6001);
    ethertype!(DEC_MOP_REMOTE_CONSOLE = 0x6002);
    ethertype!(DEC_DECNET_PHASE_IV_ROUTE = 0x6003);
    ethertype!(DEC_LAT = 0x6004);
    ethertype!(DEC_DIAGNOSTIC = 0x6005);
    ethertype!(DEC_CUSTOMER = 0x6006);
    ethertype!(DEC_LAVC_SCA = 0x6007);
    ethertype!(_3COM_CORP = [0x6010, 0x6014]);
    ethertype!(TRANS_ETHER_BRIDGING = 0x6558);
    ethertype!(RAW_FRAME_RELAY = 0x6559);
    ethertype!(UNGERMANN_BASS_DIA_LOOP = 0x7002);
    ethertype!(LRT = [0x7020, 0x7029]);
    ethertype!(PROTEON = 0x7030);
    ethertype!(CABLETRON = 0x7034);
    ethertype!(CRONUS_VLN = 0x8003);
    ethertype!(CRONUS_DIRECT = 0x8004);
    ethertype!(HP_PROBE = 0x8005);
    ethertype!(NESTAR = 0x8006);
    ethertype!(ATT = {0x8008, 0x8046, 0x8047, 0x8069});
    ethertype!(EXCELAN = 0x8010);
    ethertype!(SGI_DIAGNOSTICS = 0x8013);
    ethertype!(SGI_NETWORK_GAMES = 0x8014);
    ethertype!(SGI_RESERVED = 0x8015);
    ethertype!(SGI_BOUNCE_SERVER = 0x8016);
    ethertype!(APOLLO_DOMAIN = 0x8019);
    ethertype!(TYMSHARE = 0x802e);
    ethertype!(TIGAN_INC = 0x802f);
    ethertype!(RARP = 0x8035);
    ethertype!(AEONIC_SYSTEMS = 0x8036);
    ethertype!(DEC_LANBRIDGE = 0x8038);
    ethertype!(DEC_ETHERNET_ENCRYPTION = 0x803d);
    ethertype!(DEC_LAN_TRAFFIC_MONITOR = 0x803f);
    ethertype!(PLANNING_RESEARCH_CORP = 0x8044);
    ethertype!(EXPERDATA = 0x8049);
    ethertype!(STANFORD_V_KERNEL_EXP = 0x805b);
    ethertype!(STANFORD_V_KERNEL_PROD = 0x805c);
    ethertype!(EVANS_AND_SUTHERLAND = 0x805d);
    ethertype!(LITTLE_MACHINES = 0x8062);
    ethertype!(COUNTERPOINT_COMPUTERS = {
        0x8062,
        [0x8081, 0x8083],
    });
    ethertype!(UNIV_OF_MASS_AMHERST = [0x8065, 0x8066]);
    ethertype!(VEECO_INTEGRATED_AUTO = 0x8067);
    ethertype!(GENERAL_DYNAMICS = 0x8068);
    ethertype!(AUTOPHON = 0x806a);
    ethertype!(COMDESIGN = 0x806c);
    ethertype!(COMPUTERGRAPHIC_CORP = 0x806d);
    ethertype!(LANDMARK_GRAPHICS_CORP = [0x806e, 0x8077]);
    ethertype!(MATRA = 0x807a);
    ethertype!(DANSK_DATA_ELEKTRONIK = 0x807b);
    ethertype!(MERIT_INTERNODAL = 0x807c);
    ethertype!(VITALINK_COMMUNICATIONS = [0x807d, 0x807f]);
    ethertype!(VITALINK_TRANSLAN_III = 0x8080);
    ethertype!(APPLETALK = 0x809b);
    ethertype!(DATABILITY = {
        [0x809c, 0x809e],
        [0x80e4, 0x80f0],
    });
    ethertype!(SPIDER_SYSTEMS_LTD = 0x809f);
    ethertype!(NIXDORF_COMPUTERS = 0x80a3);
    ethertype!(SIEMENS_GAMMASONICS_INC = [0x80a4, 0x80b3]);
    ethertype!(DCA_DATA_EXCHANGE_CLUSTER = [0x80c0, 0x80c3]);
    ethertype!(BANYAN_SYSTEMS = [0x80c4, 0x80c5]);
    ethertype!(PACER_SOFTWARE = 0x80c6);
    ethertype!(APPLITEK_CORP = 0x80c7);
    ethertype!(INTERGRAPH_CORP = [0x80c8, 0x80cc]);
    ethertype!(HARRIS_CORP = [0x80cd, 0x80ce]);
    ethertype!(TAYLOR_INSTRUMENT = [0x80cf, 0x80d2]);
    ethertype!(ROSEMOUNT_CORP = [0x80d3, 0x80d4]);
    ethertype!(IBM_SNA_SERVICE_ON_ETHER = 0x80d5);
    ethertype!(VARIAN_ASSOCIATES = 0x80dd);
    ethertype!(INTEGRATED_SOLUTIONS_TRFS = [0x80de, 0x80df]);
    ethertype!(ALLEN_BRADLEY = [0x80e0, 0x80e3]);
    ethertype!(RETIX = 0x80f2);
    ethertype!(APPLETALK_AARP_KINETICS = 0x80f3);
    ethertype!(KINETICS = [0x80f4, 0x80f5]);
    ethertype!(APOLLO_COMPUTER = 0x80f7);
    ethertype!(WELLFLEET_COMMUNICATIONS = {
        0x80ff,
        [0x8101, 0x8103],
    });
    ethertype!(CUSTOMER_VLAN_TAG_TYPE = 0x8100);
    ethertype!(HAYES_MICROCOMPUTERS = 0x8130);
    ethertype!(VG_LABORATORY_SYSTEMS = 0x8131);
    ethertype!(BRIDGE_COMMUNICATIONS = [0x8132, 0x8136]);
    ethertype!(NOVELL_INC = [0x8137, 0x8138]);
    ethertype!(KTI = [0x8139, 0x813d]);
    ethertype!(LOGICRAFT = 0x8148);
    ethertype!(NETWORK_COMPUTING_DEVICES = 0x8149);
    ethertype!(ALPHA_MICRO = 0x814a);
    ethertype!(SNMP = 0x814c);
    ethertype!(BIIN = [0x814d, 0x814e]);
    ethertype!(TECHNICALLY_ELITE_CONCEPT = 0x814f);
    ethertype!(RATIONAL_CORP = 0x8150);
    ethertype!(QUALCOMM = {
        [0x8151, 0x8153],
        [0x8184, 0x818c],
    });
    ethertype!(COMPUTER_PROTOCOL_PTY_LTD = [0x815c, 0x815e]);
    ethertype!(CHARLES_RIVER_DATA_SYSTEM = {
        [0x8164, 0x8166],
        [0x8263, 0x816a],
    });
    ethertype!(XTP = 0x817d);
    ethertype!(SGI_TIME_WARNER_PROP = 0x817e);
    ethertype!(HIPPI_FP_ENCAPSULATION = 0x8180);
    ethertype!(STP_HIPPI_ST = 0x8181);
    ethertype!(HIPPI_RESERVED = [0x8182, 0x8183]);
    ethertype!(SILICON_GRAPHICS_PROP = [0x8184, 0x818c]);
    ethertype!(MOTOROLA_COMPUTER = 0x818d);
    ethertype!(ARAI_BUNKICHI = 0x81a4);
    ethertype!(RAD_NETWORK_DEVICES = [0x81a5, 0x81ae]);
    ethertype!(APRICOT_COMPUTERS = [0x81cc, 0x81d5]);
    ethertype!(ARTISOFT = [0x81d6, 0x81dd]);
    ethertype!(POLYGON = [0x81e6, 0x81ef]);
    ethertype!(COMSAT_LABS = [0x81f0, 0x81f2]);
    ethertype!(SAIC = [0x81f3, 0x81f5]);
    ethertype!(VG_ANALYTICAL = [0x81f6, 0x81f8]);
    ethertype!(QUANTUM_SOFTWARE = [0x8203, 0x8205]);
    ethertype!(ASCOM_BANKING_SYSTEMS = [0x8221, 0x8222]);
    ethertype!(ADVANCED_ENCRYPTION_SYSTE = [0x823e, 0x8240]);
    ethertype!(ATHENA_PROGRAMMING = [0x827f, 0x8282]);
    ethertype!(INST_IND_INFO_TECH = [0x829a, 0x829b]);
    ethertype!(TAURUS_CONTROLS = [0x829c, 0x82ab]);
    ethertype!(WALKER_RICHER_AND_QUINN = [0x82ac, 0x8693]);
    ethertype!(IDEA_COURIER = [0x8694, 0x869d]);
    ethertype!(COMPUTER_NETWORK_TECH = [0x869e, 0x86a1]);
    ethertype!(GATEWAY_COMMUNICATIONS = [0x86a3, 0x86ac]);
    ethertype!(SECTRA = 0x86db);
    ethertype!(DELTA_CONTROLS = 0x86de);
    ethertype!(IPV6 = 0x86dd);
    ethertype!(ATOMIC = 0x86df);
    ethertype!(LANDIS_AND_GYR_POWERS = [0x86e0, 0x86ef]);
    ethertype!(MOTOROLA = [0x8700, 0x8710]);
    ethertype!(TCP_IP_COMPRESSION = 0x876b);
    ethertype!(IP_AUTONOMOUS_SYSTEMS = 0x876c);
    ethertype!(SECURE_DATA = 0x876d);
    ethertype!(IEEE_802_3_EPON = 0x8808);
    ethertype!(PPP = 0x880b);
    ethertype!(GSMP = 0x880c);
    ethertype!(ETHERNET_NIC_TESTING = 0x8822);
    ethertype!(MPLS = 0x8847);
    ethertype!(MPLS_WITH_UPSTREAM_ASSIGNED_LABEL = 0x8848);
    ethertype!(MCAP = 0x8861);
    ethertype!(PPPOE_SESSION_STAGE = 0x8864);
    ethertype!(IEEE_802_1X = 0x888e);
    ethertype!(IEEE_802_1Q_S_TAG = 0x88a8);
    ethertype!(INVISIBLE_SOFTWARE = [0x8a96, 0x8a97]);
    ethertype!(IEEE_802_LOCAL_EXPERIMENTAL_ETHERTYPE = [0x88b5, 0x88b6]);
    ethertype!(IEEE_802_OUI_EXTENDED_ETHERTYPE = 0x88b7);
    ethertype!(IEEE_802_11I = 0x88c7);
    ethertype!(IEEE_802_1AB = 0x88cc);
    ethertype!(IEEE_802_1AE = 0x88e5);
    ethertype!(PROVIDER_BACKBONE_BRIDGING_INSTANCE_TAG = 0x88e7);
    ethertype!(IEEE_802_1Q_MVRP = 0x88f5);
    ethertype!(IEEE_802_1Q_MMRP = 0x88f6);
    ethertype!(IEEE_802_1R = 0x890d);
    ethertype!(IEEE_802_21 = 0x8917);
    ethertype!(IEEE_802_1QBE = 0x8929);
    ethertype!(TRILL_FGL = 0x893b);
    ethertype!(IEEE_802_1QBG = 0x8940);
    ethertype!(TRILL_RBRIDGE_CHANNEL = 0x8946);
    ethertype!(GEONETWORKING = 0x8947);
    ethertype!(NSH = 0x894f);
    ethertype!(LOOPBACK = 0x9000);
    ethertype!(_3COM_BRIDGE_XNS_SYS_MGMT = 0x9001);
    ethertype!(_3COM_BRIDGE_TCP_IP_SYS = 0x9002);
    ethertype!(_3COM_BRIDGE_LOOP_DETECT = 0x9003);
    ethertype!(MULTI_TOPOLOGY = 0x9a22);
    ethertype!(LOWPAN_ENCAPSULATION = 0xa0ed);
    ethertype!(BBN_VITAL_LANBRIDGE_CACHE = 0xff00);
    ethertype!(ISC_BUNKER_RAMO = [0xff00, 0xff0f]);
}

impl<const N: usize> EthertypeSet<N> {
    pub fn contains(&self, ethertype: Ethertype) -> bool {
        for t in self.0.iter() {
            if ethertype.0 >= t.begin && ethertype.0 < t.end {
                return true;
            }
        }
        false
    }

    pub fn iter(&'static self) -> EthertypeIter {
        let mut iter = self.0.iter();
        match iter.next() {
            Some(item) => EthertypeIter {
                iter,
                val: item.begin,
                end: item.end,
            },
            None => EthertypeIter {
                iter,
                val: 0,
                end: 0,
            },
        }
    }
}

impl Iterator for EthertypeIter {
    type Item = Ethertype;

    fn next(&mut self) -> Option<Self::Item> {
        if self.val == self.end {
            return None;
        }

        let ret = Some(Ethertype(self.val));
        self.val += 1;
        if self.val == self.end {
            let (val, end) = match self.iter.next() {
                Some(item) => (item.begin, item.end),
                None => {
                    return ret;
                }
            };
            self.val = val;
            self.end = end;
        }
        ret
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
