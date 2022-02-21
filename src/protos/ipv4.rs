use super::prelude::*;
use crate::address::IPv4Address;

pub struct IPv4 {
    base: BasePDU,
    version: uint::U4,
    ihl: uint::U4,
    dscp: uint::U6,
    ecn: uint::U2,
    totlen: u16,
    ident: u16,
    flags: uint::U3,
    frag_offset: uint::U13,
    ttl: u8,
    proto: IPProto,
    chksum: u16,
    src_addr: IPv4Address,
    dst_addr: IPv4Address,
    opts: Vec<IPv4Option>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct IPProto(pub u8);

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum IPv4OptionType {
    Eool,
    Nop,
    OldSec,
    Rr,
    Zsu,
    Mtup,
    Encode,
    Qs,
    Ts,
    Tr,
    Sec,
    Lsr,
    ESec,
    Cipso,
    Sid,
    Ssr,
    Visa,
    Imitd,
    Eip,
    AddExt,
    RtrAlt,
    Sdb,
    Dps,
    Ump,
    Finn,
    Unknown(uint::U5),
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum IPv4OptionClass {
    Control,
    DebugMeas,
    Reserved(uint::U2),
}

#[derive(Clone, Debug)]
pub struct IPv4Option {
    copied: bool,
    class: IPv4OptionClass,
    type_num: IPv4OptionType,
    data: Vec<u8>,
}

macro_rules! ip_proto {
    ($name:ident = $val:literal) => {
        pub const $name: IPProto = IPProto($val);
    };
}

impl IPProto {
    ip_proto!(HOPOPT = 0);
    ip_proto!(ICMP = 1);
    ip_proto!(IGMP = 2);
    ip_proto!(GGP = 3);
    ip_proto!(IPV4 = 4);
    ip_proto!(ST = 5);
    ip_proto!(TCP = 6);
    ip_proto!(CBT = 7);
    ip_proto!(EGP = 8);
    ip_proto!(IGP = 9);
    ip_proto!(BBN_RCC_MON = 10);
    ip_proto!(NVP_II = 11);
    ip_proto!(PUP = 12);
    ip_proto!(ARGUS = 13);
    ip_proto!(EMCON = 14);
    ip_proto!(XNET = 15);
    ip_proto!(CHAOS = 16);
    ip_proto!(UDP = 17);
    ip_proto!(MUX = 18);
    ip_proto!(DCN_MEAS = 19);
    ip_proto!(HMP = 20);
    ip_proto!(PRM = 21);
    ip_proto!(XNS_IDP = 22);
    ip_proto!(TRUNK_1 = 23);
    ip_proto!(TRUNK_2 = 24);
    ip_proto!(LEAF_1 = 25);
    ip_proto!(LEAF_2 = 26);
    ip_proto!(RDP = 27);
    ip_proto!(IRTP = 28);
    ip_proto!(ISO_TP4 = 29);
    ip_proto!(NETBLT = 30);
    ip_proto!(MFE_NSP = 31);
    ip_proto!(MERIT_INP = 32);
    ip_proto!(DCCP = 33);
    ip_proto!(_3PC = 34);
    ip_proto!(IDPR = 35);
    ip_proto!(XTP = 36);
    ip_proto!(DDP = 37);
    ip_proto!(IDPR_CMTP = 38);
    ip_proto!(TP_PLUS_PLUS = 39);
    ip_proto!(IL = 40);
    ip_proto!(IPV6 = 41);
    ip_proto!(SDRP = 42);
    ip_proto!(IPV6_ROUTE = 43);
    ip_proto!(IPV6_FRAG = 44);
    ip_proto!(IDRP = 45);
    ip_proto!(RSVP = 46);
    ip_proto!(GRE = 47);
    ip_proto!(DSR = 48);
    ip_proto!(BNA = 49);
    ip_proto!(ESP = 50);
    ip_proto!(AH = 51);
    ip_proto!(I_NLSP = 52);
    ip_proto!(SWIPE = 53);
    ip_proto!(NARP = 54);
    ip_proto!(MOBILE = 55);
    ip_proto!(TLSP = 56);
    ip_proto!(SKIP = 57);
    ip_proto!(IPV6_ICMP = 58);
    ip_proto!(IPV6_NONXT = 59);
    ip_proto!(IPV6_OPTS = 60);
    ip_proto!(ANY_HOST_INTERNAL_PROTOCOL = 61);
    ip_proto!(CFTP = 62);
    ip_proto!(ANY_LOCAL_NETWORK = 63);
    ip_proto!(SAT_EXPAK = 64);
    ip_proto!(KRYPTOLAN = 65);
    ip_proto!(RVD = 66);
    ip_proto!(IPPC = 67);
    ip_proto!(ANY_DISTRIBUTED_FILE_SYSTEM = 68);
    ip_proto!(SAT_MON = 69);
    ip_proto!(VISA = 70);
    ip_proto!(IPCV = 71);
    ip_proto!(CPNX = 72);
    ip_proto!(CPHB = 73);
    ip_proto!(WSN = 74);
    ip_proto!(PVP = 75);
    ip_proto!(BR_SAT_MON = 76);
    ip_proto!(SUN_ND = 77);
    ip_proto!(WB_MON = 78);
    ip_proto!(WB_EXPAK = 79);
    ip_proto!(ISO_IP = 80);
    ip_proto!(VMTP = 81);
    ip_proto!(SECURE_VMTP = 82);
    ip_proto!(VINES = 83);
    ip_proto!(TTP = 84);
    ip_proto!(IPTM = 84);
    ip_proto!(NSFNET_IGP = 85);
    ip_proto!(DGP = 86);
    ip_proto!(TCF = 87);
    ip_proto!(EIGRP = 88);
    ip_proto!(OSPFIGP = 89);
    ip_proto!(SPRITE_RPC = 90);
    ip_proto!(LARP = 91);
    ip_proto!(MTP = 92);
    ip_proto!(AX_25 = 93);
    ip_proto!(IPIP = 94);
    ip_proto!(MICP = 95);
    ip_proto!(SCC_SP = 96);
    ip_proto!(ETHERIP = 97);
    ip_proto!(ENCAP = 98);
    ip_proto!(ANY_PRIVATE_ENCRYPTION_SCHEME = 99);
    ip_proto!(GMTP = 100);
    ip_proto!(IFMP = 101);
    ip_proto!(PNNI = 102);
    ip_proto!(PIM = 103);
    ip_proto!(ARIS = 104);
    ip_proto!(SCPS = 105);
    ip_proto!(QNX = 106);
    ip_proto!(A_N = 107);
    ip_proto!(IPCOMP = 108);
    ip_proto!(SNP = 109);
    ip_proto!(COMPAQ_PEER = 110);
    ip_proto!(IPX_IN_IP = 111);
    ip_proto!(VRRP = 112);
    ip_proto!(PGM = 113);
    ip_proto!(ANY_0_HOP_PROTOCOL = 114);
    ip_proto!(L2TP = 115);
    ip_proto!(DDX = 116);
    ip_proto!(IATP = 117);
    ip_proto!(STP = 118);
    ip_proto!(SRP = 119);
    ip_proto!(UTI = 120);
    ip_proto!(SMP = 121);
    ip_proto!(SM = 122);
    ip_proto!(PTP = 123);
    ip_proto!(ISI_OVER_IPV4 = 124);
    ip_proto!(FIRE = 125);
    ip_proto!(CRTP = 126);
    ip_proto!(CRUDP = 127);
    ip_proto!(SSCOPMCE = 128);
    ip_proto!(IPLT = 129);
    ip_proto!(SPS = 130);
    ip_proto!(PIPE = 131);
    ip_proto!(SCTP = 132);
    ip_proto!(FC = 133);
    ip_proto!(RSVP_E2E_IGNORE = 134);
    ip_proto!(MOBILITY_HEADER = 135);
    ip_proto!(UDPLITE = 136);
    ip_proto!(MPLS_IN_IP = 137);
    ip_proto!(MANET = 138);
    ip_proto!(SHIM6 = 140);
    ip_proto!(WESP = 141);
    ip_proto!(ROHC = 142);
    ip_proto!(ETHERNET = 143);
    ip_proto!(RESERVED = 255);
}

impl From<u8> for IPProto {
    fn from(proto: u8) -> Self {
        Self(proto)
    }
}

impl From<IPProto> for u8 {
    fn from(proto: IPProto) -> Self {
        proto.0
    }
}

impl IPv4 {
    pub fn new() -> Self {
        Self {
            base: Default::default(),
            version: Default::default(),
            ihl: Default::default(),
            dscp: Default::default(),
            ecn: Default::default(),
            totlen: Default::default(),
            ident: Default::default(),
            flags: Default::default(),
            frag_offset: Default::default(),
            ttl: Default::default(),
            proto: IPProto::RESERVED,
            chksum: Default::default(),
            src_addr: Default::default(),
            dst_addr: Default::default(),
            opts: Vec::new(),
        }
    }

    pub fn with_addresses(src_addr: IPv4Address, dst_addr: IPv4Address) -> Self {
        Self {
            base: Default::default(),
            version: Default::default(),
            ihl: Default::default(),
            dscp: Default::default(),
            ecn: Default::default(),
            totlen: Default::default(),
            ident: Default::default(),
            flags: Default::default(),
            frag_offset: Default::default(),
            ttl: Default::default(),
            proto: IPProto::RESERVED,
            chksum: Default::default(),
            src_addr,
            dst_addr,
            opts: Vec::new(),
        }
    }

    pub fn version(&self) -> uint::U4 {
        self.version
    }

    pub fn version_mut(&mut self) -> &mut uint::U4 {
        &mut self.version
    }

    pub fn ihl(&self) -> uint::U4 {
        self.ihl
    }

    pub fn ihl_mut(&mut self) -> &mut uint::U4 {
        &mut self.ihl
    }

    pub fn dscp(&self) -> uint::U6 {
        self.dscp
    }

    pub fn dscp_mut(&mut self) -> &mut uint::U6 {
        &mut self.dscp
    }

    pub fn ecn(&self) -> uint::U2 {
        self.ecn
    }

    pub fn ecn_mut(&mut self) -> &mut uint::U2 {
        &mut self.ecn
    }

    pub fn totlen(&self) -> u16 {
        self.totlen
    }

    pub fn totlen_mut(&mut self) -> &mut u16 {
        &mut self.totlen
    }

    pub fn identifier(&self) -> u16 {
        self.ident
    }

    pub fn identifier_mut(&mut self) -> &mut u16 {
        &mut self.ident
    }

    pub fn flags(&self) -> uint::U3 {
        self.flags
    }

    pub fn flags_mut(&mut self) -> &mut uint::U3 {
        &mut self.flags
    }

    pub fn fragment_offset(&self) -> uint::U13 {
        self.frag_offset
    }

    pub fn fragment_offset_mut(&mut self) -> &mut uint::U13 {
        &mut self.frag_offset
    }

    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    pub fn ttl_mut(&mut self) -> &mut u8 {
        &mut self.ttl
    }

    pub fn proto(&self) -> IPProto {
        self.proto
    }

    pub fn proto_mut(&mut self) -> &mut IPProto {
        &mut self.proto
    }

    pub fn checksum(&self) -> u16 {
        self.chksum
    }

    pub fn checksum_mut(&mut self) -> &mut u16 {
        &mut self.chksum
    }

    pub fn src_address(&self) -> IPv4Address {
        self.src_addr
    }

    pub fn src_address_mut(&mut self) -> &mut IPv4Address {
        &mut self.src_addr
    }

    pub fn dst_address(&self) -> IPv4Address {
        self.dst_addr
    }

    pub fn dst_address_mut(&mut self) -> &mut IPv4Address {
        &mut self.dst_addr
    }

    pub fn options(&self) -> &[IPv4Option] {
        &self.opts[..]
    }

    pub fn options_mut(&mut self) -> &mut Vec<IPv4Option> {
        &mut self.opts
    }
}

impl PDU for IPv4 {
    fn base_pdu(&self) -> &BasePDU {
        &self.base
    }

    fn base_pdu_mut(&mut self) -> &mut BasePDU {
        &mut self.base
    }

    fn dissect<'a>(
        buf: &'a [u8],
        session: &Session,
        parent: Option<&mut TempPDU<'_>>,
    ) -> DResult<'a, Self> {
        todo!()
    }

    fn header_len(&self) -> usize {
        // TODO: choose the larger value between IHL and actual length
        //       with options
        todo!()
    }

    fn serialize_header<'a, W: Encoder<'a> + ?Sized>(
        &self,
        encoder: &mut W,
    ) -> std::io::Result<()> {
        todo!()
    }

    fn serialize_trailer<'a, W: Encoder<'a> + ?Sized>(
        &self,
        encoder: &mut W,
    ) -> std::io::Result<()> {
        todo!()
    }

    fn dump<D: Dump + ?Sized>(&self, dumper: &mut NodeDumper<D>) -> Result<(), D::Error> {
        todo!()
    }

    fn make_canonical(&mut self) {
        todo!()
    }
}

impl Default for IPv4 {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for IPv4 {
    fn clone(&self) -> Self {
        Self {
            base: BasePDU::default(),
            version: self.version,
            ihl: self.ihl,
            dscp: self.dscp,
            ecn: self.ecn,
            totlen: self.totlen,
            ident: self.ident,
            flags: self.flags,
            frag_offset: self.frag_offset,
            ttl: self.ttl,
            proto: self.proto,
            chksum: self.chksum,
            src_addr: self.src_addr,
            dst_addr: self.dst_addr,
            opts: self.opts.clone(),
        }
    }
}
