use super::*;
use sniffle_core::SniffError;
use std::io::{BufRead, Seek};

pub struct Reader<F: BufRead + Seek> {
    file: F,
    pos: u64,
    curr: u64,
    next: u64,
    be: bool,
    first_snaplen: Option<u32>,
}

pub type FileReader = Reader<std::io::BufReader<std::fs::File>>;

pub enum Block<'a, F: BufRead + Seek> {
    SHB(SectionHeaderBlock<'a, F>),
    IDB(InterfaceDescriptionBlock<'a, F>),
    EPB(EnhancedPacketBlock<'a, F>),
    SPB(SimplePacketBlock<'a, F>),
    NRB(NameResolutionBlock<'a, F>),
    ISB(InterfaceStatisticsBlock<'a, F>),
    SJB(SystemdJournalExportBlock<'a, F>),
    DSB(DecryptionSecretsBlock<'a, F>),
    Other(RawBlock<'a, F>),
}

pub struct RawOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    code: u16,
    offset: u64,
    len: u16,
}

pub struct StringOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    offset: u64,
    len: u16,
}

pub struct U8Opt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    value: Option<u8>,
}

pub struct U32Opt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    value: Option<u32>,
}

pub struct I32Opt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    value: Option<i32>,
}

pub struct U64Opt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    value: Option<u64>,
}

pub struct I64Opt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    value: Option<i64>,
}

pub struct IPv4Opt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    addr: Option<IPv4Address>,
}

pub struct IPv6Opt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    addr: Option<IPv6Address>,
}

pub struct IPv4IfaceOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    addr: Option<(IPv4Address, IPv4Address)>,
}

pub struct IPv6IfaceOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    addr: Option<(IPv6Address, u8)>,
}

pub struct MACOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    addr: Option<MACAddress>,
}

pub struct EUIOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    addr: Option<EUIAddress>,
}

pub struct TimestampOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    ts: Option<u64>,
}

pub enum FilterOpt<'a, F: BufRead + Seek> {
    String(StringFilterOpt<'a, F>),
    ByteCode(ByteCodeFilterOpt<'a, F>),
    Unknown(RawFilterOpt<'a, F>),
}

pub struct StringFilterOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    offset: u64,
    len: u16,
}

pub struct ByteCodeFilterOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    offset: u64,
    len: u16,
}

pub struct RawFilterOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    code: u8,
    offset: u64,
    len: u16,
}

pub struct PacketFlagsOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    flags: Option<u32>,
}

pub enum HashOpt<'a, F: BufRead + Seek> {
    TwosComplement(TwosComplementOpt<'a, F>),
    XOR(XOROpt<'a, F>),
    CRC32(CRC32Opt<'a, F>),
    MD5(MD5Opt<'a, F>),
    SHA1(SHA1Opt<'a, F>),
    Toeplitz(ToeplitzOpt<'a, F>),
    Unknown(RawHashOpt<'a, F>),
}

pub struct TwosComplementOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    offset: u64,
    len: u16,
}

pub struct XOROpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    offset: u64,
    len: u16,
}

pub struct CRC32Opt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    crc: Option<[u8; 4]>,
}

pub struct MD5Opt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    hash: Option<[u8; 16]>,
}

pub struct SHA1Opt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    hash: Option<[u8; 20]>,
}

pub struct ToeplitzOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    hash: Option<[u8; 4]>,
}

pub struct RawHashOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    id: u8,
    offset: u64,
    len: u16,
}

pub enum VerdictOpt<'a, F: BufRead + Seek> {
    Hardware(HardwareVerdictOpt<'a, F>),
    LinuxEBPFTC(LinuxVerdictOpt<'a, F>),
    LinuxEBPFXDP(LinuxVerdictOpt<'a, F>),
    Unknown(RawVerdictOpt<'a, F>),
}

pub struct HardwareVerdictOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    offset: u64,
    len: u16,
}

pub struct LinuxVerdictOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    verdict: Option<u64>,
}

pub struct RawVerdictOpt<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    id: u8,
    offset: u64,
    len: u16,
}

pub struct SectionHeaderBlock<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    data: Option<SHB>,
    next: u64,
    opt_end: u64,
}

struct SHB {
    version_major: u16,
    version_minor: u16,
    section_len: u64,
}

pub enum SHBOption<'a, F: BufRead + Seek> {
    Comment(StringOpt<'a, F>),
    Hardware(StringOpt<'a, F>),
    OS(StringOpt<'a, F>),
    UserApplication(StringOpt<'a, F>),
    Unknown(RawOpt<'a, F>),
}

pub struct InterfaceDescriptionBlock<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    data: Option<IDB>,
    next: u64,
    opt_end: u64,
}

struct IDB {
    link_type: u16,
    snaplen: u32,
}

pub enum IDBOption<'a, F: BufRead + Seek> {
    Comment(StringOpt<'a, F>),
    Name(StringOpt<'a, F>),
    Description(StringOpt<'a, F>),
    IPv4(IPv4IfaceOpt<'a, F>),
    IPv6(IPv6IfaceOpt<'a, F>),
    MAC(MACOpt<'a, F>),
    EUI(EUIOpt<'a, F>),
    Speed(U64Opt<'a, F>),
    TSResol(U8Opt<'a, F>),
    TimeZone(I32Opt<'a, F>),
    Filter(FilterOpt<'a, F>),
    OS(StringOpt<'a, F>),
    FCSLen(U8Opt<'a, F>),
    TSOffset(I64Opt<'a, F>),
    Hardware(StringOpt<'a, F>),
    TXSpeed(U64Opt<'a, F>),
    RXSpeed(U64Opt<'a, F>),
    Unknown(RawOpt<'a, F>),
}

pub struct EnhancedPacketBlock<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    data: Option<EPB>,
    offset: u64,
    next: u64,
    opt_end: u64,
}

struct EPB {
    iface: u32,
    ts: u64,
    cap_len: u32,
    orig_len: u32,
}

pub enum EPBOption<'a, F: BufRead + Seek> {
    Comment(StringOpt<'a, F>),
    Flags(PacketFlagsOpt<'a, F>),
    Hash(HashOpt<'a, F>),
    DropCount(U64Opt<'a, F>),
    PacketId(U64Opt<'a, F>),
    Queue(U32Opt<'a, F>),
    Verdict(VerdictOpt<'a, F>),
    Unknown(RawOpt<'a, F>),
}

pub struct SimplePacketBlock<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    data: Option<SPB>,
    offset: u64,
}

struct SPB {
    cap_len: u32,
    orig_len: u32,
}

pub struct NameResolutionBlock<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    next_rec: u64,
    next: u64,
    opt_end: u64,
}

pub enum NameRecord<'a, F: BufRead + Seek> {
    IPv4(IPv4NameRecord<'a, F>),
    IPv6(IPv6NameRecord<'a, F>),
    Other(RawOpt<'a, F>),
}

pub struct IPv4NameRecord<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    addr: Option<IPv4Address>,
    next: u64,
    names_end: u64,
}

pub struct IPv6NameRecord<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    addr: Option<IPv6Address>,
    next: u64,
    names_end: u64,
}

pub enum NRBOption<'a, F: BufRead + Seek> {
    Comment(StringOpt<'a, F>),
    DNSName(StringOpt<'a, F>),
    DNSIPv4Addr(IPv4Opt<'a, F>),
    DNSIPv6Addr(IPv6Opt<'a, F>),
    Unknown(RawOpt<'a, F>),
}

pub struct InterfaceStatisticsBlock<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    data: Option<ISB>,
    next: u64,
    opt_end: u64,
}

struct ISB {
    iface: u32,
    ts: u64,
}

pub enum ISBOption<'a, F: BufRead + Seek> {
    Comment(StringOpt<'a, F>),
    StartTime(TimestampOpt<'a, F>),
    EndTime(TimestampOpt<'a, F>),
    IfRecv(U64Opt<'a, F>),
    IfDrop(U64Opt<'a, F>),
    FilterAccept(U64Opt<'a, F>),
    OSDrop(U64Opt<'a, F>),
    UserDeliv(U64Opt<'a, F>),
    Unknown(RawOpt<'a, F>),
}

pub struct SystemdJournalExportBlock<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    len: u32,
    offset: u64,
}

pub struct DecryptionSecretsBlock<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    data: Option<DSB>,
    offset: u64,
    next: u64,
    opt_end: u64,
}

struct DSB {
    secrets_type: u32,
    secrets_len: u32,
}

pub enum DSBOption<'a, F: BufRead + Seek> {
    Comment(StringOpt<'a, F>),
    Unknown(RawOpt<'a, F>),
}

pub struct RawBlock<'a, F: BufRead + Seek> {
    reader: &'a mut Reader<F>,
    id: u32,
    len: u32,
    offset: u64,
}

fn guarantee<T>(opt: Option<T>) -> T {
    match opt {
        Some(val) => val,
        None => unreachable!(),
    }
}

impl<F: BufRead + Seek> Reader<F> {
    pub fn new(mut file: F) -> std::io::Result<Self> {
        let pos = file.stream_position()?;
        Ok(Self::init(file, pos))
    }

    pub fn open<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<FileReader> {
        Ok(FileReader::init(
            std::io::BufReader::new(std::fs::File::open(path)?),
            0,
        ))
    }

    fn jump_to(&mut self, pos: u64) -> std::io::Result<()> {
        if self.pos != pos {
            self.pos = self.file.seek(std::io::SeekFrom::Start(pos))?;
        }
        Ok(())
    }

    fn skip(&mut self, bytes: u64) -> std::io::Result<()> {
        self.jump_to(self.pos + bytes)
    }

    fn read_buf(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.file.read_exact(buf)?;
        self.pos += buf.len() as u64;
        Ok(())
    }

    fn read_buf_at(&mut self, buf: &mut [u8], pos: u64) -> std::io::Result<()> {
        self.jump_to(pos)?;
        self.read_buf(buf)
    }

    fn read_strz(&mut self, s: &mut String) -> Result<(), SniffError> {
        let mut buf = std::mem::replace(s, String::new()).into_bytes();
        self.file.read_until(0, &mut buf)?;
        buf.pop();
        *s = String::from_utf8(buf).map_err(|_| SniffError::MalformedCapture)?;
        Ok(())
    }

    fn read_strz_at(&mut self, s: &mut String, pos: u64) -> Result<(), SniffError> {
        self.jump_to(pos)?;
        self.read_strz(s)
    }

    fn read_u8(&mut self) -> std::io::Result<u8> {
        let mut buf = [0u8];
        self.read_buf(&mut buf[..])?;
        Ok(buf[0])
    }

    fn read_u8_at(&mut self, pos: u64) -> std::io::Result<u8> {
        self.jump_to(pos)?;
        self.read_u8()
    }

    fn read_u16(&mut self) -> std::io::Result<u16> {
        let mut buf = [0u8; 2];
        self.read_buf(&mut buf[..])?;
        Ok(if self.be {
            u16::from_be_bytes(buf)
        } else {
            u16::from_le_bytes(buf)
        })
    }

    fn read_u16_at(&mut self, pos: u64) -> std::io::Result<u16> {
        self.jump_to(pos)?;
        self.read_u16()
    }

    fn read_u32(&mut self) -> std::io::Result<u32> {
        let mut buf = [0u8; 4];
        self.read_buf(&mut buf[..])?;
        Ok(if self.be {
            u32::from_be_bytes(buf)
        } else {
            u32::from_le_bytes(buf)
        })
    }

    fn read_u32_at(&mut self, pos: u64) -> std::io::Result<u32> {
        self.jump_to(pos)?;
        self.read_u32()
    }

    fn read_i32(&mut self) -> std::io::Result<i32> {
        let mut buf = [0u8; 4];
        self.read_buf(&mut buf[..])?;
        Ok(if self.be {
            i32::from_be_bytes(buf)
        } else {
            i32::from_le_bytes(buf)
        })
    }

    fn read_u64(&mut self) -> std::io::Result<u64> {
        let mut buf = [0u8; 8];
        self.read_buf(&mut buf[..])?;
        Ok(if self.be {
            u64::from_be_bytes(buf)
        } else {
            u64::from_le_bytes(buf)
        })
    }

    fn read_i64(&mut self) -> std::io::Result<i64> {
        let mut buf = [0u8; 8];
        self.read_buf(&mut buf[..])?;
        Ok(if self.be {
            i64::from_be_bytes(buf)
        } else {
            i64::from_le_bytes(buf)
        })
    }

    fn init(file: F, init_pos: u64) -> Self {
        Self {
            file,
            pos: init_pos,
            curr: init_pos,
            next: init_pos,
            be: false,
            first_snaplen: None,
        }
    }

    pub fn next_block(&mut self) -> Result<Option<Block<'_, F>>, SniffError> {
        let id = match self.read_u32_at(self.next) {
            Ok(id) => id,
            Err(e) => {
                let kind = e.kind();
                match kind {
                    std::io::ErrorKind::UnexpectedEof => {
                        return Ok(None);
                    }
                    _ => {
                        return Err(SniffError::from(e));
                    }
                }
            }
        };
        let len = self.read_u32()?;
        self.curr = self.pos - 8;
        self.next = self.curr + (len as u64);
        Ok(Some(match id {
            SHB_ID => Block::SHB(SectionHeaderBlock::new(self, len)?),
            IDB_ID => Block::IDB(InterfaceDescriptionBlock::new(self, len)?),
            EPB_ID => Block::EPB(EnhancedPacketBlock::new(self, len)?),
            SPB_ID => Block::SPB(SimplePacketBlock::new(self, len)?),
            NRB_ID => Block::NRB(NameResolutionBlock::new(self, len)?),
            ISB_ID => Block::ISB(InterfaceStatisticsBlock::new(self, len)?),
            SJB_ID => Block::SJB(SystemdJournalExportBlock::new(self, len)?),
            DSB_ID => Block::DSB(DecryptionSecretsBlock::new(self, len)?),
            _ => Block::Other(RawBlock::new(self, id, len)?),
        }))
    }
}

macro_rules! impl_next_opt {
    ((&mut $slf:ident, $off:ident, $len:ident) -> $opt:ty { }) => {
        pub fn next_option(&mut $slf) -> Result<Option<$opt>, SniffError> {
            if $slf.next == $slf.opt_end { return Ok(None); }
            let _ = $slf.data()?;
            let id_ = $slf.reader.read_u16_at($slf.next)?;
            let $len = $slf.reader.read_u16()?;
            $slf.next += (4 + $len + ((4 - ($len % 4)) % 4)) as u64;
            let $off = $slf.reader.pos;
            Ok(Some(match id_ {
                OPT_ENDOFOPT => {
                    if $len != 0 { return Err(SniffError::MalformedCapture); }
                    return Ok(None);
                },
                OPT_COMMENT => {
                    <$opt>::Comment(StringOpt {
                        reader: $slf.reader,
                        offset: $off,
                        len: $len,
                    })
                },
                _ => {
                    <$opt>::Unknown(RawOpt {
                        reader: $slf.reader,
                        code: id_,
                        offset: $off,
                        len: $len,
                    })
                },
            }))
        }
    };
    ((&mut $slf:ident, $off:ident, $len:ident) -> $opt:ty { $($id:ident => $bld:expr),+ }) => {
        pub fn next_option(&mut $slf) -> Result<Option<$opt>, SniffError> {
            if $slf.next == $slf.opt_end { return Ok(None); }
            let _ = $slf.data()?;
            let id_ = $slf.reader.read_u16_at($slf.next)?;
            let $len = $slf.reader.read_u16()?;
            $slf.next += (4 + $len + ((4 - ($len % 4)) % 4)) as u64;
            let $off = $slf.reader.pos;
            Ok(Some(match id_ {
                OPT_ENDOFOPT => {
                    if $len != 0 { return Err(SniffError::MalformedCapture); }
                    return Ok(None);
                },
                OPT_COMMENT => {
                    <$opt>::Comment(StringOpt {
                        reader: $slf.reader,
                        offset: $off,
                        len: $len,
                    })
                },
                $($id => $bld),+,
                _ => {
                    <$opt>::Unknown(RawOpt {
                        reader: $slf.reader,
                        code: id_,
                        offset: $off,
                        len: $len,
                    })
                },
            }))
        }
    };
    ((&mut $slf:ident, $off:ident, $len:ident) -> $opt:ty { $($id:ident => $bld:expr),+ , }) => {
        impl_next_opt!((&mut $slf, $off, $len) -> $opt { $($id => $bld),+ });
    };
}

impl<'a, F: BufRead + Seek> SectionHeaderBlock<'a, F> {
    fn new(rdr: &'a mut Reader<F>, len: u32) -> Result<Self, SniffError> {
        let mut magic = [0u8; 4];
        rdr.read_buf(&mut magic)?;
        let magic = u32::from_ne_bytes(magic);
        match magic {
            BE_MAGIC => {
                rdr.be = true;
            }
            LE_MAGIC => {
                rdr.be = false;
            }
            _ => {
                return Err(SniffError::MalformedCapture);
            }
        }
        rdr.first_snaplen = None;
        let opt_end = rdr.pos + ((len as u64) - 16);
        let next = rdr.pos + 12;
        Ok(Self {
            reader: rdr,
            data: None,
            next,
            opt_end,
        })
    }

    fn data(&mut self) -> Result<&mut SHB, SniffError> {
        let ready = self.data.is_some();
        if !ready {
            let version_major = self.reader.read_u16()?;
            let version_minor = self.reader.read_u16()?;
            let section_len = self.reader.read_u64()?;
            self.data = Some(SHB {
                version_major,
                version_minor,
                section_len,
            });
        }
        Ok(guarantee(self.data.as_mut()))
    }

    pub fn version_major(&mut self) -> Result<u16, SniffError> {
        Ok(self.data()?.version_major)
    }

    pub fn version_minor(&mut self) -> Result<u16, SniffError> {
        Ok(self.data()?.version_minor)
    }

    pub fn section_length(&mut self) -> Result<u64, SniffError> {
        Ok(self.data()?.section_len)
    }

    impl_next_opt!((&mut self, offset, len) -> SHBOption<'_, F> {
        SHB_HARDWARE => SHBOption::Hardware(StringOpt {
            reader: self.reader,
            offset,
            len,
        }),
        SHB_OS => SHBOption::OS(StringOpt {
            reader: self.reader,
            offset,
            len,
        }),
        SHB_USERAPPL => SHBOption::UserApplication(StringOpt {
            reader: self.reader,
            offset,
            len,
        }),
    });
}

impl<'a, F: BufRead + Seek> InterfaceDescriptionBlock<'a, F> {
    fn new(rdr: &'a mut Reader<F>, len: u32) -> Result<Self, SniffError> {
        let opt_end = rdr.pos + ((len as u64) - 20);
        let next = rdr.pos + 8;
        let mut blk = Self {
            reader: rdr,
            data: None,
            next,
            opt_end,
        };
        let has_first = blk.reader.first_snaplen.is_some();
        if has_first {
            let snaplen = blk.data()?.snaplen;
            blk.reader.first_snaplen = Some(snaplen);
        }
        Ok(blk)
    }

    fn data(&mut self) -> Result<&mut IDB, SniffError> {
        let ready = self.data.is_some();
        if !ready {
            let link_type = self.reader.read_u16()?;
            self.reader.skip(2)?;
            let snaplen = self.reader.read_u32()?;
            self.data = Some(IDB { link_type, snaplen });
        }
        Ok(guarantee(self.data.as_mut()))
    }

    pub fn link_type(&mut self) -> Result<u16, SniffError> {
        Ok(self.data()?.link_type)
    }

    pub fn snaplen(&mut self) -> Result<u32, SniffError> {
        Ok(self.data()?.snaplen)
    }

    impl_next_opt!((&mut self, offset, len) -> IDBOption<'_, F> {
        IF_NAME => IDBOption::Name(StringOpt {
            reader: self.reader,
            offset,
            len,
        }),
        IF_DESCRIPTION => IDBOption::Description(StringOpt {
            reader: self.reader,
            offset,
            len,
        }),
        IF_IPV4ADDR => {
            if len != 8 {
                return Err(SniffError::MalformedCapture);
            }
            IDBOption::IPv4(IPv4IfaceOpt {
                reader: self.reader,
                addr: None,
            })
        },
        IF_IPV6ADDR => {
            if len != 17 {
                return Err(SniffError::MalformedCapture);
            }
            IDBOption::IPv6(IPv6IfaceOpt {
                reader: self.reader,
                addr: None,
            })
        },
        IF_MACADDR => {
            if len != 6 {
                return Err(SniffError::MalformedCapture);
            }
            IDBOption::MAC(MACOpt {
                reader: self.reader,
                addr: None,
            })
        },
        IF_EUIADDR => {
            if len != 8 {
                return Err(SniffError::MalformedCapture);
            }
            IDBOption::EUI(EUIOpt {
                reader: self.reader,
                addr: None,
            })
        },
        IF_SPEED => {
            if len != 8 {
                return Err(SniffError::MalformedCapture);
            }
            IDBOption::Speed(U64Opt {
                reader: self.reader,
                value: None,
            })
        },
        IF_TSRESOL => {
            if len != 1 {
                return Err(SniffError::MalformedCapture);
            }
            IDBOption::TSResol(U8Opt {
                reader: self.reader,
                value: None,
            })
        },
        IF_TZONE => {
            if len != 4 {
                return Err(SniffError::MalformedCapture);
            }
            IDBOption::TimeZone(I32Opt {
                reader: self.reader,
                value: None,
            })
        },
        IF_FILTER => {
            if len < 1 {
                return Err(SniffError::MalformedCapture);
            }
            let code = self.reader.read_u8_at(offset)?;
            match code {
                0 => IDBOption::Filter(FilterOpt::String(StringFilterOpt {
                    reader: self.reader,
                    offset: offset + 1,
                    len: len - 1,
                })),
                1 => IDBOption::Filter(FilterOpt::ByteCode(ByteCodeFilterOpt {
                    reader: self.reader,
                    offset: offset + 1,
                    len: len - 1,
                })),
                _ => IDBOption::Filter(FilterOpt::Unknown(RawFilterOpt {
                    reader: self.reader,
                    code,
                    offset: offset + 1,
                    len: len - 1,
                })),
            }
        },
        IF_OS => IDBOption::OS(StringOpt {
            reader: self.reader,
            offset,
            len,
        }),
        IF_FCSLEN => {
            if len != 1 {
                return Err(SniffError::MalformedCapture);
            }
            IDBOption::FCSLen(U8Opt {
                reader: self.reader,
                value: None,
            })
        },
        IF_TSOFFSET => {
            if len != 8 {
                return Err(SniffError::MalformedCapture);
            }
            IDBOption::TSOffset(I64Opt {
                reader: self.reader,
                value: None,
            })
        },
        IF_HARDWARE => IDBOption::Hardware(StringOpt {
            reader: self.reader,
            offset,
            len,
        }),
        IF_TXSPEED => {
            if len != 8 {
                return Err(SniffError::MalformedCapture);
            }
            IDBOption::TXSpeed(U64Opt {
                reader: self.reader,
                value: None,
            })
        },
        IF_RXSPEED => {
            if len != 8 {
                return Err(SniffError::MalformedCapture);
            }
            IDBOption::RXSpeed(U64Opt {
                reader: self.reader,
                value: None,
            })
        },
    });
}

impl<'a, F: BufRead + Seek> EnhancedPacketBlock<'a, F> {
    fn new(rdr: &'a mut Reader<F>, len: u32) -> Result<Self, SniffError> {
        let offset = rdr.pos + 20;
        let opt_end = rdr.pos + ((len as u64) - 12);
        Ok(Self {
            reader: rdr,
            data: None,
            offset,
            next: offset,
            opt_end,
        })
    }

    fn data(&mut self) -> Result<&mut EPB, SniffError> {
        let ready = self.data.is_some();
        if !ready {
            let iface = self.reader.read_u32_at(self.offset - 20)?;
            let ts_hi = self.reader.read_u32()?;
            let ts_lo = self.reader.read_u32()?;
            let cap_len = self.reader.read_u32()?;
            let orig_len = self.reader.read_u32()?;
            let ts = ((ts_hi as u64) << 32) | (ts_lo as u64);
            self.next = self.offset + (cap_len as u64) + (((4 - (cap_len % 4)) % 4) as u64);
            self.data = Some(EPB {
                iface,
                ts,
                cap_len,
                orig_len,
            });
        }
        Ok(guarantee(self.data.as_mut()))
    }

    pub fn interface_id(&mut self) -> Result<u32, SniffError> {
        Ok(self.data()?.iface)
    }

    pub fn timestamp(&mut self) -> Result<u64, SniffError> {
        Ok(self.data()?.ts)
    }

    pub fn capture_length(&mut self) -> Result<u32, SniffError> {
        Ok(self.data()?.cap_len)
    }

    pub fn original_length(&mut self) -> Result<u32, SniffError> {
        Ok(self.data()?.orig_len)
    }

    pub fn packet_data(&mut self, buf: &mut Vec<u8>) -> Result<(), SniffError> {
        buf.resize(self.capture_length()? as usize, 0);
        self.reader.read_buf_at(&mut buf[..], self.offset)?;
        Ok(())
    }

    impl_next_opt!((&mut self, offset, len) -> EPBOption<'_, F> {
        EPB_FLAGS => EPBOption::Flags(PacketFlagsOpt {
            reader: self.reader,
            flags: None,
        }),
        EPB_DROPCOUNT => {
            if len != 8 { return Err(SniffError::MalformedCapture); }
            EPBOption::DropCount(U64Opt {
                reader: self.reader,
                value: None,
            })
        },
        EPB_PACKETID => {
            if len != 8 { return Err(SniffError::MalformedCapture); }
            EPBOption::PacketId(U64Opt {
                reader: self.reader,
                value: None,
            })
        },
        EPB_QUEUE => {
            if len != 4 { return Err(SniffError::MalformedCapture); }
            EPBOption::PacketId(U64Opt {
                reader: self.reader,
                value: None,
            })
        },
        EPB_VERDICT => {
            if len < 1 { return Err(SniffError::MalformedCapture); }
            let id = self.reader.read_u8()?;
            EPBOption::Verdict(match id {
                0 => VerdictOpt::Hardware(HardwareVerdictOpt {
                    reader: self.reader,
                    offset: offset + 1,
                    len: len - 1,
                }),
                1 => VerdictOpt::LinuxEBPFTC(LinuxVerdictOpt {
                    reader: self.reader,
                    verdict: None,
                }),
                2 => VerdictOpt::LinuxEBPFTC(LinuxVerdictOpt {
                    reader: self.reader,
                    verdict: None,
                }),
                _ => VerdictOpt::Unknown(RawVerdictOpt {
                    reader: self.reader,
                    id,
                    offset: offset + 1,
                    len: len - 1,
                }),
            })
        },
        EPB_HASH => {
            if len < 1 { return Err(SniffError::MalformedCapture); }
            let id = self.reader.read_u8()?;
            EPBOption::Hash(match id {
                0 => HashOpt::TwosComplement(TwosComplementOpt {
                    reader: self.reader,
                    offset: offset + 1,
                    len: len - 1,
                }),
                1 => HashOpt::XOR(XOROpt {
                    reader: self.reader,
                    offset: offset + 1,
                    len: len - 1,
                }),
                2 => HashOpt::CRC32(CRC32Opt {
                    reader: self.reader,
                    crc: None,
                }),
                3 => HashOpt::MD5(MD5Opt {
                    reader: self.reader,
                    hash: None,
                }),
                4 => HashOpt::SHA1(SHA1Opt {
                    reader: self.reader,
                    hash: None,
                }),
                5 => HashOpt::Toeplitz(ToeplitzOpt {
                    reader: self.reader,
                    hash: None,
                }),
                _ => HashOpt::Unknown(RawHashOpt {
                    reader: self.reader,
                    id,
                    offset: offset + 1,
                    len: len - 1,
                }),
            })
        },
    });
}

impl<'a, F: BufRead + Seek> SimplePacketBlock<'a, F> {
    fn new(rdr: &'a mut Reader<F>, _len: u32) -> Result<Self, SniffError> {
        if rdr.first_snaplen.is_none() {
            return Err(SniffError::MalformedCapture);
        }

        let offset = rdr.pos + 4;
        Ok(Self {
            reader: rdr,
            data: None,
            offset,
        })
    }

    fn data(&mut self) -> Result<&mut SPB, SniffError> {
        let ready = self.data.is_some();
        if !ready {
            let snaplen = self.reader.first_snaplen.unwrap_or(0);
            let orig_len = self.reader.read_u32_at(self.offset - 4)?;
            let cap_len = std::cmp::min(snaplen, orig_len);
            self.data = Some(SPB { cap_len, orig_len });
        }
        Ok(guarantee(self.data.as_mut()))
    }

    pub fn capture_length(&mut self) -> Result<u32, SniffError> {
        Ok(self.data()?.cap_len)
    }

    pub fn original_length(&mut self) -> Result<u32, SniffError> {
        Ok(self.data()?.orig_len)
    }

    pub fn packet_data(&mut self, buf: &mut Vec<u8>) -> Result<(), SniffError> {
        buf.resize(self.capture_length()? as usize, 0);
        self.reader.read_buf_at(&mut buf[..], self.offset)?;
        Ok(())
    }
}

impl<'a, F: BufRead + Seek> NameResolutionBlock<'a, F> {
    fn new(rdr: &'a mut Reader<F>, len: u32) -> Result<Self, SniffError> {
        let next_rec = rdr.pos;
        let opt_end = next_rec + (len as u64) - 12;
        Ok(Self {
            reader: rdr,
            next_rec,
            next: 0,
            opt_end,
        })
    }

    fn data(&mut self) -> Result<(), SniffError> {
        let ready = self.next != 0;
        let mut next_rec = self.next_rec;
        if !ready && next_rec == u64::MAX {
            self.reader.jump_to(next_rec)?;
            loop {
                let id = self.reader.read_u16_at(next_rec)?;
                if id == 0 {
                    break;
                } else {
                    let len = self.reader.read_u16()? as u64;
                    let len = len + ((4 - (len % 4)) % 4);
                    next_rec += len;
                }
            }
        }
        Ok(())
    }

    pub fn next_record(&mut self) -> Result<Option<NameRecord<'_, F>>, SniffError> {
        if self.next_rec == u64::MAX {
            return Ok(None);
        }
        let id = self.reader.read_u16_at(self.next_rec)?;
        let len = self.reader.read_u16()?;
        self.next_rec += (4 + len + ((4 - (len % 4)) % 4)) as u64;
        let offset = self.reader.pos;
        Ok(Some(match id {
            NRB_RECORD_END => {
                if len != 0 {
                    return Err(SniffError::MalformedCapture);
                }
                self.next_rec = u64::MAX;
                return Ok(None);
            }
            NRB_RECORD_IPV4 => NameRecord::IPv4(IPv4NameRecord {
                reader: self.reader,
                addr: None,
                next: offset + 4,
                names_end: offset + (len as u64),
            }),
            NRB_RECORD_IPV6 => NameRecord::IPv6(IPv6NameRecord {
                reader: self.reader,
                addr: None,
                next: offset + 16,
                names_end: offset + (len as u64),
            }),
            _ => NameRecord::Other(RawOpt {
                reader: self.reader,
                code: id,
                offset,
                len,
            }),
        }))
    }

    impl_next_opt!((&mut self, offset, len) -> NRBOption<'_, F> {
        NS_DNSNAME => NRBOption::DNSName(StringOpt {
            reader: self.reader,
            offset,
            len,
        }),
        NS_DNSIP4ADDR => NRBOption::DNSIPv4Addr(IPv4Opt {
            reader: self.reader,
            addr: None,
        }),
        NS_DNSIP6ADDR => NRBOption::DNSIPv6Addr(IPv6Opt {
            reader: self.reader,
            addr: None,
        }),
    });
}

impl<'a, F: BufRead + Seek> InterfaceStatisticsBlock<'a, F> {
    fn new(rdr: &'a mut Reader<F>, len: u32) -> Result<Self, SniffError> {
        let next = rdr.pos + 12;
        let opt_end = rdr.pos + (len as u64) - 12;
        Ok(Self {
            reader: rdr,
            data: None,
            next,
            opt_end,
        })
    }

    fn data(&mut self) -> Result<&mut ISB, SniffError> {
        let ready = self.data.is_some();
        if !ready {
            let iface = self.reader.read_u32()?;
            let ts_hi = self.reader.read_u32()?;
            let ts_lo = self.reader.read_u32()?;
            let ts = ((ts_hi as u64) << 32) | (ts_lo as u64);
            self.data = Some(ISB { iface, ts });
        }
        Ok(guarantee(self.data.as_mut()))
    }

    pub fn interface_id(&mut self) -> Result<u32, SniffError> {
        Ok(self.data()?.iface)
    }

    pub fn timestamp(&mut self) -> Result<u64, SniffError> {
        Ok(self.data()?.ts)
    }

    impl_next_opt!((&mut self, offset, len) -> ISBOption<'_, F> {
        ISB_STARTTIME => {
            if len != 8 {
                return Err(SniffError::MalformedCapture);
            }
            ISBOption::StartTime(TimestampOpt {
                reader: self.reader,
                ts: None,
            })
        },
        ISB_ENDTIME => {
            if len != 8 {
                return Err(SniffError::MalformedCapture);
            }
            ISBOption::EndTime(TimestampOpt {
                reader: self.reader,
                ts: None,
            })
        },
        ISB_IFRECV => {
            if len != 8 {
                return Err(SniffError::MalformedCapture);
            }
            ISBOption::IfRecv(U64Opt {
                reader: self.reader,
                value: None,
            })
        },
        ISB_IFDROP => {
            if len != 8 {
                return Err(SniffError::MalformedCapture);
            }
            ISBOption::IfDrop(U64Opt {
                reader: self.reader,
                value: None,
            })
        },
        ISB_FILTERACCEPT => {
            if len != 8 {
                return Err(SniffError::MalformedCapture);
            }
            ISBOption::FilterAccept(U64Opt {
                reader: self.reader,
                value: None,
            })
        },
        ISB_OSDROP => {
            if len != 8 {
                return Err(SniffError::MalformedCapture);
            }
            ISBOption::OSDrop(U64Opt {
                reader: self.reader,
                value: None,
            })
        },
        ISB_USRDELIV => {
            if len != 8 {
                return Err(SniffError::MalformedCapture);
            }
            ISBOption::UserDeliv(U64Opt {
                reader: self.reader,
                value: None,
            })
        },
    });
}

impl<'a, F: BufRead + Seek> SystemdJournalExportBlock<'a, F> {
    fn new(rdr: &'a mut Reader<F>, len: u32) -> Result<Self, SniffError> {
        let offset = rdr.pos;
        Ok(Self {
            reader: rdr,
            len,
            offset,
        })
    }

    pub fn journal_entry(&mut self, entry: &mut String) -> Result<(), SniffError> {
        entry.reserve(self.len as usize);
        self.reader.read_strz_at(entry, self.offset)
    }
}

impl<'a, F: BufRead + Seek> DecryptionSecretsBlock<'a, F> {
    fn new(rdr: &'a mut Reader<F>, len: u32) -> Result<Self, SniffError> {
        let offset = rdr.pos + 8;
        let opt_end = rdr.pos + (len as u64) - 12;
        Ok(Self {
            reader: rdr,
            data: None,
            offset,
            next: 0,
            opt_end,
        })
    }

    fn data(&mut self) -> Result<&mut DSB, SniffError> {
        let ready = self.data.is_some();
        if !ready {
            let secrets_type = self.reader.read_u32_at(self.offset - 8)?;
            let secrets_len = self.reader.read_u32()?;
            self.data = Some(DSB {
                secrets_type,
                secrets_len,
            });
            let len = secrets_len as u64;
            self.next = self.offset + len + ((4 - (len % 4)) % 4);
        }
        Ok(guarantee(self.data.as_mut()))
    }

    pub fn secrets_type(&mut self) -> Result<u32, SniffError> {
        Ok(self.data()?.secrets_type)
    }

    pub fn secrets_length(&mut self) -> Result<u32, SniffError> {
        Ok(self.data()?.secrets_len)
    }

    pub fn secrets(&mut self, buf: &mut Vec<u8>) -> Result<(), SniffError> {
        let len = self.secrets_length()?;
        buf.resize(len as usize, 0);
        self.reader.read_buf_at(buf, self.offset)?;
        Ok(())
    }

    impl_next_opt!((&mut self, offset, len) -> DSBOption<'_, F> {});
}

impl<'a, F: BufRead + Seek> RawBlock<'a, F> {
    fn new(rdr: &'a mut Reader<F>, id: u32, len: u32) -> Result<Self, SniffError> {
        let offset = rdr.pos;
        Ok(Self {
            reader: rdr,
            id,
            len: len - 12,
            offset,
        })
    }

    pub fn block_id(&self) -> u32 {
        self.id
    }

    pub fn content_length(&self) -> u32 {
        self.len
    }

    pub fn content(&mut self, buf: &mut Vec<u8>) -> Result<(), SniffError> {
        buf.resize(self.len as usize, 0);
        self.reader.read_buf_at(&mut buf[..], self.offset)?;
        Ok(())
    }
}

impl<'a, F: BufRead + Seek> RawOpt<'a, F> {
    pub fn option_code(&self) -> u16 {
        self.code
    }

    pub fn option_length(&self) -> u16 {
        self.len
    }

    pub fn content(&mut self, buf: &mut Vec<u8>) -> Result<(), SniffError> {
        buf.resize(self.len as usize, 0);
        self.reader.read_buf_at(&mut buf[..], self.offset)?;
        Ok(())
    }
}

impl<'a, F: BufRead + Seek> StringOpt<'a, F> {
    pub fn string_length(&self) -> u16 {
        self.len
    }

    pub fn string(&mut self, s: &mut String) -> Result<(), SniffError> {
        let mut buf = std::mem::replace(s, String::new()).into_bytes();
        buf.resize(self.len as usize, 0);
        self.reader.read_buf_at(&mut buf[..], self.offset)?;
        *s = String::from_utf8(buf).map_err(|_| SniffError::MalformedCapture)?;
        Ok(())
    }
}

impl<'a, F: BufRead + Seek> U8Opt<'a, F> {
    pub fn value(&mut self) -> Result<u8, SniffError> {
        let ready = self.value.is_some();
        if !ready {
            let val = self.reader.read_u8()?;
            self.value = Some(val);
            Ok(val)
        } else {
            Ok(guarantee(self.value))
        }
    }
}

impl<'a, F: BufRead + Seek> U32Opt<'a, F> {
    pub fn value(&mut self) -> Result<u32, SniffError> {
        let ready = self.value.is_some();
        if !ready {
            let val = self.reader.read_u32()?;
            self.value = Some(val);
            Ok(val)
        } else {
            Ok(guarantee(self.value))
        }
    }
}

impl<'a, F: BufRead + Seek> I32Opt<'a, F> {
    pub fn value(&mut self) -> Result<i32, SniffError> {
        let ready = self.value.is_some();
        if !ready {
            let val = self.reader.read_i32()?;
            self.value = Some(val);
            Ok(val)
        } else {
            Ok(guarantee(self.value))
        }
    }
}

impl<'a, F: BufRead + Seek> U64Opt<'a, F> {
    pub fn value(&mut self) -> Result<u64, SniffError> {
        let ready = self.value.is_some();
        if !ready {
            let val = self.reader.read_u64()?;
            self.value = Some(val);
            Ok(val)
        } else {
            Ok(guarantee(self.value))
        }
    }
}

impl<'a, F: BufRead + Seek> I64Opt<'a, F> {
    pub fn value(&mut self) -> Result<i64, SniffError> {
        let ready = self.value.is_some();
        if !ready {
            let val = self.reader.read_i64()?;
            self.value = Some(val);
            Ok(val)
        } else {
            Ok(guarantee(self.value))
        }
    }
}

impl<'a, F: BufRead + Seek> IPv4Opt<'a, F> {
    pub fn address(&mut self) -> Result<IPv4Address, SniffError> {
        let ready = self.addr.is_some();
        if !ready {
            let mut addr = [0u8; 4];
            self.reader.read_buf(&mut addr[..])?;
            let addr = IPv4Address::from(addr);
            self.addr = Some(addr);
            Ok(addr)
        } else {
            Ok(guarantee(self.addr))
        }
    }
}

impl<'a, F: BufRead + Seek> IPv6Opt<'a, F> {
    pub fn address(&mut self) -> Result<IPv6Address, SniffError> {
        let ready = self.addr.is_some();
        if !ready {
            let mut addr = [0u8; 16];
            self.reader.read_buf(&mut addr[..])?;
            let addr = IPv6Address::from(addr);
            self.addr = Some(addr);
            Ok(addr)
        } else {
            Ok(guarantee(self.addr))
        }
    }
}

impl<'a, F: BufRead + Seek> IPv4IfaceOpt<'a, F> {
    fn data(&mut self) -> Result<&mut (IPv4Address, IPv4Address), SniffError> {
        let ready = self.addr.is_some();
        if !ready {
            let mut addr = [0u8; 8];
            self.reader.read_buf(&mut addr[..])?;
            self.addr = Some((
                IPv4Address::new(addr[0], addr[1], addr[2], addr[3]),
                IPv4Address::new(addr[4], addr[5], addr[6], addr[7]),
            ));
        }
        Ok(guarantee(self.addr.as_mut()))
    }

    pub fn address(&mut self) -> Result<IPv4Address, SniffError> {
        Ok(self.data()?.0)
    }

    pub fn netmask(&mut self) -> Result<IPv4Address, SniffError> {
        Ok(self.data()?.1)
    }
}

impl<'a, F: BufRead + Seek> IPv6IfaceOpt<'a, F> {
    fn data(&mut self) -> Result<&mut (IPv6Address, u8), SniffError> {
        let ready = self.addr.is_some();
        if !ready {
            let mut addr = [0u8; 17];
            self.reader.read_buf(&mut addr[..])?;
            self.addr = Some((
                IPv6Address::new(
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                    addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15],
                ),
                addr[16],
            ));
        }
        Ok(guarantee(self.addr.as_mut()))
    }

    pub fn address(&mut self) -> Result<IPv6Address, SniffError> {
        Ok(self.data()?.0)
    }

    pub fn prefix_length(&mut self) -> Result<u8, SniffError> {
        Ok(self.data()?.1)
    }
}

impl<'a, F: BufRead + Seek> MACOpt<'a, F> {
    pub fn address(&mut self) -> Result<MACAddress, SniffError> {
        let ready = self.addr.is_some();
        if !ready {
            let mut addr = [0u8; 6];
            self.reader.read_buf(&mut addr[..])?;
            let addr = MACAddress::from(addr);
            self.addr = Some(addr);
            Ok(addr)
        } else {
            Ok(guarantee(self.addr))
        }
    }
}

impl<'a, F: BufRead + Seek> EUIOpt<'a, F> {
    pub fn address(&mut self) -> Result<EUIAddress, SniffError> {
        let ready = self.addr.is_some();
        if !ready {
            let mut addr = [0u8; 8];
            self.reader.read_buf(&mut addr[..])?;
            let addr = EUIAddress::from(addr);
            self.addr = Some(addr);
            Ok(addr)
        } else {
            Ok(guarantee(self.addr))
        }
    }
}

impl<'a, F: BufRead + Seek> TimestampOpt<'a, F> {
    pub fn timestamp(&mut self) -> Result<u64, SniffError> {
        let ready = self.ts.is_some();
        if !ready {
            let ts_hi = self.reader.read_u32()?;
            let ts_lo = self.reader.read_u32()?;
            let ts = ((ts_hi as u64) << 32) | (ts_lo as u64);
            self.ts = Some(ts);
            Ok(ts)
        } else {
            Ok(guarantee(self.ts))
        }
    }
}

impl<'a, F: BufRead + Seek> StringFilterOpt<'a, F> {
    pub fn filter_string(&mut self, filter: &mut String) -> Result<(), SniffError> {
        let mut buf = std::mem::replace(filter, String::new()).into_bytes();
        buf.resize(self.len as usize, 0);
        self.reader.read_buf_at(&mut buf[..], self.offset)?;
        *filter = String::from_utf8(buf).map_err(|_| SniffError::MalformedCapture)?;
        Ok(())
    }
}

impl<'a, F: BufRead + Seek> ByteCodeFilterOpt<'a, F> {
    pub fn filter_byte_code(&mut self, filter: &mut Vec<u8>) -> Result<(), SniffError> {
        filter.resize(self.len as usize, 0);
        self.reader.read_buf_at(&mut filter[..], self.offset)?;
        Ok(())
    }
}

impl<'a, F: BufRead + Seek> RawFilterOpt<'a, F> {
    pub fn filter_type(&self) -> u8 {
        self.code
    }

    pub fn filter_length(&self) -> u16 {
        self.len
    }

    pub fn filter_data(&mut self, buf: &mut Vec<u8>) -> Result<(), SniffError> {
        buf.resize(self.len as usize, 0);
        self.reader.read_buf_at(&mut buf[..], self.offset)?;
        Ok(())
    }
}

impl<'a, F: BufRead + Seek> PacketFlagsOpt<'a, F> {
    pub fn raw_flags(&mut self) -> Result<u32, SniffError> {
        let ready = self.flags.is_some();
        if !ready {
            let flags = self.reader.read_u32()?;
            self.flags = Some(flags);
            Ok(flags)
        } else {
            Ok(guarantee(self.flags))
        }
    }

    pub fn direction(&mut self) -> Result<Direction, SniffError> {
        Ok(match self.raw_flags()? & 0b0011 {
            0b00 => Direction::Unknown,
            0b01 => Direction::Inbound,
            0b10 => Direction::Outbound,
            _ => {
                return Err(SniffError::MalformedCapture);
            }
        })
    }

    pub fn reception_type(&mut self) -> Result<ReceptionType, SniffError> {
        Ok(match (self.raw_flags()? >> 2) & 0b111 {
            0b000 => ReceptionType::Unspecified,
            0b001 => ReceptionType::Unicast,
            0b010 => ReceptionType::Multicast,
            0b011 => ReceptionType::Broadcast,
            0b100 => ReceptionType::Promiscuous,
            _ => {
                return Err(SniffError::MalformedCapture);
            }
        })
    }

    pub fn fcs_length(&mut self) -> Result<u8, SniffError> {
        Ok(((self.raw_flags()? >> 5) & 0b0000_1111) as u8)
    }

    pub fn link_layer_dependent_errors(&mut self) -> Result<bool, SniffError> {
        Ok(((self.raw_flags()? >> 31) & 1) != 0)
    }

    pub fn preamble_error(&mut self) -> Result<bool, SniffError> {
        Ok(((self.raw_flags()? >> 30) & 1) != 0)
    }

    pub fn start_frame_delimiter_error(&mut self) -> Result<bool, SniffError> {
        Ok(((self.raw_flags()? >> 29) & 1) != 0)
    }

    pub fn unaligned_frame_error(&mut self) -> Result<bool, SniffError> {
        Ok(((self.raw_flags()? >> 28) & 1) != 0)
    }

    pub fn wrong_inter_frame_gap_error(&mut self) -> Result<bool, SniffError> {
        Ok(((self.raw_flags()? >> 27) & 1) != 0)
    }

    pub fn packet_too_short_error(&mut self) -> Result<bool, SniffError> {
        Ok(((self.raw_flags()? >> 26) & 1) != 0)
    }

    pub fn packet_too_long_error(&mut self) -> Result<bool, SniffError> {
        Ok(((self.raw_flags()? >> 25) & 1) != 0)
    }

    pub fn crc_error(&mut self) -> Result<bool, SniffError> {
        Ok(((self.raw_flags()? >> 24) & 1) != 0)
    }
}

impl<'a, F: BufRead + Seek> TwosComplementOpt<'a, F> {
    pub fn hash(&mut self, buf: &mut Vec<u8>) -> Result<(), SniffError> {
        buf.resize(self.len as usize, 0);
        self.reader.read_buf_at(&mut buf[..], self.offset)?;
        Ok(())
    }
}

impl<'a, F: BufRead + Seek> XOROpt<'a, F> {
    pub fn hash(&mut self, buf: &mut Vec<u8>) -> Result<(), SniffError> {
        buf.resize(self.len as usize, 0);
        self.reader.read_buf_at(&mut buf[..], self.offset)?;
        Ok(())
    }
}

impl<'a, F: BufRead + Seek> CRC32Opt<'a, F> {
    pub fn hash(&mut self) -> Result<[u8; 4], SniffError> {
        let ready = self.crc.is_some();
        if !ready {
            let mut buf = [0u8; 4];
            self.reader.read_buf(&mut buf[..])?;
            self.crc = Some(buf.clone());
            Ok(buf)
        } else {
            Ok(guarantee(self.crc.as_ref()).clone())
        }
    }
}

impl<'a, F: BufRead + Seek> MD5Opt<'a, F> {
    pub fn hash(&mut self) -> Result<[u8; 16], SniffError> {
        let ready = self.hash.is_some();
        if !ready {
            let mut buf = [0u8; 16];
            self.reader.read_buf(&mut buf[..])?;
            self.hash = Some(buf.clone());
            Ok(buf)
        } else {
            Ok(guarantee(self.hash.as_ref()).clone())
        }
    }
}

impl<'a, F: BufRead + Seek> SHA1Opt<'a, F> {
    pub fn hash(&mut self) -> Result<[u8; 20], SniffError> {
        let ready = self.hash.is_some();
        if !ready {
            let mut buf = [0u8; 20];
            self.reader.read_buf(&mut buf[..])?;
            self.hash = Some(buf.clone());
            Ok(buf)
        } else {
            Ok(guarantee(self.hash.as_ref()).clone())
        }
    }
}

impl<'a, F: BufRead + Seek> ToeplitzOpt<'a, F> {
    pub fn hash(&mut self) -> Result<[u8; 4], SniffError> {
        let ready = self.hash.is_some();
        if !ready {
            let mut buf = [0u8; 4];
            self.reader.read_buf(&mut buf[..])?;
            self.hash = Some(buf.clone());
            Ok(buf)
        } else {
            Ok(guarantee(self.hash.as_ref()).clone())
        }
    }
}

impl<'a, F: BufRead + Seek> RawHashOpt<'a, F> {
    pub fn hash_type(&self) -> u8 {
        self.id
    }

    pub fn hash_data(&mut self, buf: &mut Vec<u8>) -> Result<(), SniffError> {
        buf.resize(self.len as usize, 0);
        self.reader.read_buf_at(&mut buf[..], self.offset)?;
        Ok(())
    }
}

impl<'a, F: BufRead + Seek> HardwareVerdictOpt<'a, F> {
    pub fn verdict(&mut self, buf: &mut Vec<u8>) -> Result<(), SniffError> {
        buf.resize(self.len as usize, 0);
        self.reader.read_buf_at(&mut buf[..], self.offset)?;
        Ok(())
    }
}

impl<'a, F: BufRead + Seek> LinuxVerdictOpt<'a, F> {
    pub fn verdict(&mut self) -> Result<u64, SniffError> {
        let ready = self.verdict.is_some();
        if !ready {
            let v = self.reader.read_u64()?;
            self.verdict = Some(v);
            Ok(v)
        } else {
            Ok(guarantee(self.verdict))
        }
    }
}

impl<'a, F: BufRead + Seek> RawVerdictOpt<'a, F> {
    pub fn verdict_type(&self) -> u8 {
        self.id
    }

    pub fn verdict_data(&mut self, buf: &mut Vec<u8>) -> Result<(), SniffError> {
        buf.resize(self.len as usize, 0);
        self.reader.read_buf_at(&mut buf[..], self.offset)?;
        Ok(())
    }
}

impl<'a, F: BufRead + Seek> IPv4NameRecord<'a, F> {
    pub fn address(&mut self) -> Result<IPv4Address, SniffError> {
        let ready = self.addr.is_some();
        if !ready {
            let mut addr = [0u8; 4];
            self.reader.read_buf(&mut addr[..])?;
            let addr = IPv4Address::from(addr);
            self.addr = Some(addr);
            Ok(addr)
        } else {
            Ok(guarantee(self.addr))
        }
    }

    pub fn next_name(&mut self, name: &mut String) -> Result<Option<()>, SniffError> {
        if self.next == self.names_end {
            return Ok(None);
        }

        let _ = self.address()?;

        self.reader.read_strz_at(name, self.next)?;
        if name.is_empty() {
            self.next = self.names_end;
            return Ok(None);
        }
        self.next += (name.len() as u64) + 1;
        Ok(Some(()))
    }
}

impl<'a, F: BufRead + Seek> IPv6NameRecord<'a, F> {
    pub fn address(&mut self) -> Result<IPv6Address, SniffError> {
        let ready = self.addr.is_some();
        if !ready {
            let mut addr = [0u8; 16];
            self.reader.read_buf(&mut addr[..])?;
            let addr = IPv6Address::from(addr);
            self.addr = Some(addr);
            Ok(addr)
        } else {
            Ok(guarantee(self.addr))
        }
    }

    pub fn next_name(&mut self, name: &mut String) -> Result<Option<()>, SniffError> {
        if self.next == self.names_end {
            return Ok(None);
        }

        let _ = self.address()?;

        self.reader.read_strz_at(name, self.next)?;
        if name.is_empty() {
            self.next = self.names_end;
            return Ok(None);
        }
        self.next += (name.len() as u64) + 1;
        Ok(Some(()))
    }
}
