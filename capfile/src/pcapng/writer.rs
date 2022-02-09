use super::*;
use sniffle_core::TransmitError;
use std::io::{Seek, SeekFrom, Write};

pub struct Writer<F: Write + Seek> {
    file: F,
    be: bool,
    section_start: u64,
    first_snaplen: Option<u32>,
}

pub type FileWriter = Writer<std::io::BufWriter<std::fs::File>>;

pub struct RawBlockWriter<'a, F: Write + Seek> {
    writer: &'a mut Writer<F>,
    body_start: u64,
    finished: bool,
}

pub struct RawOptionWriter<'a, 'b, F: Write + Seek> {
    block: &'a mut RawBlockWriter<'b, F>,
    body_start: u64,
    finished: bool,
}

pub struct RawFilterOptionWriter<'a, 'b, 'c, F: Write + Seek> {
    opt: &'a mut RawOptionWriter<'b, 'c, F>,
}

pub struct SHBOptionWriter<'a, F: Write + Seek> {
    block: RawBlockWriter<'a, F>,
    finished: bool,
}

pub struct IDBOptionWriter<'a, F: Write + Seek> {
    block: RawBlockWriter<'a, F>,
    finished: bool,
}

pub struct FilterOptionWriter<'a, 'b, F: Write + Seek> {
    opt: RawOptionWriter<'a, 'b, F>,
}

pub struct EPBDataWriter<'a, F: Write + Seek> {
    block: Option<RawBlockWriter<'a, F>>,
    custom_orig_len: bool,
}

pub struct EPBOptionWriter<'a, F: Write + Seek> {
    block: RawBlockWriter<'a, F>,
    finished: bool,
}

pub struct PacketFlagsOptionWriter<'a, 'b, F: Write + Seek> {
    block: RawOptionWriter<'a, 'b, F>,
    flags: u32,
    finished: bool,
}

pub struct SPBDataWriter<'a, F: Write + Seek> {
    block: Option<RawBlockWriter<'a, F>>,
    custom_orig_len: bool,
}

pub struct NRBRecordWriter<'a, F: Write + Seek> {
    block: Option<RawBlockWriter<'a, F>>,
}

pub struct NRBNameWriter<'a, 'b, F: Write + Seek> {
    block: &'a mut RawBlockWriter<'b, F>,
    len_pos: u64,
}

pub struct NRBOptionWriter<'a, F: Write + Seek> {
    block: RawBlockWriter<'a, F>,
    finished: bool,
}

pub struct ISBOptionWriter<'a, F: Write + Seek> {
    block: RawBlockWriter<'a, F>,
    finished: bool,
}

pub struct SJBEntryWriter<'a, F: Write + Seek> {
    block: RawBlockWriter<'a, F>,
    finished: bool,
}

pub struct DSBSecretsWriter<'a, F: Write + Seek> {
    block: Option<RawBlockWriter<'a, F>>,
    body_start: u64,
}

pub struct DSBOptionWriter<'a, F: Write + Seek> {
    block: RawBlockWriter<'a, F>,
    finished: bool,
}

fn guarantee<T>(opt: Option<T>) -> T {
    match opt {
        Some(val) => val,
        None => unreachable!(),
    }
}

fn write_padding<F: Write>(file: &mut F, len: usize) -> std::io::Result<()> {
    const PADDING: [u8; 4] = [0u8; 4];
    file.write_all(&PADDING[..((4 - (len % 4)) % 4)])
}

impl<F: Write + Seek> Writer<F> {
    pub fn new(file: F) -> Self {
        Self {
            file,
            be: false,
            section_start: 0,
            first_snaplen: None,
        }
    }

    pub fn create<P: AsRef<std::path::Path>>(path: P) -> Result<FileWriter, TransmitError> {
        Ok(FileWriter::new(std::io::BufWriter::new(
            std::fs::File::create(path)?,
        )))
    }

    fn finish_section(&mut self) -> std::io::Result<()> {
        if self.section_start != u64::MAX {
            let end = self.file.seek(SeekFrom::End(0))?;
            self.file.seek(SeekFrom::Start(self.section_start + 16))?;
            if self.be {
                self.file
                    .write_all(&(end - self.section_start).to_be_bytes()[..])?;
            } else {
                self.file
                    .write_all(&(end - self.section_start).to_le_bytes()[..])?;
            }
            self.file.seek(SeekFrom::End(0))?;
        }
        Ok(())
    }

    pub fn write_shb(
        &mut self,
        big_endian: bool,
        version_major: u16,
        version_minor: u16,
    ) -> Result<SHBOptionWriter<'_, F>, TransmitError> {
        self.finish_section()?;
        let mut block = self.write_raw_block(SHB_ID)?;
        block.writer.be = big_endian;
        block.write_u32(0x1A2B3C4D)?;
        block.write_u16(version_major)?;
        block.write_u16(version_minor)?;
        block.write_u64(u64::MAX)?;
        Ok(SHBOptionWriter {
            block,
            finished: true,
        })
    }

    pub fn write_idb(
        &mut self,
        link_type: u16,
        snaplen: u32,
    ) -> Result<IDBOptionWriter<'_, F>, TransmitError> {
        self.first_snaplen.get_or_insert(snaplen);
        let mut block = self.write_raw_block(IDB_ID)?;
        block.write_u16(link_type)?;
        block.write_u16(0)?;
        block.write_u32(snaplen)?;
        Ok(IDBOptionWriter {
            block,
            finished: true,
        })
    }

    pub fn write_epb(
        &mut self,
        iface_id: u32,
        timestamp: u64,
    ) -> Result<EPBDataWriter<'_, F>, TransmitError> {
        let mut block = self.write_raw_block(EPB_ID)?;
        block.write_u32(iface_id)?;
        block.write_u32((timestamp >> 32) as u32)?;
        block.write_u32((timestamp & 0xFFFFFFFF) as u32)?;
        Ok(EPBDataWriter {
            block: Some(block),
            custom_orig_len: false,
        })
    }

    pub fn write_spb(&mut self) -> Result<SPBDataWriter<'_, F>, TransmitError> {
        Ok(SPBDataWriter {
            block: Some(self.write_raw_block(SPB_ID)?),
            custom_orig_len: false,
        })
    }

    pub fn write_nrb(&mut self) -> Result<NRBRecordWriter<'_, F>, TransmitError> {
        Ok(NRBRecordWriter {
            block: Some(self.write_raw_block(NRB_ID)?),
        })
    }

    pub fn write_isb(
        &mut self,
        iface_id: u32,
        timestamp: u64,
    ) -> Result<ISBOptionWriter<'_, F>, TransmitError> {
        let mut block = self.write_raw_block(ISB_ID)?;
        block.write_u32(iface_id)?;
        block.write_u32((timestamp >> 32) as u32)?;
        block.write_u32((timestamp & 0xFFFFFFFF) as u32)?;
        Ok(ISBOptionWriter {
            block,
            finished: true,
        })
    }

    pub fn write_sjb(&mut self) -> Result<SJBEntryWriter<'_, F>, TransmitError> {
        Ok(SJBEntryWriter {
            block: self.write_raw_block(SJB_ID)?,
            finished: true,
        })
    }

    pub fn write_dsb(
        &mut self,
        secrets_type: u32,
    ) -> Result<DSBSecretsWriter<'_, F>, TransmitError> {
        let mut block = self.write_raw_block(DSB_ID)?;
        block.write_u32(secrets_type)?;
        block.write_u32(0)?;
        let body_start = block.stream_position()?;
        Ok(DSBSecretsWriter {
            block: Some(block),
            body_start,
        })
    }

    pub fn write_raw_block(
        &mut self,
        block_id: u32,
    ) -> Result<RawBlockWriter<'_, F>, TransmitError> {
        Ok(RawBlockWriter::new(self, block_id)?)
    }
}

impl<'a, F: Write + Seek> RawBlockWriter<'a, F> {
    fn new(writer: &'a mut Writer<F>, id: u32) -> std::io::Result<Self> {
        if writer.be {
            writer.file.write_all(&id.to_be_bytes()[..])?;
            writer.file.write_all(&0u32.to_be_bytes()[..])?;
        } else {
            writer.file.write_all(&id.to_le_bytes()[..])?;
            writer.file.write_all(&0u32.to_le_bytes()[..])?;
        }
        let body_start = writer.file.stream_position()?;
        Ok(Self {
            writer,
            body_start,
            finished: false,
        })
    }

    fn finish_impl(&mut self) -> std::io::Result<()> {
        if !self.finished {
            let end = self.writer.file.seek(SeekFrom::End(0))?;
            let len = 12u64 + (end - self.body_start);
            let len = if self.writer.be {
                len.to_be_bytes()
            } else {
                len.to_le_bytes()
            };
            self.writer.file.write_all(&len[..])?;
            self.writer
                .file
                .seek(SeekFrom::Start(self.body_start - 4))?;
            self.writer.file.write_all(&len[..])?;
            self.writer.file.seek(SeekFrom::End(0))?;
            self.finished = true;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), TransmitError> {
        Ok(self.finish_impl()?)
    }

    pub fn big_endian(&self) -> bool {
        self.writer.be
    }

    pub fn little_endian(&self) -> bool {
        !self.writer.be
    }

    pub fn write_u8(&mut self, value: u8) -> std::io::Result<()> {
        self.write_all(&value.to_ne_bytes()[..])
    }

    pub fn write_i8(&mut self, value: i8) -> std::io::Result<()> {
        self.write_all(&value.to_ne_bytes()[..])
    }

    pub fn write_u16(&mut self, value: u16) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_i16(&mut self, value: i16) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_u32(&mut self, value: u32) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_i32(&mut self, value: i32) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_u64(&mut self, value: u64) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_i64(&mut self, value: i64) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_raw_option(&mut self, id: u16) -> std::io::Result<RawOptionWriter<'_, 'a, F>> {
        self.write_u16(id)?;
        self.write_u16(0)?;
        let body_start = self.stream_position()?;
        Ok(RawOptionWriter {
            block: self,
            body_start,
            finished: false,
        })
    }
}

impl<'a, F: Write + Seek> Write for RawBlockWriter<'a, F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.file.flush()
    }
}

fn offset_seek<F: Seek>(file: &mut F, start: u64, pos: SeekFrom) -> std::io::Result<u64> {
    Ok(match pos {
        SeekFrom::Start(pos) => file.seek(SeekFrom::Start(pos + start))?,
        SeekFrom::Current(offset) => {
            let pos = file.seek(SeekFrom::Current(offset))?;
            if pos < start {
                file.seek(SeekFrom::Current(-((pos + 1) as i64)))?
            } else {
                pos
            }
        }
        SeekFrom::End(offset) => {
            let pos = file.seek(SeekFrom::End(offset))?;
            if pos < start {
                file.seek(SeekFrom::Current(-((pos + 1) as i64)))?
            } else {
                pos
            }
        }
    } - start)
}

impl<'a, F: Write + Seek> Seek for RawBlockWriter<'a, F> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        offset_seek(&mut self.writer.file, self.body_start, pos)
    }

    fn rewind(&mut self) -> std::io::Result<()> {
        self.writer.file.seek(SeekFrom::Start(self.body_start))?;
        Ok(())
    }

    fn stream_position(&mut self) -> std::io::Result<u64> {
        Ok(self.writer.file.stream_position()? - self.body_start)
    }
}

impl<'a, F: Write + Seek> Drop for RawBlockWriter<'a, F> {
    fn drop(&mut self) {
        self.finish_impl().unwrap()
    }
}

impl<'a, 'b, F: Write + Seek> RawOptionWriter<'a, 'b, F> {
    fn finish_impl(&mut self) -> std::io::Result<()> {
        if !self.finished {
            let end = self.block.seek(SeekFrom::End(0))?;
            let len = (end - self.body_start) as u16;
            self.block.seek(SeekFrom::Start(self.body_start - 4))?;
            self.block.write_u16(len)?;
            self.block.seek(SeekFrom::End(0))?;
            write_padding(&mut self.block, ((4 - (len % 4)) % 4) as usize)?;
            self.finished = true;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), TransmitError> {
        Ok(self.finish_impl()?)
    }

    pub fn big_endian(&self) -> bool {
        self.block.big_endian()
    }

    pub fn little_endian(&self) -> bool {
        self.block.little_endian()
    }

    pub fn write_u8(&mut self, value: u8) -> std::io::Result<()> {
        self.write_all(&value.to_ne_bytes()[..])
    }

    pub fn write_i8(&mut self, value: i8) -> std::io::Result<()> {
        self.write_all(&value.to_ne_bytes()[..])
    }

    pub fn write_u16(&mut self, value: u16) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_i16(&mut self, value: i16) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_u32(&mut self, value: u32) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_i32(&mut self, value: i32) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_u64(&mut self, value: u64) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_i64(&mut self, value: i64) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }
}

impl<'a, 'b, F: Write + Seek> Write for RawOptionWriter<'a, 'b, F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.block.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.block.flush()
    }
}

impl<'a, 'b, F: Write + Seek> Seek for RawOptionWriter<'a, 'b, F> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        offset_seek(&mut self.block, self.body_start, pos)
    }

    fn rewind(&mut self) -> std::io::Result<()> {
        self.block.seek(SeekFrom::Start(self.body_start))?;
        Ok(())
    }

    fn stream_position(&mut self) -> std::io::Result<u64> {
        Ok(self.block.stream_position()? - self.body_start)
    }
}

impl<'a, 'b, F: Write + Seek> Drop for RawOptionWriter<'a, 'b, F> {
    fn drop(&mut self) {
        self.finish_impl().unwrap()
    }
}

impl<'a, 'b, 'c, F: Write + Seek> Write for RawFilterOptionWriter<'a, 'b, 'c, F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.opt.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.opt.flush()
    }
}

impl<'a, 'b, 'c, F: Write + Seek> Seek for RawFilterOptionWriter<'a, 'b, 'c, F> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        offset_seek(&mut self.opt, 1, pos)
    }

    fn rewind(&mut self) -> std::io::Result<()> {
        self.opt.seek(SeekFrom::Start(1))?;
        Ok(())
    }

    fn stream_position(&mut self) -> std::io::Result<u64> {
        Ok(self.opt.stream_position()? - 1)
    }
}

impl<'a, 'b, 'c, F: Write + Seek> Drop for RawFilterOptionWriter<'a, 'b, 'c, F> {
    fn drop(&mut self) {
        self.finish_impl().unwrap()
    }
}

impl<'a, 'b, 'c, F: Write + Seek> RawFilterOptionWriter<'a, 'b, 'c, F> {
    fn finish_impl(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    pub fn finish(mut self) -> std::io::Result<()> {
        self.finish_impl()
    }

    pub fn big_endian(&self) -> bool {
        self.opt.big_endian()
    }

    pub fn little_endian(&self) -> bool {
        self.opt.little_endian()
    }

    pub fn write_u8(&mut self, value: u8) -> std::io::Result<()> {
        self.write_all(&value.to_ne_bytes()[..])
    }

    pub fn write_i8(&mut self, value: i8) -> std::io::Result<()> {
        self.write_all(&value.to_ne_bytes()[..])
    }

    pub fn write_u16(&mut self, value: u16) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_i16(&mut self, value: i16) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_u32(&mut self, value: u32) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_i32(&mut self, value: i32) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_u64(&mut self, value: u64) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }

    pub fn write_i64(&mut self, value: i64) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..])
        } else {
            self.write_all(&value.to_le_bytes()[..])
        }
    }
}

const END_OPT: [u8; 4] = [0u8; 4];

impl<'a, F: Write + Seek> SHBOptionWriter<'a, F> {
    fn finish_impl(&mut self) -> std::io::Result<()> {
        if !self.finished {
            self.block.write_all(&END_OPT[..])?;
            self.finished = true;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), TransmitError> {
        Ok(self.finish_impl()?)
    }

    pub fn write_raw_option(
        &mut self,
        id: u16,
    ) -> Result<RawOptionWriter<'_, 'a, F>, TransmitError> {
        self.finished = false;
        Ok(self.block.write_raw_option(id)?)
    }

    pub fn write_comment(&mut self, comment: &str) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(OPT_COMMENT)?;
        opt.write_all(comment.as_bytes())?;
        opt.finish()
    }

    pub fn write_hardware(&mut self, hardware: &str) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(SHB_HARDWARE)?;
        opt.write_all(hardware.as_bytes())?;
        opt.finish()
    }

    pub fn write_os(&mut self, os: &str) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(SHB_OS)?;
        opt.write_all(os.as_bytes())?;
        opt.finish()
    }

    pub fn write_user_app(&mut self, user_app: &str) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(SHB_USERAPPL)?;
        opt.write_all(user_app.as_bytes())?;
        opt.finish()
    }
}

impl<'a, F: Write + Seek> Drop for SHBOptionWriter<'a, F> {
    fn drop(&mut self) {
        self.finish_impl().unwrap();
    }
}

impl<'a, F: Write + Seek> IDBOptionWriter<'a, F> {
    fn finish_impl(&mut self) -> std::io::Result<()> {
        if !self.finished {
            self.block.write_all(&END_OPT[..])?;
            self.finished = true;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), TransmitError> {
        Ok(self.finish_impl()?)
    }

    pub fn write_raw_option(
        &mut self,
        id: u16,
    ) -> Result<RawOptionWriter<'_, 'a, F>, TransmitError> {
        self.finished = false;
        Ok(self.block.write_raw_option(id)?)
    }

    pub fn write_comment(&mut self, comment: &str) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(IF_NAME)?;
        opt.write_all(comment.as_bytes())?;
        opt.finish()
    }

    pub fn write_name(&mut self, name: &str) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(IF_NAME)?;
        opt.write_all(name.as_bytes())?;
        opt.finish()
    }

    pub fn write_description(&mut self, desc: &str) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(IF_DESCRIPTION)?;
        opt.write_all(desc.as_bytes())?;
        opt.finish()
    }

    pub fn write_ipv4_address(
        &mut self,
        addr: IPv4Address,
        mask: IPv4Address,
    ) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(IF_IPV4ADDR)?;
        let buf: [u8; 4] = addr.into();
        opt.write_all(&buf[..])?;
        let buf: [u8; 4] = mask.into();
        opt.write_all(&buf[..])?;
        opt.finish()
    }

    pub fn write_ipv6_address(
        &mut self,
        addr: IPv6Address,
        prefix_len: u8,
    ) -> Result<(), TransmitError> {
        let buf: [u8; 16] = addr.into();
        let mut opt = self.write_raw_option(IF_IPV6ADDR)?;
        opt.write_all(&buf[..])?;
        opt.write_u8(prefix_len)?;
        opt.finish()
    }

    pub fn write_mac_address(&mut self, addr: MACAddress) -> Result<(), TransmitError> {
        let buf: [u8; 6] = addr.into();
        let mut opt = self.write_raw_option(IF_MACADDR)?;
        opt.write_all(&buf[..])?;
        opt.finish()
    }

    pub fn write_eui_address(&mut self, addr: EUIAddress) -> Result<(), TransmitError> {
        let buf: [u8; 8] = addr.into();
        let mut opt = self.write_raw_option(IF_EUIADDR)?;
        opt.write_all(&buf[..])?;
        opt.finish()
    }

    pub fn write_speed(&mut self, speed: u64) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(IF_SPEED)?;
        opt.write_u64(speed)?;
        opt.finish()
    }

    pub fn write_tsresol(&mut self, tsresol: u8) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(IF_TSRESOL)?;
        opt.write_u8(tsresol)?;
        opt.finish()
    }

    pub fn write_tzone(&mut self, tzone: i32) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(IF_TZONE)?;
        opt.write_i32(tzone)?;
        opt.finish()
    }

    pub fn write_filter(&mut self) -> Result<FilterOptionWriter<'_, 'a, F>, TransmitError> {
        Ok(FilterOptionWriter {
            opt: self.write_raw_option(IF_FILTER)?,
        })
    }

    pub fn write_os(&mut self, os: &str) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(IF_OS)?;
        opt.write_all(os.as_bytes())?;
        opt.finish()
    }

    pub fn write_fcslen(&mut self, fcslen: u8) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(IF_FCSLEN)?;
        opt.write_u8(fcslen)?;
        opt.finish()
    }

    pub fn write_tsoffset(&mut self, tsoffset: i64) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(IF_TSOFFSET)?;
        opt.write_i64(tsoffset)?;
        opt.finish()
    }

    pub fn write_hardware(&mut self, hardware: &str) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(IF_HARDWARE)?;
        opt.write_all(hardware.as_bytes())?;
        opt.finish()
    }

    pub fn write_txspeed(&mut self, speed: u64) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(IF_TXSPEED)?;
        opt.write_u64(speed)?;
        opt.finish()
    }

    pub fn write_rxspeed(&mut self, speed: u64) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(IF_RXSPEED)?;
        opt.write_u64(speed)?;
        opt.finish()
    }
}

impl<'a, 'b, F: Write + Seek> FilterOptionWriter<'a, 'b, F> {
    pub fn finish(self) -> Result<(), TransmitError> {
        self.opt.finish()
    }

    pub fn write_string(mut self, filter: &str) -> Result<(), TransmitError> {
        self.opt.write_u8(0)?;
        self.opt.write_all(filter.as_bytes())?;
        Ok(self.opt.finish()?)
    }

    pub fn write_byte_code(mut self, filter: &[u8]) -> Result<(), TransmitError> {
        self.opt.write_u8(1)?;
        self.opt.write_all(filter)?;
        Ok(self.opt.finish()?)
    }

    pub fn write_raw(
        &mut self,
        filter_type: u8,
    ) -> Result<RawFilterOptionWriter<'_, 'a, 'b, F>, TransmitError> {
        self.opt.write_u8(filter_type)?;
        Ok(RawFilterOptionWriter { opt: &mut self.opt })
    }
}

impl<'a, F: Write + Seek> EPBDataWriter<'a, F> {
    fn finish_impl(&mut self) -> std::io::Result<()> {
        let custom_orig_len = self.custom_orig_len;
        Ok(match self.block.as_mut() {
            Some(block) => {
                let end = block.seek(SeekFrom::End(0))?;
                if end < 16 {
                    block.write_u32(0)?;
                    block.write_u32(0)?;
                } else {
                    block.seek(SeekFrom::Start(16))?;
                    let len = (end - 20) as u32;
                    block.write_u32(len)?;
                    if !custom_orig_len {
                        block.write_u32(len)?;
                    }
                    block.seek(SeekFrom::End(0))?;
                    write_padding(block, len as usize)?;
                }
            }
            None => (),
        })
    }

    pub fn finish(mut self) -> Result<(), TransmitError> {
        self.finish_impl()?;
        guarantee(std::mem::replace(&mut self.block, None)).finish()
    }

    pub fn write_options(mut self) -> Result<EPBOptionWriter<'a, F>, TransmitError> {
        self.finish_impl()?;
        let block = guarantee(std::mem::replace(&mut self.block, None));
        Ok(EPBOptionWriter {
            block,
            finished: true,
        })
    }

    pub fn write_original_length(&mut self, orig_len: u32) -> Result<(), TransmitError> {
        self.custom_orig_len = true;
        let block = guarantee(self.block.as_mut());
        let pos = block.stream_position()?;
        block.seek(SeekFrom::Start(16))?;
        block.write_u32(orig_len)?;
        block.seek(SeekFrom::Start(pos))?;
        Ok(())
    }
}

impl<'a, F: Write + Seek> Write for EPBDataWriter<'a, F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        guarantee(self.block.as_mut()).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        guarantee(self.block.as_mut()).flush()
    }
}

impl<'a, F: Write + Seek> Seek for EPBDataWriter<'a, F> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        offset_seek(guarantee(self.block.as_mut()), 20, pos)
    }

    fn rewind(&mut self) -> std::io::Result<()> {
        guarantee(self.block.as_mut()).seek(SeekFrom::Start(20))?;
        Ok(())
    }

    fn stream_position(&mut self) -> std::io::Result<u64> {
        Ok(guarantee(self.block.as_mut()).stream_position()? - 20)
    }
}

impl<'a, F: Write + Seek> Drop for EPBDataWriter<'a, F> {
    fn drop(&mut self) {
        self.finish_impl().unwrap()
    }
}

impl<'a, F: Write + Seek> EPBOptionWriter<'a, F> {
    fn finish_impl(&mut self) -> std::io::Result<()> {
        if !self.finished {
            self.block.write_all(&END_OPT[..])?;
            self.finished = true;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), TransmitError> {
        Ok(self.finish_impl()?)
    }

    pub fn write_raw_option(
        &mut self,
        id: u16,
    ) -> Result<RawOptionWriter<'_, 'a, F>, TransmitError> {
        self.finished = false;
        Ok(self.block.write_raw_option(id)?)
    }

    pub fn write_comment(&mut self, comment: &str) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(OPT_COMMENT)?;
        opt.write_all(comment.as_bytes())?;
        opt.finish()
    }

    pub fn write_raw_packet_flags(&mut self, flags: u32) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(EPB_FLAGS)?;
        opt.write_u32(flags)?;
        opt.finish()
    }

    pub fn write_packet_flags(
        &mut self,
    ) -> Result<PacketFlagsOptionWriter<'_, 'a, F>, TransmitError> {
        Ok(PacketFlagsOptionWriter {
            block: self.write_raw_option(EPB_FLAGS)?,
            flags: 0,
            finished: false,
        })
    }
}

impl<'a, 'b, F: Write + Seek> PacketFlagsOptionWriter<'a, 'b, F> {
    fn finish_impl(&mut self) -> std::io::Result<()> {
        if !self.finished {
            self.block.write_u32(self.flags)?;
            self.block.finish_impl()?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), TransmitError> {
        Ok(self.finish_impl()?)
    }

    pub fn write_direction(&mut self, dir: Direction) -> Result<(), TransmitError> {
        self.flags &= !0b0011;
        match dir {
            Direction::Unknown => {
                self.flags |= 0b00;
            }
            Direction::Inbound => {
                self.flags |= 0b01;
            }
            Direction::Outbound => {
                self.flags |= 0b10;
            }
        }
        Ok(())
    }

    pub fn write_reception_type(&mut self, rtype: ReceptionType) -> Result<(), TransmitError> {
        self.flags &= !(0b111 << 2);
        match rtype {
            ReceptionType::Unspecified => {
                self.flags |= 0b000 << 2;
            }
            ReceptionType::Unicast => {
                self.flags |= 0b001 << 2;
            }
            ReceptionType::Multicast => {
                self.flags |= 0b010 << 2;
            }
            ReceptionType::Broadcast => {
                self.flags |= 0b011 << 2;
            }
            ReceptionType::Promiscuous => {
                self.flags |= 0b100 << 2;
            }
        }
        Ok(())
    }

    pub fn write_fcs_length(&mut self, fcslen: u8) -> Result<(), TransmitError> {
        if fcslen > 0b1111 {
            Err(TransmitError::MalformedCapture)
        } else {
            self.flags &= !(0b1111 << 5);
            self.flags |= (fcslen as u32) << 5;
            Ok(())
        }
    }

    pub fn write_link_layer_dependent_errors(
        &mut self,
        has_errors: bool,
    ) -> Result<(), TransmitError> {
        const FLAG: u32 = 1 << 31;
        if has_errors {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }

    pub fn write_preamble_error(&mut self, has_error: bool) -> Result<(), TransmitError> {
        const FLAG: u32 = 1 << 30;
        if has_error {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }

    pub fn write_start_frame_delimiter_error(
        &mut self,
        has_error: bool,
    ) -> Result<(), TransmitError> {
        const FLAG: u32 = 1 << 29;
        if has_error {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }

    pub fn write_unaligned_frame_error(&mut self, has_error: bool) -> Result<(), TransmitError> {
        const FLAG: u32 = 1 << 28;
        if has_error {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }

    pub fn write_wrong_inter_frame_gap_error(
        &mut self,
        has_error: bool,
    ) -> Result<(), TransmitError> {
        const FLAG: u32 = 1 << 27;
        if has_error {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }

    pub fn write_packet_too_short_error(&mut self, has_error: bool) -> Result<(), TransmitError> {
        const FLAG: u32 = 1 << 26;
        if has_error {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }

    pub fn write_packet_too_long_error(&mut self, has_error: bool) -> Result<(), TransmitError> {
        const FLAG: u32 = 1 << 25;
        if has_error {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }

    pub fn write_crc_error(&mut self, has_error: bool) -> Result<(), TransmitError> {
        const FLAG: u32 = 1 << 24;
        if has_error {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }
}

impl<'a, 'b, F: Write + Seek> Drop for PacketFlagsOptionWriter<'a, 'b, F> {
    fn drop(&mut self) {
        self.finish_impl().unwrap();
    }
}

impl<'a, F: Write + Seek> SPBDataWriter<'a, F> {
    fn finish_impl(&mut self) -> Result<(), TransmitError> {
        let custom_orig_len = self.custom_orig_len;
        Ok(match self.block.as_mut() {
            Some(block) => {
                let snaplen = match block.writer.first_snaplen {
                    Some(snaplen) => snaplen,
                    None => {
                        return Err(TransmitError::MalformedCapture);
                    }
                };
                let end = block.seek(SeekFrom::End(0))?;
                if end < 4 {
                    block.write_u32(0)?;
                } else {
                    let len = (end - 4) as u32;
                    if len > snaplen {
                        return Err(TransmitError::MalformedCapture);
                    } else if !custom_orig_len {
                        block.seek(SeekFrom::Start(0))?;
                        block.write_u32(len)?;
                    }
                    block.seek(SeekFrom::End(0))?;
                    write_padding(block, len as usize)?;
                }
            }
            None => (),
        })
    }

    pub fn finish(mut self) -> Result<(), TransmitError> {
        self.finish_impl()?;
        guarantee(std::mem::replace(&mut self.block, None)).finish()
    }

    pub fn write_original_length(&mut self, orig_len: u32) -> Result<(), TransmitError> {
        self.custom_orig_len = true;
        let block = guarantee(self.block.as_mut());
        let pos = block.stream_position()?;
        block.seek(SeekFrom::Start(0))?;
        block.write_u32(orig_len)?;
        block.seek(SeekFrom::Start(pos))?;
        Ok(())
    }
}

impl<'a, F: Write + Seek> Write for SPBDataWriter<'a, F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        guarantee(self.block.as_mut()).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        guarantee(self.block.as_mut()).flush()
    }
}

impl<'a, F: Write + Seek> Seek for SPBDataWriter<'a, F> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        offset_seek(guarantee(self.block.as_mut()), 4, pos)
    }

    fn rewind(&mut self) -> std::io::Result<()> {
        guarantee(self.block.as_mut()).seek(SeekFrom::Start(4))?;
        Ok(())
    }

    fn stream_position(&mut self) -> std::io::Result<u64> {
        Ok(guarantee(self.block.as_mut()).stream_position()? - 4)
    }
}

impl<'a, F: Write + Seek> Drop for SPBDataWriter<'a, F> {
    fn drop(&mut self) {
        self.finish_impl().unwrap()
    }
}

impl<'a, F: Write + Seek> NRBRecordWriter<'a, F> {
    fn finish_impl(&mut self) -> std::io::Result<()> {
        match self.block.as_mut() {
            Some(block) => {
                block.write_u16(NRB_RECORD_END)?;
                block.write_u16(0)?;
            }
            None => (),
        }
        Ok(())
    }

    pub fn write_ipv4_record(
        &mut self,
        addr: IPv4Address,
    ) -> Result<NRBNameWriter<'_, 'a, F>, TransmitError> {
        let block = guarantee(self.block.as_mut());
        block.write_u16(NRB_RECORD_IPV4)?;
        let len_pos = block.stream_position()?;
        block.write_u16(0)?;
        block.write_all(&addr[..])?;
        Ok(NRBNameWriter { block, len_pos })
    }

    pub fn write_ipv6_record(
        &mut self,
        addr: IPv6Address,
    ) -> Result<NRBNameWriter<'_, 'a, F>, TransmitError> {
        let block = guarantee(self.block.as_mut());
        block.write_u16(NRB_RECORD_IPV4)?;
        let len_pos = block.stream_position()?;
        block.write_u16(0)?;
        block.write_all(&addr[..])?;
        Ok(NRBNameWriter { block, len_pos })
    }

    pub fn finish(mut self) -> Result<(), TransmitError> {
        self.finish_impl()?;
        guarantee(std::mem::replace(&mut self.block, None)).finish()
    }

    pub fn write_options(mut self) -> Result<NRBOptionWriter<'a, F>, TransmitError> {
        self.finish_impl()?;
        Ok(NRBOptionWriter {
            block: guarantee(std::mem::replace(&mut self.block, None)),
            finished: true,
        })
    }
}

impl<'a, F: Write + Seek> Drop for NRBRecordWriter<'a, F> {
    fn drop(&mut self) {
        self.finish_impl().unwrap()
    }
}

impl<'a, 'b, F: Write + Seek> NRBNameWriter<'a, 'b, F> {
    fn finish_impl(&mut self) -> std::io::Result<()> {
        if self.len_pos != u64::MAX {
            let end = self.block.stream_position()?;
            let len = end - self.len_pos - 2;
            self.block.seek(SeekFrom::Start(self.len_pos))?;
            self.block.write_u16(len as u16)?;
            self.block.seek(SeekFrom::End(0))?;
            self.len_pos = u64::MAX;
        }
        Ok(())
    }

    pub fn write_name(&mut self, name: &str) -> Result<(), TransmitError> {
        self.block.write_all(name.as_bytes())?;
        self.block.write_u8(0)?;
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), TransmitError> {
        self.finish_impl()?;
        Ok(())
    }
}

impl<'a, 'b, F: Write + Seek> Drop for NRBNameWriter<'a, 'b, F> {
    fn drop(&mut self) {
        self.finish_impl().unwrap()
    }
}

impl<'a, F: Write + Seek> NRBOptionWriter<'a, F> {
    fn finish_impl(&mut self) -> std::io::Result<()> {
        if !self.finished {
            self.block.write_all(&END_OPT[..])?;
            self.finished = true;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), TransmitError> {
        Ok(self.finish_impl()?)
    }

    pub fn write_raw_option(
        &mut self,
        id: u16,
    ) -> Result<RawOptionWriter<'_, 'a, F>, TransmitError> {
        self.finished = false;
        Ok(self.block.write_raw_option(id)?)
    }

    pub fn write_comment(&mut self, comment: &str) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(OPT_COMMENT)?;
        opt.write_all(comment.as_bytes())?;
        opt.finish()
    }

    pub fn write_dns_name(&mut self, name: &str) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(NS_DNSNAME)?;
        opt.write_all(name.as_bytes())?;
        opt.finish()
    }

    pub fn write_dns_ipv4_address(&mut self, addr: IPv4Address) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(NS_DNSIP4ADDR)?;
        opt.write_all(&addr[..])?;
        opt.finish()
    }

    pub fn write_dns_ipv6_address(&mut self, addr: IPv6Address) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(NS_DNSIP6ADDR)?;
        opt.write_all(&addr[..])?;
        opt.finish()
    }
}

impl<'a, F: Write + Seek> Drop for NRBOptionWriter<'a, F> {
    fn drop(&mut self) {
        self.finish_impl().unwrap()
    }
}

impl<'a, F: Write + Seek> ISBOptionWriter<'a, F> {
    fn finish_impl(&mut self) -> std::io::Result<()> {
        if !self.finished {
            self.block.write_all(&END_OPT[..])?;
            self.finished = true;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), TransmitError> {
        Ok(self.finish_impl()?)
    }

    pub fn write_raw_option(
        &mut self,
        id: u16,
    ) -> Result<RawOptionWriter<'_, 'a, F>, TransmitError> {
        self.finished = false;
        Ok(self.block.write_raw_option(id)?)
    }

    pub fn write_comment(&mut self, comment: &str) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(OPT_COMMENT)?;
        opt.write_all(comment.as_bytes())?;
        opt.finish()
    }

    pub fn write_start_time(&mut self, ts: u64) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(ISB_STARTTIME)?;
        opt.write_u32((ts >> 32) as u32)?;
        opt.write_u32((ts & 0xFFFFFFFF) as u32)?;
        opt.finish()
    }

    pub fn write_end_time(&mut self, ts: u64) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(ISB_ENDTIME)?;
        opt.write_u32((ts >> 32) as u32)?;
        opt.write_u32((ts & 0xFFFFFFFF) as u32)?;
        opt.finish()
    }

    pub fn write_ifrecv(&mut self, count: u64) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(ISB_IFRECV)?;
        opt.write_u64(count)?;
        opt.finish()
    }

    pub fn write_ifdrop(&mut self, count: u64) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(ISB_IFDROP)?;
        opt.write_u64(count)?;
        opt.finish()
    }

    pub fn write_filter_accept(&mut self, count: u64) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(ISB_FILTERACCEPT)?;
        opt.write_u64(count)?;
        opt.finish()
    }

    pub fn write_osdrop(&mut self, count: u64) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(ISB_OSDROP)?;
        opt.write_u64(count)?;
        opt.finish()
    }

    pub fn write_user_deliv(&mut self, count: u64) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(ISB_USRDELIV)?;
        opt.write_u64(count)?;
        opt.finish()
    }
}

impl<'a, F: Write + Seek> Drop for ISBOptionWriter<'a, F> {
    fn drop(&mut self) {
        self.finish_impl().unwrap()
    }
}

impl<'a, F: Write + Seek> SJBEntryWriter<'a, F> {
    fn finish_impl(&mut self) -> std::io::Result<()> {
        if !self.finished {
            let end = self.block.seek(SeekFrom::End(0))?;
            let len = end - self.block.body_start;
            write_padding(&mut self.block, ((4 - (len % 4)) % 4) as usize)?;
            self.finished = true;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), TransmitError> {
        Ok(self.finish_impl()?)
    }
}

impl<'a, F: Write + Seek> Write for SJBEntryWriter<'a, F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.block.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.block.flush()
    }
}

impl<'a, F: Write + Seek> Seek for SJBEntryWriter<'a, F> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.block.seek(pos)
    }

    fn rewind(&mut self) -> std::io::Result<()> {
        self.block.rewind()
    }

    fn stream_position(&mut self) -> std::io::Result<u64> {
        self.block.stream_position()
    }
}

impl<'a, F: Write + Seek> Drop for SJBEntryWriter<'a, F> {
    fn drop(&mut self) {
        self.finish_impl().unwrap()
    }
}

impl<'a, F: Write + Seek> DSBSecretsWriter<'a, F> {
    fn finish_impl(&mut self) -> std::io::Result<()> {
        let body_start = self.body_start;
        Ok(match self.block.as_mut() {
            Some(block) => {
                let end = block.seek(SeekFrom::End(0))?;
                let len = (end - body_start) as u32;
                block.seek(SeekFrom::Start(4))?;
                block.write_u32(len)?;
                block.seek(SeekFrom::End(0))?;
                write_padding(block, len as usize)?;
            }
            None => (),
        })
    }

    pub fn finish(mut self) -> Result<(), TransmitError> {
        self.finish_impl()?;
        guarantee(std::mem::replace(&mut self.block, None)).finish()
    }

    pub fn write_options(mut self) -> Result<DSBOptionWriter<'a, F>, TransmitError> {
        self.finish_impl()?;
        let block = guarantee(std::mem::replace(&mut self.block, None));
        Ok(DSBOptionWriter {
            block,
            finished: true,
        })
    }
}

impl<'a, F: Write + Seek> Write for DSBSecretsWriter<'a, F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        guarantee(self.block.as_mut()).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        guarantee(self.block.as_mut()).flush()
    }
}

impl<'a, F: Write + Seek> Seek for DSBSecretsWriter<'a, F> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        offset_seek(guarantee(self.block.as_mut()), self.body_start, pos)
    }

    fn rewind(&mut self) -> std::io::Result<()> {
        guarantee(self.block.as_mut()).seek(SeekFrom::Start(self.body_start))?;
        Ok(())
    }

    fn stream_position(&mut self) -> std::io::Result<u64> {
        Ok(guarantee(self.block.as_mut()).stream_position()? - self.body_start)
    }
}

impl<'a, F: Write + Seek> Drop for DSBSecretsWriter<'a, F> {
    fn drop(&mut self) {
        self.finish_impl().unwrap()
    }
}

impl<'a, F: Write + Seek> DSBOptionWriter<'a, F> {
    fn finish_impl(&mut self) -> std::io::Result<()> {
        if !self.finished {
            self.block.write_all(&END_OPT[..])?;
            self.finished = true;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), TransmitError> {
        Ok(self.finish_impl()?)
    }

    pub fn write_raw_option(
        &mut self,
        id: u16,
    ) -> Result<RawOptionWriter<'_, 'a, F>, TransmitError> {
        self.finished = false;
        Ok(self.block.write_raw_option(id)?)
    }

    pub fn write_comment(&mut self, comment: &str) -> Result<(), TransmitError> {
        let mut opt = self.write_raw_option(OPT_COMMENT)?;
        opt.write_all(comment.as_bytes())?;
        opt.finish()
    }
}
