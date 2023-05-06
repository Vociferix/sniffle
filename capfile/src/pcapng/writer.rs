use super::*;
use sniffle_core::Error;
use std::io::SeekFrom;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

pub struct Writer<F: AsyncWrite + AsyncSeek + Send + Unpin> {
    file: F,
    be: bool,
    section_start: u64,
    first_snaplen: Option<u32>,
}

pub type FileWriter = Writer<tokio::io::BufWriter<tokio::fs::File>>;

pub struct RawBlockWriter<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    writer: &'a mut Writer<F>,
    body_start: u64,
    finished: bool,
}

pub struct RawOptionWriter<'a, 'b, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    block: &'a mut RawBlockWriter<'b, F>,
    body_start: u64,
    finished: bool,
}

pub struct RawFilterOptionWriter<'a, 'b, 'c, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    opt: &'a mut RawOptionWriter<'b, 'c, F>,
}

pub struct ShbOptionWriter<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    block: RawBlockWriter<'a, F>,
    finished: bool,
}

pub struct IdbOptionWriter<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    block: RawBlockWriter<'a, F>,
    finished: bool,
}

pub struct FilterOptionWriter<'a, 'b, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    opt: RawOptionWriter<'a, 'b, F>,
}

pub struct EpbDataWriter<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    block: Option<RawBlockWriter<'a, F>>,
    custom_orig_len: bool,
}

pub struct EpbOptionWriter<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    block: RawBlockWriter<'a, F>,
    finished: bool,
}

pub struct PacketFlagsOptionWriter<'a, 'b, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    block: RawOptionWriter<'a, 'b, F>,
    flags: u32,
    finished: bool,
}

pub struct SpbDataWriter<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    block: RawBlockWriter<'a, F>,
    custom_orig_len: bool,
    finished: bool,
}

pub struct NrbRecordWriter<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    block: Option<RawBlockWriter<'a, F>>,
}

pub struct NrbNameWriter<'a, 'b, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    block: &'a mut RawBlockWriter<'b, F>,
    len_pos: u64,
}

pub struct NrbOptionWriter<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    block: RawBlockWriter<'a, F>,
    finished: bool,
}

pub struct IsbOptionWriter<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    block: RawBlockWriter<'a, F>,
    finished: bool,
}

pub struct SjbEntryWriter<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    block: RawBlockWriter<'a, F>,
    finished: bool,
}

pub struct DsbSecretsWriter<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    block: Option<RawBlockWriter<'a, F>>,
    body_start: u64,
}

pub struct DsbOptionWriter<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> {
    block: RawBlockWriter<'a, F>,
    finished: bool,
}

fn guarantee<T>(opt: Option<T>) -> T {
    match opt {
        Some(val) => val,
        None => unreachable!(),
    }
}

async fn write_padding<F: AsyncWrite + Unpin>(file: &mut F, len: usize) -> std::io::Result<()> {
    const PADDING: [u8; 4] = [0u8; 4];
    file.write_all(&PADDING[..((4 - (len % 4)) % 4)]).await
}

impl<F: AsyncWrite + AsyncSeek + Send + Unpin> Writer<F> {
    pub fn new(file: F) -> Self {
        Self {
            file,
            be: false,
            section_start: 0,
            first_snaplen: None,
        }
    }

    pub async fn create<P: AsRef<std::path::Path>>(path: P) -> Result<FileWriter, Error> {
        Ok(FileWriter::new(tokio::io::BufWriter::new(
            tokio::fs::File::create(path).await?,
        )))
    }

    async fn finish_section(&mut self) -> std::io::Result<()> {
        if self.section_start != u64::MAX {
            let end = self.file.seek(SeekFrom::End(0)).await?;
            self.file
                .seek(SeekFrom::Start(self.section_start + 16))
                .await?;
            if self.be {
                self.file
                    .write_all(&(end - self.section_start).to_be_bytes()[..])
                    .await?;
            } else {
                self.file
                    .write_all(&(end - self.section_start).to_le_bytes()[..])
                    .await?;
            }
            self.file.seek(SeekFrom::End(0)).await?;
        }
        Ok(())
    }

    pub async fn write_shb(
        &mut self,
        big_endian: bool,
        version_major: u16,
        version_minor: u16,
    ) -> Result<ShbOptionWriter<'_, F>, Error> {
        self.finish_section().await?;
        let mut block = self.write_raw_block(SHB_ID).await?;
        block.writer.be = big_endian;
        block.write_u32(0x1A2B3C4D).await?;
        block.write_u16(version_major).await?;
        block.write_u16(version_minor).await?;
        block.write_u64(u64::MAX).await?;
        Ok(ShbOptionWriter {
            block,
            finished: true,
        })
    }

    pub async fn write_idb(
        &mut self,
        link_type: u16,
        snaplen: u32,
    ) -> Result<IdbOptionWriter<'_, F>, Error> {
        self.first_snaplen.get_or_insert(snaplen);
        let mut block = self.write_raw_block(IDB_ID).await?;
        block.write_u16(link_type).await?;
        block.write_u16(0).await?;
        block.write_u32(snaplen).await?;
        Ok(IdbOptionWriter {
            block,
            finished: true,
        })
    }

    pub async fn write_epb(
        &mut self,
        iface_id: u32,
        timestamp: u64,
    ) -> Result<EpbDataWriter<'_, F>, Error> {
        let mut block = self.write_raw_block(EPB_ID).await?;
        block.write_u32(iface_id).await?;
        block.write_u32((timestamp >> 32) as u32).await?;
        block.write_u32((timestamp & 0xFFFFFFFF) as u32).await?;
        Ok(EpbDataWriter {
            block: Some(block),
            custom_orig_len: false,
        })
    }

    pub async fn write_spb(&mut self) -> Result<SpbDataWriter<'_, F>, Error> {
        Ok(SpbDataWriter {
            block: self.write_raw_block(SPB_ID).await?,
            custom_orig_len: false,
            finished: false,
        })
    }

    pub async fn write_nrb(&mut self) -> Result<NrbRecordWriter<'_, F>, Error> {
        Ok(NrbRecordWriter {
            block: Some(self.write_raw_block(NRB_ID).await?),
        })
    }

    pub async fn write_isb(
        &mut self,
        iface_id: u32,
        timestamp: u64,
    ) -> Result<IsbOptionWriter<'_, F>, Error> {
        let mut block = self.write_raw_block(ISB_ID).await?;
        block.write_u32(iface_id).await?;
        block.write_u32((timestamp >> 32) as u32).await?;
        block.write_u32((timestamp & 0xFFFFFFFF) as u32).await?;
        Ok(IsbOptionWriter {
            block,
            finished: true,
        })
    }

    pub async fn write_sjb(&mut self) -> Result<SjbEntryWriter<'_, F>, Error> {
        Ok(SjbEntryWriter {
            block: self.write_raw_block(SJB_ID).await?,
            finished: true,
        })
    }

    pub async fn write_dsb(&mut self, secrets_type: u32) -> Result<DsbSecretsWriter<'_, F>, Error> {
        let mut block = self.write_raw_block(DSB_ID).await?;
        block.write_u32(secrets_type).await?;
        block.write_u32(0).await?;
        let body_start = block.stream_position().await?;
        Ok(DsbSecretsWriter {
            block: Some(block),
            body_start,
        })
    }

    pub async fn write_raw_block(&mut self, block_id: u32) -> Result<RawBlockWriter<'_, F>, Error> {
        Ok(RawBlockWriter::new(self, block_id).await?)
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> RawBlockWriter<'a, F> {
    async fn new(writer: &'a mut Writer<F>, id: u32) -> std::io::Result<RawBlockWriter<'a, F>> {
        if writer.be {
            writer.file.write_all(&id.to_be_bytes()[..]).await?;
            writer.file.write_all(&0u32.to_be_bytes()[..]).await?;
        } else {
            writer.file.write_all(&id.to_le_bytes()[..]).await?;
            writer.file.write_all(&0u32.to_le_bytes()[..]).await?;
        }
        let body_start = writer.file.stream_position().await?;
        Ok(Self {
            writer,
            body_start,
            finished: false,
        })
    }

    async fn finish_impl(&mut self) -> Result<(), Error> {
        self.finished = true;
        let end = self.writer.file.seek(SeekFrom::End(0)).await?;
        let len = 12u64 + (end - self.body_start);
        let len = if self.writer.be {
            len.to_be_bytes()
        } else {
            len.to_le_bytes()
        };
        self.writer.file.write_all(&len[..]).await?;
        self.writer
            .file
            .seek(SeekFrom::Start(self.body_start - 4))
            .await?;
        self.writer.file.write_all(&len[..]).await?;
        self.writer.file.seek(SeekFrom::End(0)).await?;
        Ok(())
    }

    pub async fn finish(mut self) -> Result<(), Error> {
        self.finish_impl().await
    }

    pub fn big_endian(&self) -> bool {
        self.writer.be
    }

    pub fn little_endian(&self) -> bool {
        !self.writer.be
    }

    pub async fn write_u8(&mut self, value: u8) -> std::io::Result<()> {
        self.write_all(&value.to_ne_bytes()[..]).await
    }

    pub async fn write_i8(&mut self, value: i8) -> std::io::Result<()> {
        self.write_all(&value.to_ne_bytes()[..]).await
    }

    pub async fn write_u16(&mut self, value: u16) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_i16(&mut self, value: i16) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_u32(&mut self, value: u32) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_i32(&mut self, value: i32) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_u64(&mut self, value: u64) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_i64(&mut self, value: i64) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_raw_option(
        &mut self,
        id: u16,
    ) -> std::io::Result<RawOptionWriter<'_, 'a, F>> {
        self.write_u16(id).await?;
        self.write_u16(0).await?;
        let body_start = self.stream_position().await?;
        Ok(RawOptionWriter {
            block: self,
            body_start,
            finished: false,
        })
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> AsyncWrite for RawBlockWriter<'a, F> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer.file).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer.file).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer.file).poll_shutdown(cx)
    }
}

fn start_offset_seek<F: AsyncSeek + Send + Unpin>(
    file: &mut F,
    start: u64,
    pos: SeekFrom,
) -> std::io::Result<()> {
    match pos {
        SeekFrom::Start(pos) => Pin::new(file).start_seek(SeekFrom::Start(pos + start)),
        SeekFrom::Current(offset) => Pin::new(file).start_seek(SeekFrom::Current(offset)),
        SeekFrom::End(offset) => Pin::new(file).start_seek(SeekFrom::End(offset)),
    }
}

fn poll_offset_seek_complete<F: AsyncSeek + Send + Unpin>(
    file: &mut F,
    start: u64,
    cx: &mut Context<'_>,
) -> Poll<std::io::Result<u64>> {
    let mut file = Pin::new(file);
    let pos = match file.as_mut().poll_complete(cx) {
        Poll::Pending => {
            return Poll::Pending;
        }
        Poll::Ready(Ok(pos)) => pos,
        Poll::Ready(Err(e)) => {
            return Poll::Ready(Err(e));
        }
    };

    if pos < start {
        match file.start_seek(SeekFrom::Current(-((pos + 1) as i64))) {
            Ok(_) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    } else {
        Poll::Ready(Ok(pos - start))
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> AsyncSeek for RawBlockWriter<'a, F> {
    fn start_seek(mut self: Pin<&mut Self>, pos: SeekFrom) -> std::io::Result<()> {
        let start = self.body_start;
        start_offset_seek(&mut self.writer.file, start, pos)
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        let start = self.body_start;
        poll_offset_seek_complete(&mut self.writer.file, start, cx)
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> Drop for RawBlockWriter<'a, F> {
    fn drop(&mut self) {
        if !self.finished {
            panic!("Unfinished PCAPNG block!");
        }
    }
}

impl<'a, 'b, F: AsyncWrite + AsyncSeek + Send + Unpin> RawOptionWriter<'a, 'b, F> {
    async fn finish_impl(&mut self) -> Result<(), Error> {
        self.finished = true;
        let end = self.block.seek(SeekFrom::End(0)).await?;
        let len = (end - self.body_start) as u16;
        self.block
            .seek(SeekFrom::Start(self.body_start - 4))
            .await?;
        self.block.write_u16(len).await?;
        self.block.seek(SeekFrom::End(0)).await?;
        write_padding(&mut self.block, ((4 - (len % 4)) % 4) as usize).await?;
        Ok(())
    }

    pub async fn finish(mut self) -> Result<(), Error> {
        self.finish_impl().await
    }

    pub fn big_endian(&self) -> bool {
        self.block.big_endian()
    }

    pub fn little_endian(&self) -> bool {
        self.block.little_endian()
    }

    pub async fn write_u8(&mut self, value: u8) -> std::io::Result<()> {
        self.write_all(&value.to_ne_bytes()[..]).await
    }

    pub async fn write_i8(&mut self, value: i8) -> std::io::Result<()> {
        self.write_all(&value.to_ne_bytes()[..]).await
    }

    pub async fn write_u16(&mut self, value: u16) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_i16(&mut self, value: i16) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_u32(&mut self, value: u32) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_i32(&mut self, value: i32) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_u64(&mut self, value: u64) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_i64(&mut self, value: i64) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }
}

impl<'a, 'b, F: AsyncWrite + AsyncSeek + Send + Unpin> AsyncWrite for RawOptionWriter<'a, 'b, F> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.block).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.block).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.block).poll_shutdown(cx)
    }
}

impl<'a, 'b, F: AsyncWrite + AsyncSeek + Send + Unpin> AsyncSeek for RawOptionWriter<'a, 'b, F> {
    fn start_seek(mut self: Pin<&mut Self>, pos: SeekFrom) -> std::io::Result<()> {
        let start = self.body_start;
        start_offset_seek(&mut self.block, start, pos)
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        let start = self.body_start;
        poll_offset_seek_complete(&mut self.block, start, cx)
    }
}

impl<'a, 'b, F: AsyncWrite + AsyncSeek + Send + Unpin> Drop for RawOptionWriter<'a, 'b, F> {
    fn drop(&mut self) {
        if !self.finished {
            panic!("Unfinished PCAPNG option!");
        }
    }
}

impl<'a, 'b, 'c, F: AsyncWrite + AsyncSeek + Send + Unpin> AsyncWrite
    for RawFilterOptionWriter<'a, 'b, 'c, F>
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.opt).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.opt).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.opt).poll_shutdown(cx)
    }
}

impl<'a, 'b, 'c, F: AsyncWrite + AsyncSeek + Send + Unpin> AsyncSeek
    for RawFilterOptionWriter<'a, 'b, 'c, F>
{
    fn start_seek(mut self: Pin<&mut Self>, pos: SeekFrom) -> std::io::Result<()> {
        start_offset_seek(&mut self.opt, 1, pos)
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        poll_offset_seek_complete(&mut self.opt, 1, cx)
    }
}

impl<'a, 'b, 'c, F: AsyncWrite + AsyncSeek + Send + Unpin> RawFilterOptionWriter<'a, 'b, 'c, F> {
    pub async fn finish(self) -> std::io::Result<()> {
        Ok(())
    }

    pub fn big_endian(&self) -> bool {
        self.opt.big_endian()
    }

    pub fn little_endian(&self) -> bool {
        self.opt.little_endian()
    }

    pub async fn write_u8(&mut self, value: u8) -> std::io::Result<()> {
        self.write_all(&value.to_ne_bytes()[..]).await
    }

    pub async fn write_i8(&mut self, value: i8) -> std::io::Result<()> {
        self.write_all(&value.to_ne_bytes()[..]).await
    }

    pub async fn write_u16(&mut self, value: u16) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_i16(&mut self, value: i16) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_u32(&mut self, value: u32) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_i32(&mut self, value: i32) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_u64(&mut self, value: u64) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }

    pub async fn write_i64(&mut self, value: i64) -> std::io::Result<()> {
        if self.big_endian() {
            self.write_all(&value.to_be_bytes()[..]).await
        } else {
            self.write_all(&value.to_le_bytes()[..]).await
        }
    }
}

const END_OPT: [u8; 4] = [0u8; 4];

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> ShbOptionWriter<'a, F> {
    pub async fn finish(mut self) -> Result<(), Error> {
        self.finished = true;
        self.block.write_all(&END_OPT[..]).await?;
        Ok(())
    }

    pub async fn write_raw_option(&mut self, id: u16) -> Result<RawOptionWriter<'_, 'a, F>, Error> {
        self.finished = false;
        Ok(self.block.write_raw_option(id).await?)
    }

    pub async fn write_comment(&mut self, comment: &str) -> Result<(), Error> {
        let mut opt = self.write_raw_option(OPT_COMMENT).await?;
        opt.write_all(comment.as_bytes()).await?;
        opt.finish().await
    }

    pub async fn write_hardware(&mut self, hardware: &str) -> Result<(), Error> {
        let mut opt = self.write_raw_option(SHB_HARDWARE).await?;
        opt.write_all(hardware.as_bytes()).await?;
        opt.finish().await
    }

    pub async fn write_os(&mut self, os: &str) -> Result<(), Error> {
        let mut opt = self.write_raw_option(SHB_OS).await?;
        opt.write_all(os.as_bytes()).await?;
        opt.finish().await
    }

    pub async fn write_user_app(&mut self, user_app: &str) -> Result<(), Error> {
        let mut opt = self.write_raw_option(SHB_USERAPPL).await?;
        opt.write_all(user_app.as_bytes()).await?;
        opt.finish().await
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> Drop for ShbOptionWriter<'a, F> {
    fn drop(&mut self) {
        if !self.finished {
            panic!("Unfinished PCAPNG Section Header Block!");
        }
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> IdbOptionWriter<'a, F> {
    pub async fn finish(mut self) -> Result<(), Error> {
        self.finished = true;
        self.block.write_all(&END_OPT[..]).await?;
        Ok(())
    }

    pub async fn write_raw_option(&mut self, id: u16) -> Result<RawOptionWriter<'_, 'a, F>, Error> {
        self.finished = false;
        Ok(self.block.write_raw_option(id).await?)
    }

    pub async fn write_comment(&mut self, comment: &str) -> Result<(), Error> {
        let mut opt = self.write_raw_option(OPT_COMMENT).await?;
        opt.write_all(comment.as_bytes()).await?;
        opt.finish().await
    }

    pub async fn write_name(&mut self, name: &str) -> Result<(), Error> {
        let mut opt = self.write_raw_option(IF_NAME).await?;
        opt.write_all(name.as_bytes()).await?;
        opt.finish().await
    }

    pub async fn write_description(&mut self, desc: &str) -> Result<(), Error> {
        let mut opt = self.write_raw_option(IF_DESCRIPTION).await?;
        opt.write_all(desc.as_bytes()).await?;
        opt.finish().await
    }

    pub async fn write_ipv4_address(
        &mut self,
        addr: Ipv4Address,
        mask: Ipv4Address,
    ) -> Result<(), Error> {
        let mut opt = self.write_raw_option(IF_IPV4ADDR).await?;
        let buf: [u8; 4] = addr.into();
        opt.write_all(&buf[..]).await?;
        let buf: [u8; 4] = mask.into();
        opt.write_all(&buf[..]).await?;
        opt.finish().await
    }

    pub async fn write_ipv6_address(
        &mut self,
        addr: Ipv6Address,
        prefix_len: u8,
    ) -> Result<(), Error> {
        let buf: [u8; 16] = addr.into();
        let mut opt = self.write_raw_option(IF_IPV6ADDR).await?;
        opt.write_all(&buf[..]).await?;
        opt.write_u8(prefix_len).await?;
        opt.finish().await
    }

    pub async fn write_mac_address(&mut self, addr: MacAddress) -> Result<(), Error> {
        let buf: [u8; 6] = addr.into();
        let mut opt = self.write_raw_option(IF_MACADDR).await?;
        opt.write_all(&buf[..]).await?;
        opt.finish().await
    }

    pub async fn write_eui_address(&mut self, addr: HwAddress<8>) -> Result<(), Error> {
        let buf: [u8; 8] = addr.into();
        let mut opt = self.write_raw_option(IF_EUIADDR).await?;
        opt.write_all(&buf[..]).await?;
        opt.finish().await
    }

    pub async fn write_speed(&mut self, speed: u64) -> Result<(), Error> {
        let mut opt = self.write_raw_option(IF_SPEED).await?;
        opt.write_u64(speed).await?;
        opt.finish().await
    }

    pub async fn write_tsresol(&mut self, tsresol: u8) -> Result<(), Error> {
        let mut opt = self.write_raw_option(IF_TSRESOL).await?;
        opt.write_u8(tsresol).await?;
        opt.finish().await
    }

    pub async fn write_tzone(&mut self, tzone: i32) -> Result<(), Error> {
        let mut opt = self.write_raw_option(IF_TZONE).await?;
        opt.write_i32(tzone).await?;
        opt.finish().await
    }

    pub async fn write_filter(&mut self) -> Result<FilterOptionWriter<'_, 'a, F>, Error> {
        Ok(FilterOptionWriter {
            opt: self.write_raw_option(IF_FILTER).await?,
        })
    }

    pub async fn write_os(&mut self, os: &str) -> Result<(), Error> {
        let mut opt = self.write_raw_option(IF_OS).await?;
        opt.write_all(os.as_bytes()).await?;
        opt.finish().await
    }

    pub async fn write_fcslen(&mut self, fcslen: u8) -> Result<(), Error> {
        let mut opt = self.write_raw_option(IF_FCSLEN).await?;
        opt.write_u8(fcslen).await?;
        opt.finish().await
    }

    pub async fn write_tsoffset(&mut self, tsoffset: i64) -> Result<(), Error> {
        let mut opt = self.write_raw_option(IF_TSOFFSET).await?;
        opt.write_i64(tsoffset).await?;
        opt.finish().await
    }

    pub async fn write_hardware(&mut self, hardware: &str) -> Result<(), Error> {
        let mut opt = self.write_raw_option(IF_HARDWARE).await?;
        opt.write_all(hardware.as_bytes()).await?;
        opt.finish().await
    }

    pub async fn write_txspeed(&mut self, speed: u64) -> Result<(), Error> {
        let mut opt = self.write_raw_option(IF_TXSPEED).await?;
        opt.write_u64(speed).await?;
        opt.finish().await
    }

    pub async fn write_rxspeed(&mut self, speed: u64) -> Result<(), Error> {
        let mut opt = self.write_raw_option(IF_RXSPEED).await?;
        opt.write_u64(speed).await?;
        opt.finish().await
    }
}

impl<'a, 'b, F: AsyncWrite + AsyncSeek + Send + Unpin> FilterOptionWriter<'a, 'b, F> {
    pub async fn finish(self) -> Result<(), Error> {
        self.opt.finish().await
    }

    pub async fn write_string(mut self, filter: &str) -> Result<(), Error> {
        self.opt.write_u8(0).await?;
        self.opt.write_all(filter.as_bytes()).await?;
        self.opt.finish().await
    }

    pub async fn write_byte_code(mut self, filter: &[u8]) -> Result<(), Error> {
        self.opt.write_u8(1).await?;
        self.opt.write_all(filter).await?;
        self.opt.finish().await
    }

    pub async fn write_raw(
        &mut self,
        filter_type: u8,
    ) -> Result<RawFilterOptionWriter<'_, 'a, 'b, F>, Error> {
        self.opt.write_u8(filter_type).await?;
        Ok(RawFilterOptionWriter { opt: &mut self.opt })
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> EpbDataWriter<'a, F> {
    async fn finish_impl(&mut self) -> std::io::Result<()> {
        let custom_orig_len = self.custom_orig_len;
        if let Some(block) = self.block.as_mut() {
            let end = block.seek(SeekFrom::End(0)).await?;
            if end < 16 {
                block.write_u32(0).await?;
                block.write_u32(0).await?;
            } else {
                block.seek(SeekFrom::Start(16)).await?;
                let len = (end - 20) as u32;
                block.write_u32(len).await?;
                if !custom_orig_len {
                    block.write_u32(len).await?;
                }
                block.seek(SeekFrom::End(0)).await?;
                write_padding(block, len as usize).await?;
            }
        }
        Ok(())
    }

    pub async fn finish(mut self) -> Result<(), Error> {
        self.finish_impl().await?;
        guarantee(std::mem::replace(&mut self.block, None))
            .finish()
            .await
    }

    pub async fn write_options(mut self) -> Result<EpbOptionWriter<'a, F>, Error> {
        self.finish_impl().await?;
        let block = guarantee(std::mem::replace(&mut self.block, None));
        Ok(EpbOptionWriter {
            block,
            finished: true,
        })
    }

    pub async fn write_original_length(&mut self, orig_len: u32) -> Result<(), Error> {
        self.custom_orig_len = true;
        let block = guarantee(self.block.as_mut());
        let pos = block.stream_position().await?;
        block.seek(SeekFrom::Start(16)).await?;
        block.write_u32(orig_len).await?;
        block.seek(SeekFrom::Start(pos)).await?;
        Ok(())
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> AsyncWrite for EpbDataWriter<'a, F> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(guarantee(self.block.as_mut())).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(guarantee(self.block.as_mut())).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(guarantee(self.block.as_mut())).poll_shutdown(cx)
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> AsyncSeek for EpbDataWriter<'a, F> {
    fn start_seek(mut self: Pin<&mut Self>, pos: SeekFrom) -> std::io::Result<()> {
        start_offset_seek(guarantee(self.block.as_mut()), 20, pos)
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        poll_offset_seek_complete(guarantee(self.block.as_mut()), 20, cx)
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> Drop for EpbDataWriter<'a, F> {
    fn drop(&mut self) {
        if self.block.is_some() {
            panic!("Unfinished PCAPNG Enhanced Packet Block");
        }
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> EpbOptionWriter<'a, F> {
    pub async fn finish(mut self) -> Result<(), Error> {
        self.finished = true;
        self.block.write_all(&END_OPT[..]).await?;
        Ok(())
    }

    pub async fn write_raw_option(&mut self, id: u16) -> Result<RawOptionWriter<'_, 'a, F>, Error> {
        self.finished = false;
        Ok(self.block.write_raw_option(id).await?)
    }

    pub async fn write_comment(&mut self, comment: &str) -> Result<(), Error> {
        let mut opt = self.write_raw_option(OPT_COMMENT).await?;
        opt.write_all(comment.as_bytes()).await?;
        opt.finish().await
    }

    pub async fn write_raw_packet_flags(&mut self, flags: u32) -> Result<(), Error> {
        let mut opt = self.write_raw_option(EPB_FLAGS).await?;
        opt.write_u32(flags).await?;
        opt.finish().await
    }

    pub async fn write_packet_flags(
        &mut self,
    ) -> Result<PacketFlagsOptionWriter<'_, 'a, F>, Error> {
        Ok(PacketFlagsOptionWriter {
            block: self.write_raw_option(EPB_FLAGS).await?,
            flags: 0,
            finished: false,
        })
    }
}

impl<'a, 'b, F: AsyncWrite + AsyncSeek + Send + Unpin> PacketFlagsOptionWriter<'a, 'b, F> {
    pub async fn finish(mut self) -> Result<(), Error> {
        self.block.write_u32(self.flags).await?;
        self.block.finish_impl().await?;
        Ok(())
    }

    pub async fn write_direction(&mut self, dir: Direction) -> Result<(), Error> {
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

    pub async fn write_reception_type(&mut self, rtype: ReceptionType) -> Result<(), Error> {
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

    pub async fn write_fcs_length(&mut self, fcslen: u8) -> Result<(), Error> {
        if fcslen > 0b1111 {
            Err(Error::MalformedCapture)
        } else {
            self.flags &= !(0b1111 << 5);
            self.flags |= (fcslen as u32) << 5;
            Ok(())
        }
    }

    pub async fn write_link_layer_dependent_errors(
        &mut self,
        has_errors: bool,
    ) -> Result<(), Error> {
        const FLAG: u32 = 1 << 31;
        if has_errors {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }

    pub async fn write_preamble_error(&mut self, has_error: bool) -> Result<(), Error> {
        const FLAG: u32 = 1 << 30;
        if has_error {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }

    pub async fn write_start_frame_delimiter_error(
        &mut self,
        has_error: bool,
    ) -> Result<(), Error> {
        const FLAG: u32 = 1 << 29;
        if has_error {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }

    pub async fn write_unaligned_frame_error(&mut self, has_error: bool) -> Result<(), Error> {
        const FLAG: u32 = 1 << 28;
        if has_error {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }

    pub async fn write_wrong_inter_frame_gap_error(
        &mut self,
        has_error: bool,
    ) -> Result<(), Error> {
        const FLAG: u32 = 1 << 27;
        if has_error {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }

    pub async fn write_packet_too_short_error(&mut self, has_error: bool) -> Result<(), Error> {
        const FLAG: u32 = 1 << 26;
        if has_error {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }

    pub async fn write_packet_too_long_error(&mut self, has_error: bool) -> Result<(), Error> {
        const FLAG: u32 = 1 << 25;
        if has_error {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }

    pub async fn write_crc_error(&mut self, has_error: bool) -> Result<(), Error> {
        const FLAG: u32 = 1 << 24;
        if has_error {
            self.flags |= FLAG;
        } else {
            self.flags &= !FLAG;
        }
        Ok(())
    }
}

impl<'a, 'b, F: AsyncWrite + AsyncSeek + Send + Unpin> Drop for PacketFlagsOptionWriter<'a, 'b, F> {
    fn drop(&mut self) {
        if !self.finished {
            panic!("Unfinished PCAPNG packet flags option!");
        }
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> SpbDataWriter<'a, F> {
    pub async fn finish(mut self) -> Result<(), Error> {
        self.finished = true;
        let custom_orig_len = self.custom_orig_len;
        let snaplen = match self.block.writer.first_snaplen {
            Some(snaplen) => snaplen,
            None => {
                return Err(Error::MalformedCapture);
            }
        };
        let end = self.block.seek(SeekFrom::End(0)).await?;
        if end < 4 {
            self.block.write_u32(0).await?;
        } else {
            let len = (end - 4) as u32;
            if len > snaplen {
                return Err(Error::MalformedCapture);
            } else if !custom_orig_len {
                self.block.seek(SeekFrom::Start(0)).await?;
                self.block.write_u32(len).await?;
            }
            self.block.seek(SeekFrom::End(0)).await?;
            write_padding(&mut self.block, len as usize).await?;
        }
        self.block.finish_impl().await
    }

    pub async fn write_original_length(&mut self, orig_len: u32) -> Result<(), Error> {
        self.custom_orig_len = true;
        let pos = self.block.stream_position().await?;
        self.block.seek(SeekFrom::Start(0)).await?;
        self.block.write_u32(orig_len).await?;
        self.block.seek(SeekFrom::Start(pos)).await?;
        Ok(())
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> AsyncWrite for SpbDataWriter<'a, F> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.block).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.block).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.block).poll_shutdown(cx)
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> AsyncSeek for SpbDataWriter<'a, F> {
    fn start_seek(mut self: Pin<&mut Self>, pos: SeekFrom) -> std::io::Result<()> {
        start_offset_seek(&mut self.block, 4, pos)
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        poll_offset_seek_complete(&mut self.block, 4, cx)
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> Drop for SpbDataWriter<'a, F> {
    fn drop(&mut self) {
        if !self.finished {
            panic!("Unfinished PCAPNG Simple Packet Block");
        }
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> NrbRecordWriter<'a, F> {
    async fn finish_impl(&mut self) -> std::io::Result<()> {
        if let Some(block) = self.block.as_mut() {
            block.write_u16(NRB_RECORD_END).await?;
            block.write_u16(0).await?;
        }
        Ok(())
    }

    pub async fn write_ipv4_record(
        &mut self,
        addr: Ipv4Address,
    ) -> Result<NrbNameWriter<'_, 'a, F>, Error> {
        let block = guarantee(self.block.as_mut());
        block.write_u16(NRB_RECORD_IPV4).await?;
        let len_pos = block.stream_position().await?;
        block.write_u16(0).await?;
        block.write_all(&addr[..]).await?;
        Ok(NrbNameWriter { block, len_pos })
    }

    pub async fn write_ipv6_record(
        &mut self,
        addr: Ipv6Address,
    ) -> Result<NrbNameWriter<'_, 'a, F>, Error> {
        let block = guarantee(self.block.as_mut());
        block.write_u16(NRB_RECORD_IPV4).await?;
        let len_pos = block.stream_position().await?;
        block.write_u16(0).await?;
        block.write_all(&addr[..]).await?;
        Ok(NrbNameWriter { block, len_pos })
    }

    pub async fn finish(mut self) -> Result<(), Error> {
        self.finish_impl().await?;
        guarantee(std::mem::replace(&mut self.block, None))
            .finish()
            .await
    }

    pub async fn write_options(mut self) -> Result<NrbOptionWriter<'a, F>, Error> {
        self.finish_impl().await?;
        Ok(NrbOptionWriter {
            block: guarantee(std::mem::replace(&mut self.block, None)),
            finished: true,
        })
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> Drop for NrbRecordWriter<'a, F> {
    fn drop(&mut self) {
        if self.block.is_some() {
            panic!("Unfinished PCAPNG Name Resolution Block");
        }
    }
}

impl<'a, 'b, F: AsyncWrite + AsyncSeek + Send + Unpin> NrbNameWriter<'a, 'b, F> {
    pub async fn write_name(&mut self, name: &str) -> Result<(), Error> {
        self.block.write_all(name.as_bytes()).await?;
        self.block.write_u8(0).await?;
        Ok(())
    }

    pub async fn finish(mut self) -> Result<(), Error> {
        self.len_pos = u64::MAX;
        let end = self.block.stream_position().await?;
        let len = end - self.len_pos - 2;
        self.block.seek(SeekFrom::Start(self.len_pos)).await?;
        self.block.write_u16(len as u16).await?;
        self.block.seek(SeekFrom::End(0)).await?;
        Ok(())
    }
}

impl<'a, 'b, F: AsyncWrite + AsyncSeek + Send + Unpin> Drop for NrbNameWriter<'a, 'b, F> {
    fn drop(&mut self) {
        if self.len_pos != u64::MAX {
            panic!("Unfinished PCAPNG Name Resultion Block entry");
        }
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> NrbOptionWriter<'a, F> {
    pub async fn finish(mut self) -> Result<(), Error> {
        self.finished = true;
        self.block.write_all(&END_OPT[..]).await?;
        Ok(())
    }

    pub async fn write_raw_option(&mut self, id: u16) -> Result<RawOptionWriter<'_, 'a, F>, Error> {
        self.finished = false;
        Ok(self.block.write_raw_option(id).await?)
    }

    pub async fn write_comment(&mut self, comment: &str) -> Result<(), Error> {
        let mut opt = self.write_raw_option(OPT_COMMENT).await?;
        opt.write_all(comment.as_bytes()).await?;
        opt.finish().await
    }

    pub async fn write_dns_name(&mut self, name: &str) -> Result<(), Error> {
        let mut opt = self.write_raw_option(NS_DNSNAME).await?;
        opt.write_all(name.as_bytes()).await?;
        opt.finish().await
    }

    pub async fn write_dns_ipv4_address(&mut self, addr: Ipv4Address) -> Result<(), Error> {
        let mut opt = self.write_raw_option(NS_DNSIP4ADDR).await?;
        opt.write_all(&addr[..]).await?;
        opt.finish().await
    }

    pub async fn write_dns_ipv6_address(&mut self, addr: Ipv6Address) -> Result<(), Error> {
        let mut opt = self.write_raw_option(NS_DNSIP6ADDR).await?;
        opt.write_all(&addr[..]).await?;
        opt.finish().await
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> Drop for NrbOptionWriter<'a, F> {
    fn drop(&mut self) {
        if !self.finished {
            panic!("Unfinished PCAPNG Name Resolution Block option");
        }
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> IsbOptionWriter<'a, F> {
    pub async fn finish(mut self) -> Result<(), Error> {
        self.finished = true;
        self.block.write_all(&END_OPT[..]).await?;
        Ok(())
    }

    pub async fn write_raw_option(&mut self, id: u16) -> Result<RawOptionWriter<'_, 'a, F>, Error> {
        self.finished = false;
        Ok(self.block.write_raw_option(id).await?)
    }

    pub async fn write_comment(&mut self, comment: &str) -> Result<(), Error> {
        let mut opt = self.write_raw_option(OPT_COMMENT).await?;
        opt.write_all(comment.as_bytes()).await?;
        opt.finish().await
    }

    pub async fn write_start_time(&mut self, ts: u64) -> Result<(), Error> {
        let mut opt = self.write_raw_option(ISB_STARTTIME).await?;
        opt.write_u32((ts >> 32) as u32).await?;
        opt.write_u32((ts & 0xFFFFFFFF) as u32).await?;
        opt.finish().await
    }

    pub async fn write_end_time(&mut self, ts: u64) -> Result<(), Error> {
        let mut opt = self.write_raw_option(ISB_ENDTIME).await?;
        opt.write_u32((ts >> 32) as u32).await?;
        opt.write_u32((ts & 0xFFFFFFFF) as u32).await?;
        opt.finish().await
    }

    pub async fn write_ifrecv(&mut self, count: u64) -> Result<(), Error> {
        let mut opt = self.write_raw_option(ISB_IFRECV).await?;
        opt.write_u64(count).await?;
        opt.finish().await
    }

    pub async fn write_ifdrop(&mut self, count: u64) -> Result<(), Error> {
        let mut opt = self.write_raw_option(ISB_IFDROP).await?;
        opt.write_u64(count).await?;
        opt.finish().await
    }

    pub async fn write_filter_accept(&mut self, count: u64) -> Result<(), Error> {
        let mut opt = self.write_raw_option(ISB_FILTERACCEPT).await?;
        opt.write_u64(count).await?;
        opt.finish().await
    }

    pub async fn write_osdrop(&mut self, count: u64) -> Result<(), Error> {
        let mut opt = self.write_raw_option(ISB_OSDROP).await?;
        opt.write_u64(count).await?;
        opt.finish().await
    }

    pub async fn write_user_deliv(&mut self, count: u64) -> Result<(), Error> {
        let mut opt = self.write_raw_option(ISB_USRDELIV).await?;
        opt.write_u64(count).await?;
        opt.finish().await
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> Drop for IsbOptionWriter<'a, F> {
    fn drop(&mut self) {
        if !self.finished {
            panic!("Unfinished PCAPNG Interface Statistics Block");
        }
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> SjbEntryWriter<'a, F> {
    pub async fn finish(mut self) -> Result<(), Error> {
        self.finished = true;
        let end = self.block.seek(SeekFrom::End(0)).await?;
        let len = end - self.block.body_start;
        write_padding(&mut self.block, ((4 - (len % 4)) % 4) as usize).await?;
        Ok(())
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> AsyncWrite for SjbEntryWriter<'a, F> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.block).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.block).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.block).poll_shutdown(cx)
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> AsyncSeek for SjbEntryWriter<'a, F> {
    fn start_seek(mut self: Pin<&mut Self>, pos: SeekFrom) -> std::io::Result<()> {
        Pin::new(&mut self.block).start_seek(pos)
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        Pin::new(&mut self.block).poll_complete(cx)
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> Drop for SjbEntryWriter<'a, F> {
    fn drop(&mut self) {
        if !self.finished {
            panic!("Unfinished systemd Journal Export Block");
        }
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> DsbSecretsWriter<'a, F> {
    async fn finish_impl(&mut self) -> std::io::Result<()> {
        let body_start = self.body_start;
        if let Some(block) = self.block.as_mut() {
            let end = block.seek(SeekFrom::End(0)).await?;
            let len = (end - body_start) as u32;
            block.seek(SeekFrom::Start(4)).await?;
            block.write_u32(len).await?;
            block.seek(SeekFrom::End(0)).await?;
            write_padding(block, len as usize).await?;
        }
        Ok(())
    }

    pub async fn finish(mut self) -> Result<(), Error> {
        self.finish_impl().await?;
        guarantee(std::mem::replace(&mut self.block, None))
            .finish()
            .await
    }

    pub async fn write_options(mut self) -> Result<DsbOptionWriter<'a, F>, Error> {
        self.finish_impl().await?;
        let block = guarantee(std::mem::replace(&mut self.block, None));
        Ok(DsbOptionWriter {
            block,
            finished: true,
        })
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> AsyncWrite for DsbSecretsWriter<'a, F> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(guarantee(self.block.as_mut())).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(guarantee(self.block.as_mut())).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(guarantee(self.block.as_mut())).poll_shutdown(cx)
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> AsyncSeek for DsbSecretsWriter<'a, F> {
    fn start_seek(mut self: Pin<&mut Self>, pos: SeekFrom) -> std::io::Result<()> {
        let start = self.body_start;
        start_offset_seek(guarantee(self.block.as_mut()), start, pos)
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        let start = self.body_start;
        poll_offset_seek_complete(guarantee(self.block.as_mut()), start, cx)
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> Drop for DsbSecretsWriter<'a, F> {
    fn drop(&mut self) {
        if self.block.is_some() {
            panic!("Unfinished PCAPNG Decryption Secrets Block");
        }
    }
}

impl<'a, F: AsyncWrite + AsyncSeek + Send + Unpin> DsbOptionWriter<'a, F> {
    pub async fn finish(mut self) -> Result<(), Error> {
        self.finished = true;
        self.block.write_all(&END_OPT[..]).await?;
        Ok(())
    }

    pub async fn write_raw_option(&mut self, id: u16) -> Result<RawOptionWriter<'_, 'a, F>, Error> {
        self.finished = false;
        Ok(self.block.write_raw_option(id).await?)
    }

    pub async fn write_comment(&mut self, comment: &str) -> Result<(), Error> {
        let mut opt = self.write_raw_option(OPT_COMMENT).await?;
        opt.write_all(comment.as_bytes()).await?;
        opt.finish().await
    }
}
