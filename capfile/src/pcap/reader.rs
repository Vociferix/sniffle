use super::*;
use sniffle_core::Error;
use tokio::io::AsyncReadExt;

pub struct Reader<F: tokio::io::AsyncBufRead + Send + Unpin> {
    file: F,
    hdr: Header,
    be: bool,
    nano: bool,
}

pub type FileReader = Reader<tokio::io::BufReader<tokio::fs::File>>;

impl<F: tokio::io::AsyncBufRead + Send + Unpin> Reader<F> {
    pub async fn new(mut file: F) -> Result<Self, Error> {
        let mut hdr = [0u8; 24];
        file.read_exact(&mut hdr[..]).await?;
        let magic = u32::from_ne_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);

        let (be, nano) = match magic {
            BE_MAGIC_U => (true, false),
            BE_MAGIC_N => (true, true),
            LE_MAGIC_U => (false, false),
            LE_MAGIC_N => (false, true),
            _ => {
                return Err(Error::MalformedCapture);
            }
        };

        let hdr = if be {
            Header {
                magic,
                version_major: u16::from_be_bytes([hdr[4], hdr[5]]),
                version_minor: u16::from_be_bytes([hdr[6], hdr[7]]),
                thiszone: i32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
                sigfigs: u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]),
                snaplen: u32::from_be_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]),
                network: u32::from_be_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]),
            }
        } else {
            Header {
                magic,
                version_major: u16::from_le_bytes([hdr[4], hdr[5]]),
                version_minor: u16::from_le_bytes([hdr[6], hdr[7]]),
                thiszone: i32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
                sigfigs: u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]),
                snaplen: u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]),
                network: u32::from_le_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]),
            }
        };

        Ok(Self {
            file,
            hdr,
            be,
            nano,
        })
    }

    pub async fn open<P: AsRef<std::path::Path>>(path: P) -> Result<FileReader, Error> {
        FileReader::new(tokio::io::BufReader::new(
            tokio::fs::File::open(path).await?,
        ))
        .await
    }

    pub fn header(&self) -> &Header {
        &self.hdr
    }

    pub fn big_endian_encoded(&self) -> bool {
        self.be
    }

    pub fn little_endian_encoded(&self) -> bool {
        !self.be
    }

    pub fn timestamp_precision(&self) -> TsPrecision {
        if self.nano {
            TsPrecision::Nano
        } else {
            TsPrecision::Micro
        }
    }

    pub async fn next_record(
        &mut self,
        buffer: &mut Vec<u8>,
    ) -> Result<Option<RecordHeader>, Error> {
        let mut hdr = [0u8; 16];
        match self.file.read_exact(&mut hdr[..]).await {
            Ok(_) => {}
            Err(e) => {
                let kind = e.kind();
                match kind {
                    std::io::ErrorKind::UnexpectedEof => {
                        return Ok(None);
                    }
                    _ => {
                        return Err(Error::from(e));
                    }
                }
            }
        }

        let hdr = if self.be {
            RecordHeader {
                ts_sec: u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]),
                ts_frac: u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]),
                incl_len: u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
                orig_len: u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]),
            }
        } else {
            RecordHeader {
                ts_sec: u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]),
                ts_frac: u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]),
                incl_len: u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
                orig_len: u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]),
            }
        };

        buffer.resize(hdr.incl_len as usize, 0);
        self.file.read_exact(&mut buffer[..]).await?;
        Ok(Some(hdr))
    }
}
