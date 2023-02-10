use super::writer::*;
use super::*;
use async_trait::async_trait;
use sniffle_core::{Error, RawPacket, Transmit};
use std::time::{Duration, SystemTime};

enum FileOrWriter<F: tokio::io::AsyncWrite + Send + Unpin> {
    File(F),
    Writer(Writer<F>),
    Empty,
}

pub struct Recorder<F: tokio::io::AsyncWrite + Send + Unpin> {
    out: FileOrWriter<F>,
    buf: Vec<u8>,
    nano: bool,
}

pub type FileRecorder = Recorder<tokio::io::BufWriter<tokio::fs::File>>;

impl<F: tokio::io::AsyncWrite + Send + Unpin> Recorder<F> {
    pub fn new(file: F) -> Self {
        Self::new_with_tsprec(file, TsPrecision::Micro)
    }

    pub fn new_nano(file: F) -> Self {
        Self::new_with_tsprec(file, TsPrecision::Nano)
    }

    pub fn new_with_tsprec(file: F, tsprec: TsPrecision) -> Self {
        Self {
            out: FileOrWriter::File(file),
            buf: Vec::new(),
            nano: matches!(tsprec, TsPrecision::Nano),
        }
    }

    pub async fn create<P: AsRef<std::path::Path>>(path: P) -> Result<FileRecorder, Error> {
        FileRecorder::create_with_tsprec(path, TsPrecision::Micro).await
    }

    pub async fn create_nano<P: AsRef<std::path::Path>>(path: P) -> Result<FileRecorder, Error> {
        FileRecorder::create_with_tsprec(path, TsPrecision::Nano).await
    }

    pub async fn create_with_tsprec<P: AsRef<std::path::Path>>(
        path: P,
        tsprec: TsPrecision,
    ) -> Result<FileRecorder, Error> {
        Ok(FileRecorder::new_with_tsprec(
            tokio::io::BufWriter::new(tokio::fs::File::create(path).await?),
            tsprec,
        ))
    }
}

#[async_trait]
impl<F: tokio::io::AsyncWrite + Send + Unpin> Transmit for Recorder<F> {
    async fn transmit_raw(&mut self, packet: RawPacket<'_>) -> Result<(), Error> {
        let fow = std::mem::replace(&mut self.out, FileOrWriter::Empty);
        let mut writer = match fow {
            FileOrWriter::File(file) => {
                let hdr = Header {
                    magic: if self.nano { LE_MAGIC_N } else { LE_MAGIC_U },
                    version_major: 2,
                    version_minor: 4,
                    thiszone: 0,
                    sigfigs: 0,
                    snaplen: packet.snaplen() as u32,
                    network: packet.datalink().0.into(),
                };
                Writer::new(file, &hdr).await?
            }
            FileOrWriter::Writer(writer) => writer,
            _ => panic!("Recorder in erroneous state!"),
        };

        let dur = match packet.timestamp().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(val) => val,
            Err(_) => Duration::new(0, 0),
        };
        let hdr = RecordHeader {
            ts_sec: dur.as_secs() as u32,
            ts_frac: if self.nano {
                dur.subsec_nanos()
            } else {
                dur.subsec_micros()
            },
            incl_len: packet.data().len() as u32,
            orig_len: packet.orig_len() as u32,
        };
        let res = writer.write_record(&hdr, packet.data()).await;
        self.out = FileOrWriter::Writer(writer);
        res
    }

    fn transmission_buffer(&mut self) -> Option<&mut Vec<u8>> {
        Some(&mut self.buf)
    }
}
