use super::*;
use sniffle_core::Error;
use tokio::io::AsyncWriteExt;

pub struct Writer<F: tokio::io::AsyncWrite + Send + Unpin> {
    file: F,
    snaplen: u32,
    be: bool,
}

pub type FileWriter = Writer<tokio::io::BufWriter<tokio::fs::File>>;

impl<F: tokio::io::AsyncWrite + Send + Unpin> Writer<F> {
    pub async fn new(mut file: F, header: &Header) -> Result<Self, Error> {
        let be = match header.magic {
            BE_MAGIC_U => true,
            BE_MAGIC_N => true,
            LE_MAGIC_U => false,
            LE_MAGIC_N => false,
            _ => {
                return Err(Error::MalformedCapture);
            }
        };
        file.write_all(&header.magic.to_ne_bytes()[..]).await?;
        if be {
            file.write_all(&header.version_major.to_be_bytes()[..])
                .await?;
            file.write_all(&header.version_minor.to_be_bytes()[..])
                .await?;
            file.write_all(&header.thiszone.to_be_bytes()[..]).await?;
            file.write_all(&header.sigfigs.to_be_bytes()[..]).await?;
            file.write_all(&header.snaplen.to_be_bytes()[..]).await?;
            file.write_all(&header.network.to_be_bytes()[..]).await?;
        } else {
            file.write_all(&header.version_major.to_le_bytes()[..])
                .await?;
            file.write_all(&header.version_minor.to_le_bytes()[..])
                .await?;
            file.write_all(&header.thiszone.to_le_bytes()[..]).await?;
            file.write_all(&header.sigfigs.to_le_bytes()[..]).await?;
            file.write_all(&header.snaplen.to_le_bytes()[..]).await?;
            file.write_all(&header.network.to_le_bytes()[..]).await?;
        }
        Ok(Writer {
            file,
            snaplen: header.snaplen,
            be,
        })
    }

    pub async fn create<P: AsRef<std::path::Path>>(
        path: P,
        header: &Header,
    ) -> Result<FileWriter, Error> {
        FileWriter::new(
            tokio::io::BufWriter::new(tokio::fs::File::create(path).await?),
            header,
        )
        .await
    }

    pub async fn write_record(&mut self, header: &RecordHeader, data: &[u8]) -> Result<(), Error> {
        if header.incl_len as usize != data.len()
            || header.incl_len > header.orig_len
            || header.incl_len > self.snaplen
        {
            return Err(Error::MalformedCapture);
        }

        if self.be {
            self.file
                .write_all(&header.ts_sec.to_be_bytes()[..])
                .await?;
            self.file
                .write_all(&header.ts_frac.to_be_bytes()[..])
                .await?;
            self.file
                .write_all(&header.incl_len.to_be_bytes()[..])
                .await?;
            self.file
                .write_all(&header.orig_len.to_be_bytes()[..])
                .await?;
        } else {
            self.file
                .write_all(&header.ts_sec.to_le_bytes()[..])
                .await?;
            self.file
                .write_all(&header.ts_frac.to_le_bytes()[..])
                .await?;
            self.file
                .write_all(&header.incl_len.to_le_bytes()[..])
                .await?;
            self.file
                .write_all(&header.orig_len.to_le_bytes()[..])
                .await?;
        }
        self.file.write_all(data).await?;
        Ok(())
    }
}
