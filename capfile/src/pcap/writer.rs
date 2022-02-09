use super::*;
use sniffle_core::TransmitError;

pub struct Writer<F: std::io::Write> {
    file: F,
    snaplen: u32,
    be: bool,
}

pub type FileWriter = Writer<std::io::BufWriter<std::fs::File>>;

impl<F: std::io::Write> Writer<F> {
    pub fn new(mut file: F, header: &Header) -> Result<Self, TransmitError> {
        let be = match header.magic {
            BE_MAGIC_U => true,
            BE_MAGIC_N => true,
            LE_MAGIC_U => false,
            LE_MAGIC_N => false,
            _ => {
                return Err(TransmitError::MalformedCapture);
            }
        };
        file.write_all(&header.magic.to_ne_bytes()[..])?;
        if be {
            file.write_all(&header.version_major.to_be_bytes()[..])?;
            file.write_all(&header.version_minor.to_be_bytes()[..])?;
            file.write_all(&header.thiszone.to_be_bytes()[..])?;
            file.write_all(&header.sigfigs.to_be_bytes()[..])?;
            file.write_all(&header.snaplen.to_be_bytes()[..])?;
            file.write_all(&header.network.to_be_bytes()[..])?;
        } else {
            file.write_all(&header.version_major.to_le_bytes()[..])?;
            file.write_all(&header.version_minor.to_le_bytes()[..])?;
            file.write_all(&header.thiszone.to_le_bytes()[..])?;
            file.write_all(&header.sigfigs.to_le_bytes()[..])?;
            file.write_all(&header.snaplen.to_le_bytes()[..])?;
            file.write_all(&header.network.to_le_bytes()[..])?;
        }
        Ok(Writer {
            file,
            snaplen: header.snaplen,
            be,
        })
    }

    pub fn create<P: AsRef<std::path::Path>>(
        path: P,
        header: &Header,
    ) -> Result<FileWriter, TransmitError> {
        FileWriter::new(
            std::io::BufWriter::new(std::fs::File::create(path)?),
            header,
        )
    }

    pub fn write_record(
        &mut self,
        header: &RecordHeader,
        data: &[u8],
    ) -> Result<(), TransmitError> {
        if header.incl_len as usize != data.len()
            || header.incl_len > header.orig_len
            || header.incl_len > self.snaplen
        {
            return Err(TransmitError::MalformedCapture);
        }

        if self.be {
            self.file.write_all(&header.ts_sec.to_be_bytes()[..])?;
            self.file.write_all(&header.ts_frac.to_be_bytes()[..])?;
            self.file.write_all(&header.incl_len.to_be_bytes()[..])?;
            self.file.write_all(&header.orig_len.to_be_bytes()[..])?;
        } else {
            self.file.write_all(&header.ts_sec.to_le_bytes()[..])?;
            self.file.write_all(&header.ts_frac.to_le_bytes()[..])?;
            self.file.write_all(&header.incl_len.to_le_bytes()[..])?;
            self.file.write_all(&header.orig_len.to_le_bytes()[..])?;
        }
        self.file.write_all(data)?;
        Ok(())
    }
}
