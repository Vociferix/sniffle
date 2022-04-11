use super::writer::*;
use super::*;
use sniffle_core::{LinkType, Packet, Pdu, Transmit, TransmitError};
use std::time::{Duration, SystemTime};

enum State<F: std::io::Write> {
    Init {
        file: F,
        nano: bool,
    },
    Norm {
        writer: Writer<F>,
        buf: Vec<u8>,
        snaplen: u32,
        link: LinkType,
        nano: bool,
    },
    Empty,
}

pub struct Recorder<F: std::io::Write> {
    state: State<F>,
}

pub type FileRecorder = Recorder<std::io::BufWriter<std::fs::File>>;

impl<F: std::io::Write> Recorder<F> {
    pub fn new(file: F) -> Self {
        Self::new_with_tsprec(file, TsPrecision::Micro)
    }

    pub fn new_nano(file: F) -> Self {
        Self::new_with_tsprec(file, TsPrecision::Nano)
    }

    pub fn new_with_tsprec(file: F, tsprec: TsPrecision) -> Self {
        Self {
            state: State::Init {
                file,
                nano: match tsprec {
                    TsPrecision::Micro => false,
                    TsPrecision::Nano => true,
                },
            },
        }
    }

    pub fn create<P: AsRef<std::path::Path>>(path: P) -> Result<FileRecorder, TransmitError> {
        FileRecorder::create_with_tsprec(path, TsPrecision::Micro)
    }

    pub fn create_nano<P: AsRef<std::path::Path>>(path: P) -> Result<FileRecorder, TransmitError> {
        FileRecorder::create_with_tsprec(path, TsPrecision::Nano)
    }

    pub fn create_with_tsprec<P: AsRef<std::path::Path>>(
        path: P,
        tsprec: TsPrecision,
    ) -> Result<FileRecorder, TransmitError> {
        Ok(FileRecorder::new_with_tsprec(
            std::io::BufWriter::new(std::fs::File::create(path)?),
            tsprec,
        ))
    }
}

fn transmit_impl<F: std::io::Write>(
    mut writer: Writer<F>,
    buf: Vec<u8>,
    snaplen: u32,
    orig_len: u32,
    link: LinkType,
    nano: bool,
    ts: SystemTime,
) -> Result<State<F>, TransmitError> {
    let dur = match ts.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(val) => val,
        Err(_) => Duration::new(0, 0),
    };
    let hdr = RecordHeader {
        ts_sec: dur.as_secs() as u32,
        ts_frac: if nano {
            dur.subsec_nanos()
        } else {
            dur.subsec_micros()
        },
        incl_len: buf.len() as u32,
        orig_len,
    };
    writer.write_record(&hdr, &buf[..])?;
    Ok(State::Norm {
        writer,
        buf,
        snaplen,
        link,
        nano,
    })
}

impl<F: std::io::Write> Transmit for Recorder<F> {
    fn transmit(&mut self, packet: &Packet) -> Result<(), TransmitError> {
        let pkt_link = match LinkType::from_pdu(packet.pdu()) {
            Some(link) => link,
            None => {
                return Err(TransmitError::UnknownLinkType);
            }
        };
        let state = std::mem::replace(&mut self.state, State::Empty);
        self.state = match state {
            State::Init { file, nano } => {
                let hdr = Header {
                    magic: if nano { LE_MAGIC_N } else { LE_MAGIC_U },
                    version_major: 2,
                    version_minor: 4,
                    thiszone: 0,
                    sigfigs: 0,
                    snaplen: packet.snaplen() as u32,
                    network: pkt_link.0 as u32,
                };
                let mut buf: Vec<u8> = Vec::new();
                packet.pdu().serialize(&mut buf)?;
                transmit_impl(
                    Writer::new(file, &hdr)?,
                    Vec::new(),
                    hdr.snaplen,
                    packet.len() as u32,
                    pkt_link,
                    nano,
                    packet.timestamp(),
                )?
            }
            State::Norm {
                writer,
                mut buf,
                snaplen,
                link,
                nano,
            } => {
                if link != pkt_link {
                    return Err(TransmitError::MalformedCapture);
                }
                packet.pdu().serialize(&mut buf)?;
                if buf.len() > snaplen as usize {
                    return Err(TransmitError::MalformedCapture);
                }
                transmit_impl(
                    writer,
                    buf,
                    snaplen,
                    packet.len() as u32,
                    link,
                    nano,
                    packet.timestamp(),
                )?
            }
            State::Empty => panic!("Recorder in erroneous state"),
        };
        Ok(())
    }
}
