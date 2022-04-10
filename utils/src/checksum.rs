use std::io::{Result, Write};

#[derive(Clone, Copy, Default, Debug)]
pub struct U16OnesComplement {
    sum: u16,
    extra: Option<u8>,
}

impl U16OnesComplement {
    pub fn new() -> Self {
        Self {
            sum: 0,
            extra: None,
        }
    }

    fn add(&mut self, word: u16) {
        self.sum = self.sum.wrapping_add(word);
    }

    pub fn checksum(&self) -> u16 {
        !self.sum
    }
}

impl Write for U16OnesComplement {
    fn write(&mut self, mut buf: &[u8]) -> Result<usize> {
        let len = buf.len();
        if !buf.is_empty() {
            if let Some(first) = self.extra.take() {
                self.add(u16::from_be_bytes([first, buf[0]]));
                buf = &buf[1..];
            }
        }
        while buf.len() > 1 {
            self.add(u16::from_be_bytes([buf[0], buf[1]]));
            buf = &buf[2..];
        }
        if !buf.is_empty() {
            self.extra = Some(buf[0]);
        }
        Ok(len)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
