use sniffle_ende::encode::Encoder;

pub struct CountingEncoder<'a, 'b, E: Encoder<'a> + ?Sized> {
    encoder: &'b mut E,
    bytes: usize,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, 'b, E: Encoder<'a> + ?Sized> CountingEncoder<'a, 'b, E> {
    pub fn new(encoder: &'b mut E) -> Self {
        Self {
            encoder,
            bytes: 0,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn into_inner(self) -> &'b mut E {
        self.encoder
    }

    pub fn bytes_written(&self) -> usize {
        self.bytes
    }
}

impl<'a, 'b, E: Encoder<'a> + ?Sized> std::io::Write for CountingEncoder<'a, 'b, E> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let bytes = self.encoder.write(buf)?;
        self.bytes += bytes;
        Ok(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.encoder.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.encoder.write_all(buf)?;
        self.bytes += buf.len();
        Ok(())
    }
}
