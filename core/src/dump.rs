use std::any::Any;

pub trait Dump {
    type Error: Any + 'static;

    fn start_packet(&mut self) -> Result<(), Self::Error>;

    fn end_packet(&mut self);

    fn start_node(&mut self, name: &str, descr: Option<&str>) -> Result<(), Self::Error>;

    fn end_node(&mut self);

    fn add_field(&mut self, name: &str, descr: &str, bytes: &[u8]) -> Result<(), Self::Error>;

    fn add_bit_field(
        &mut self,
        name: &str,
        descr: &str,
        value: u64,
        bits: u8,
    ) -> Result<(), Self::Error>;

    fn add_padding(&mut self, num_bytes: usize, byte_value: u8) -> Result<(), Self::Error>;

    fn add_padding_bytes(&mut self, _padding: &[u8]) -> Result<(), Self::Error> {
        todo!()
    }
}

pub struct Dumper<D: Dump>(D);

pub struct NodeDumper<'a, D: Dump + ?Sized>(&'a mut D, bool, bool);

struct DynDumpWrapper<'a, D: Dump + ?Sized>(&'a mut D);

pub struct DebugDumper<W: std::io::Write> {
    writer: W,
    depth: usize,
    count: u64,
}

pub struct ByteDumpFormatter<'a>(pub &'a [u8]);

impl<'a> std::fmt::Display for ByteDumpFormatter<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl<'a, D: Dump + ?Sized> Dump for &'a mut D {
    type Error = D::Error;

    fn start_packet(&mut self) -> Result<(), Self::Error> {
        D::start_packet(*self)
    }

    fn end_packet(&mut self) {
        D::end_packet(*self)
    }

    fn start_node(&mut self, name: &str, descr: Option<&str>) -> Result<(), Self::Error> {
        D::start_node(*self, name, descr)
    }

    fn end_node(&mut self) {
        D::end_node(*self);
    }

    fn add_field(&mut self, name: &str, descr: &str, bytes: &[u8]) -> Result<(), Self::Error> {
        D::add_field(*self, name, descr, bytes)
    }

    fn add_bit_field(
        &mut self,
        name: &str,
        descr: &str,
        value: u64,
        bits: u8,
    ) -> Result<(), Self::Error> {
        D::add_bit_field(*self, name, descr, value, bits)
    }

    fn add_padding(&mut self, num_bytes: usize, byte_value: u8) -> Result<(), Self::Error> {
        D::add_padding(*self, num_bytes, byte_value)
    }

    fn add_padding_bytes(&mut self, padding: &[u8]) -> Result<(), Self::Error> {
        D::add_padding_bytes(*self, padding)
    }
}

fn to_boxed_any<T: Any + 'static>(val: T) -> Box<dyn Any + 'static> {
    Box::new(val)
}

impl<'a, D: Dump + ?Sized> Dump for DynDumpWrapper<'a, D> {
    type Error = Box<dyn Any + 'static>;

    fn start_packet(&mut self) -> Result<(), Self::Error> {
        self.0.start_packet().map_err(to_boxed_any)
    }

    fn end_packet(&mut self) {
        self.0.end_packet();
    }

    fn start_node(&mut self, name: &str, descr: Option<&str>) -> Result<(), Self::Error> {
        self.0.start_node(name, descr).map_err(to_boxed_any)
    }

    fn end_node(&mut self) {
        self.0.end_node();
    }

    fn add_field(&mut self, name: &str, descr: &str, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.add_field(name, descr, bytes).map_err(to_boxed_any)
    }

    fn add_bit_field(
        &mut self,
        name: &str,
        descr: &str,
        value: u64,
        bits: u8,
    ) -> Result<(), Self::Error> {
        self.0
            .add_bit_field(name, descr, value, bits)
            .map_err(to_boxed_any)
    }

    fn add_padding(&mut self, num_bytes: usize, byte_value: u8) -> Result<(), Self::Error> {
        self.0
            .add_padding(num_bytes, byte_value)
            .map_err(to_boxed_any)
    }

    fn add_padding_bytes(&mut self, padding: &[u8]) -> Result<(), Self::Error> {
        self.0.add_padding_bytes(padding).map_err(to_boxed_any)
    }
}

impl<D: Dump> Dumper<D> {
    pub fn new(raw_dumper: D) -> Self {
        Self(raw_dumper)
    }

    pub fn as_inner(&self) -> &D {
        &self.0
    }

    pub fn as_inner_mut(&mut self) -> &mut D {
        &mut self.0
    }

    pub fn add_packet(&mut self) -> Result<NodeDumper<'_, D>, D::Error> {
        self.0.start_packet()?;
        Ok(NodeDumper(&mut self.0, true, true))
    }
}

impl<'a, D: Dump + ?Sized> NodeDumper<'a, D> {
    pub fn add_node<'b>(
        &'b mut self,
        name: &str,
        descr: Option<&str>,
    ) -> Result<NodeDumper<'b, D>, D::Error> {
        self.0.start_node(name, descr)?;
        Ok(NodeDumper(self.0, true, false))
    }

    pub fn add_field(&mut self, name: &str, descr: &str, bytes: &[u8]) -> Result<(), D::Error> {
        self.0.add_field(name, descr, bytes)
    }

    pub fn add_bit_field(
        &mut self,
        name: &str,
        descr: &str,
        value: u64,
        bits: u8,
    ) -> Result<(), D::Error> {
        self.0.add_bit_field(name, descr, value, bits)
    }

    pub fn add_padding(&mut self, num_bytes: usize, byte_value: u8) -> Result<(), D::Error> {
        self.0.add_padding(num_bytes, byte_value)
    }

    pub fn add_padding_bytes(&mut self, padding: &[u8]) -> Result<(), D::Error> {
        self.0.add_padding_bytes(padding)
    }

    pub(crate) fn as_dyn_dumper<F>(&mut self, f: F) -> Result<(), D::Error>
    where
        F: for<'b, 'c> Fn(
            &mut NodeDumper<'b, dyn Dump<Error = Box<dyn Any + 'static>> + 'c>,
        ) -> Result<(), Box<dyn Any + 'static>>,
    {
        let mut wrapper = DynDumpWrapper(self.0);
        let dyn_dumper: &mut dyn Dump<Error = Box<dyn Any + 'static>> = &mut wrapper;
        let mut dumper = NodeDumper(dyn_dumper, false, false);
        f(&mut dumper).map_err(|e| -> D::Error {
            match e.downcast() {
                Ok(e) => *e,
                _ => panic!("improper use of NodeDumper"),
            }
        })
    }
}

impl<'a, D: Dump + ?Sized> Drop for NodeDumper<'a, D> {
    fn drop(&mut self) {
        if self.1 {
            if self.2 {
                self.0.end_packet();
            } else {
                self.0.end_node();
            }
        }
    }
}

impl<W: std::io::Write> DebugDumper<W> {
    pub fn new(writer: W) -> Dumper<Self> {
        Dumper::new(Self {
            writer,
            depth: 0,
            count: 0,
        })
    }

    pub fn as_inner(&self) -> &W {
        &self.writer
    }

    pub fn as_inner_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    pub fn packet_count(&self) -> u64 {
        self.count
    }

    fn indent(&mut self) -> std::io::Result<()> {
        for _ in 0..self.depth {
            write!(self.writer, "  ")?;
        }
        Ok(())
    }
}

impl<W: std::io::Write> Dump for DebugDumper<W> {
    type Error = std::io::Error;

    fn start_packet(&mut self) -> Result<(), Self::Error> {
        self.depth += 1;
        self.count += 1;
        writeln!(self.writer, "Packet {}", self.count)
    }

    fn end_packet(&mut self) {
        self.depth -= 1;
    }

    fn start_node(&mut self, name: &str, descr: Option<&str>) -> Result<(), Self::Error> {
        self.indent()?;
        self.depth += 1;
        match descr {
            Some(descr) => writeln!(self.writer, "{}: {}", name, descr),
            None => writeln!(self.writer, "{}", name),
        }
    }

    fn end_node(&mut self) {
        self.depth -= 1;
    }

    fn add_field(&mut self, name: &str, descr: &str, _bytes: &[u8]) -> Result<(), Self::Error> {
        self.indent()?;
        writeln!(self.writer, "{}: {}", name, descr)
    }

    fn add_bit_field(
        &mut self,
        name: &str,
        descr: &str,
        _value: u64,
        _bits: u8,
    ) -> Result<(), Self::Error> {
        self.indent()?;
        writeln!(self.writer, "{}: {}", name, descr)
    }

    fn add_padding(&mut self, _num_bytes: usize, _byte_value: u8) -> Result<(), Self::Error> {
        Ok(())
    }

    fn add_padding_bytes(&mut self, _padding: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}
