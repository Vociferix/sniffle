use chrono::{offset::Utc, DateTime};
use std::any::Any;

#[derive(Debug)]
#[non_exhaustive]
pub enum DumpValue<'a> {
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    Text(&'a str),
    Bytes(&'a [u8]),
    Time(std::time::SystemTime),
    Duration(std::time::Duration),
}

pub trait Dump {
    type Error: Any + 'static;

    fn start_packet(&mut self) -> Result<(), Self::Error>;

    fn end_packet(&mut self);

    fn start_node(&mut self, name: &str, descr: Option<&str>) -> Result<(), Self::Error>;

    fn end_node(&mut self);

    fn add_field(
        &mut self,
        name: &str,
        value: DumpValue<'_>,
        descr: Option<&str>,
    ) -> Result<(), Self::Error>;

    fn add_info(&mut self, name: &str, descr: &str) -> Result<(), Self::Error>;

    fn start_list(&mut self, name: &str, descr: Option<&str>) -> Result<(), Self::Error>;

    fn end_list(&mut self);

    fn add_list_item(
        &mut self,
        value: DumpValue<'_>,
        descr: Option<&str>,
    ) -> Result<(), Self::Error>;

    fn start_list_node(&mut self, descr: Option<&str>) -> Result<(), Self::Error>;

    fn end_list_node(&mut self);

    fn start_list_sublist(&mut self, descr: Option<&str>) -> Result<(), Self::Error>;

    fn end_list_sublist(&mut self);
}

pub struct Dumper<D: Dump>(D);

#[derive(Clone, Copy)]
enum NodeKind {
    Virtual,
    Packet,
    SubNode,
    ListNode,
}

#[derive(Clone, Copy)]
enum ListKind {
    List,
    SubList,
}

pub struct NodeDumper<'a, D: Dump + ?Sized>(&'a mut D, NodeKind);

pub struct ListDumper<'a, D: Dump + ?Sized>(&'a mut D, ListKind);

struct DynDumpWrapper<'a, D: Dump + ?Sized>(&'a mut D);

pub struct LogDumper<W: std::io::Write> {
    writer: W,
    depth: usize,
    count: u64,
    err: Option<std::io::Error>,
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

    fn add_field(
        &mut self,
        name: &str,
        value: DumpValue<'_>,
        descr: Option<&str>,
    ) -> Result<(), Self::Error> {
        D::add_field(*self, name, value, descr)
    }

    fn add_info(&mut self, name: &str, descr: &str) -> Result<(), Self::Error> {
        D::add_info(*self, name, descr)
    }

    fn start_list(&mut self, name: &str, descr: Option<&str>) -> Result<(), Self::Error> {
        D::start_list(*self, name, descr)
    }

    fn end_list(&mut self) {
        D::end_list(*self)
    }

    fn add_list_item(
        &mut self,
        value: DumpValue<'_>,
        descr: Option<&str>,
    ) -> Result<(), Self::Error> {
        D::add_list_item(*self, value, descr)
    }

    fn start_list_node(&mut self, descr: Option<&str>) -> Result<(), Self::Error> {
        D::start_list_node(*self, descr)
    }

    fn end_list_node(&mut self) {
        D::end_list_node(*self)
    }

    fn start_list_sublist(&mut self, descr: Option<&str>) -> Result<(), Self::Error> {
        D::start_list_sublist(*self, descr)
    }

    fn end_list_sublist(&mut self) {
        D::end_list_sublist(*self)
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

    fn add_field(
        &mut self,
        name: &str,
        value: DumpValue<'_>,
        descr: Option<&str>,
    ) -> Result<(), Self::Error> {
        self.0.add_field(name, value, descr).map_err(to_boxed_any)
    }

    fn add_info(&mut self, name: &str, descr: &str) -> Result<(), Self::Error> {
        self.0.add_info(name, descr).map_err(to_boxed_any)
    }

    fn start_list(&mut self, name: &str, descr: Option<&str>) -> Result<(), Self::Error> {
        self.0.start_list(name, descr).map_err(to_boxed_any)
    }

    fn end_list(&mut self) {
        self.0.end_list()
    }

    fn add_list_item(
        &mut self,
        value: DumpValue<'_>,
        descr: Option<&str>,
    ) -> Result<(), Self::Error> {
        self.0.add_list_item(value, descr).map_err(to_boxed_any)
    }

    fn start_list_node(&mut self, descr: Option<&str>) -> Result<(), Self::Error> {
        self.0.start_list_node(descr).map_err(to_boxed_any)
    }

    fn end_list_node(&mut self) {
        self.0.end_list_node()
    }

    fn start_list_sublist(&mut self, descr: Option<&str>) -> Result<(), Self::Error> {
        self.0.start_list_sublist(descr).map_err(to_boxed_any)
    }

    fn end_list_sublist(&mut self) {
        self.0.end_list_sublist()
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
        Ok(NodeDumper(&mut self.0, NodeKind::Packet))
    }
}

impl<'a, D: Dump + ?Sized> NodeDumper<'a, D> {
    pub fn add_node<'b>(
        &'b mut self,
        name: &str,
        descr: Option<&str>,
    ) -> Result<NodeDumper<'b, D>, D::Error> {
        self.0.start_node(name, descr)?;
        Ok(NodeDumper(self.0, NodeKind::SubNode))
    }

    pub fn add_field(
        &mut self,
        name: &str,
        value: DumpValue<'_>,
        descr: Option<&str>,
    ) -> Result<(), D::Error> {
        self.0.add_field(name, value, descr)
    }

    pub fn add_info(&mut self, name: &str, descr: &str) -> Result<(), D::Error> {
        self.0.add_info(name, descr)
    }

    pub fn add_list<'b>(
        &'b mut self,
        name: &str,
        descr: Option<&str>,
    ) -> Result<ListDumper<'b, D>, D::Error> {
        self.0.start_list(name, descr)?;
        Ok(ListDumper(self.0, ListKind::List))
    }

    pub(crate) fn as_dyn_dumper<F>(&mut self, f: F) -> Result<(), D::Error>
    where
        F: for<'b, 'c> Fn(
            &mut NodeDumper<'b, dyn Dump<Error = Box<dyn Any + 'static>> + 'c>,
        ) -> Result<(), Box<dyn Any + 'static>>,
    {
        let mut wrapper = DynDumpWrapper(self.0);
        let dyn_dumper: &mut dyn Dump<Error = Box<dyn Any + 'static>> = &mut wrapper;
        let mut dumper = NodeDumper(dyn_dumper, NodeKind::Virtual);
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
        match self.1 {
            NodeKind::Packet => {
                self.0.end_packet();
            }
            NodeKind::SubNode => {
                self.0.end_node();
            }
            NodeKind::ListNode => {
                self.0.end_list_node();
            }
            _ => {}
        }
    }
}

impl<'a, D: Dump + ?Sized> ListDumper<'a, D> {
    pub fn add_item(&mut self, value: DumpValue<'_>, descr: Option<&str>) -> Result<(), D::Error> {
        self.0.add_list_item(value, descr)
    }

    pub fn add_node<'b>(&'b mut self, descr: Option<&str>) -> Result<NodeDumper<'b, D>, D::Error> {
        self.0.start_list_node(descr)?;
        Ok(NodeDumper(self.0, NodeKind::ListNode))
    }

    pub fn add_list<'b>(&'b mut self, descr: Option<&str>) -> Result<ListDumper<'b, D>, D::Error> {
        self.0.start_list_sublist(descr)?;
        Ok(ListDumper(self.0, ListKind::SubList))
    }
}

impl<'a, D: Dump + ?Sized> Drop for ListDumper<'a, D> {
    fn drop(&mut self) {
        match self.1 {
            ListKind::List => {
                self.0.end_list();
            }
            ListKind::SubList => {
                self.0.end_list_sublist();
            }
        }
    }
}

impl<'a> std::fmt::Display for DumpValue<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use DumpValue::*;
        match self {
            Bool(val) => write!(f, "{}", val),
            Int(val) => write!(f, "{}", val),
            UInt(val) => write!(f, "{}", val),
            Float(val) => write!(f, "{}", val),
            Text(val) => write!(f, "{}", val),
            Bytes(val) => {
                for byte in val.iter() {
                    write!(f, "{:02X}", byte)?;
                }
                Ok(())
            }
            Time(val) => {
                let ts: DateTime<Utc> = (*val).into();
                write!(f, "{}", ts.format("%Y-%m-%d %H:%M:%S%.f"))
            }
            Duration(val) => {
                let secs = val.as_secs();
                let nanos = val.subsec_nanos();
                if nanos == 0 {
                    write!(f, "{}s", secs)
                } else if nanos % 100_000_000 == 0 {
                    write!(f, "{}.{:01}s", secs, nanos / 100_000_000)
                } else if nanos % 10_000_000 == 0 {
                    write!(f, "{}.{:02}s", secs, nanos / 10_000_000)
                } else if nanos % 1_000_000 == 0 {
                    write!(f, "{}.{:03}s", secs, nanos / 1_000_000)
                } else if nanos % 100_000 == 0 {
                    write!(f, "{}.{:04}s", secs, nanos / 100_000)
                } else if nanos % 10_000 == 0 {
                    write!(f, "{}.{:05}s", secs, nanos / 10_000)
                } else if nanos % 1_000 == 0 {
                    write!(f, "{}.{:06}s", secs, nanos / 1_000)
                } else if nanos % 100 == 0 {
                    write!(f, "{}.{:07}s", secs, nanos / 100)
                } else if nanos % 10 == 0 {
                    write!(f, "{}.{:08}s", secs, nanos / 10)
                } else {
                    write!(f, "{}.{:09}s", secs, nanos)
                }
            }
        }
    }
}

impl<W: std::io::Write> LogDumper<W> {
    pub fn new(writer: W) -> Dumper<Self> {
        Dumper::new(Self {
            writer,
            depth: 0,
            count: 0,
            err: None,
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

    fn check_err(&mut self) -> std::io::Result<()> {
        if let Some(e) = std::mem::replace(&mut self.err, None) {
            Err(e)
        } else {
            Ok(())
        }
    }
}

impl<W: std::io::Write> Dump for LogDumper<W> {
    type Error = std::io::Error;

    fn start_packet(&mut self) -> Result<(), Self::Error> {
        self.check_err()?;
        self.depth += 1;
        self.count += 1;
        writeln!(self.writer, "Packet {}", self.count)
    }

    fn end_packet(&mut self) {
        if self.err.is_none() {
            self.depth -= 1;
        }
    }

    fn start_node(&mut self, name: &str, descr: Option<&str>) -> Result<(), Self::Error> {
        self.check_err()?;
        self.indent()?;
        self.depth += 1;
        match descr {
            Some(descr) => writeln!(self.writer, "{}: {}", name, descr),
            None => writeln!(self.writer, "{}", name),
        }
    }

    fn end_node(&mut self) {
        if self.err.is_none() {
            self.depth -= 1;
        }
    }

    fn add_field(
        &mut self,
        name: &str,
        value: DumpValue<'_>,
        descr: Option<&str>,
    ) -> Result<(), Self::Error> {
        self.check_err()?;
        self.indent()?;
        if let Some(descr) = descr {
            writeln!(self.writer, "{}: {}", name, descr)
        } else {
            writeln!(self.writer, "{}: {}", name, value)
        }
    }

    fn add_info(&mut self, name: &str, descr: &str) -> Result<(), Self::Error> {
        self.check_err()?;
        self.indent()?;
        writeln!(self.writer, "{}: {}", name, descr)
    }

    fn start_list(&mut self, name: &str, descr: Option<&str>) -> Result<(), Self::Error> {
        self.check_err()?;
        self.indent()?;
        self.depth += 1;
        if let Some(descr) = descr {
            writeln!(self.writer, "{}: {} => [", name, descr)
        } else {
            writeln!(self.writer, "{}: [", name)
        }
    }

    fn end_list(&mut self) {
        if self.err.is_none() {
            if let Err(e) = self.indent() {
                self.err = Some(e);
                return;
            }
            if let Err(e) = write!(self.writer, "]") {
                self.err = Some(e);
            }
            self.depth -= 1;
        }
    }

    fn add_list_item(
        &mut self,
        value: DumpValue<'_>,
        descr: Option<&str>,
    ) -> Result<(), Self::Error> {
        self.check_err()?;
        self.indent()?;
        if let Some(descr) = descr {
            writeln!(self.writer, "{}", descr)
        } else {
            writeln!(self.writer, "{}", value)
        }
    }

    fn start_list_node(&mut self, descr: Option<&str>) -> Result<(), Self::Error> {
        self.check_err()?;
        self.indent()?;
        self.depth += 1;
        if let Some(descr) = descr {
            writeln!(self.writer, "{}", descr)
        } else {
            writeln!(self.writer, "=>")
        }
    }

    fn end_list_node(&mut self) {
        if self.err.is_none() {
            self.depth -= 1;
        }
    }

    fn start_list_sublist(&mut self, descr: Option<&str>) -> Result<(), Self::Error> {
        self.check_err()?;
        self.indent()?;
        self.depth += 1;
        if let Some(descr) = descr {
            writeln!(self.writer, "{} => [", descr)
        } else {
            writeln!(self.writer, "[")
        }
    }

    fn end_list_sublist(&mut self) {
        self.end_list()
    }
}
