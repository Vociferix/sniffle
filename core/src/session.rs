use super::{
    AnyPDU, BasePDU, Device, Dissector, DissectorTable, Dump, NodeDumper, PDUExt, Priority, RawPDU,
    TempPDU, PDU,
};
use lazy_static::*;
use sniffle_ende::decode::DResult;
use sniffle_ende::encode::Encoder;
use std::{
    any::{Any, TypeId},
    cell::Cell,
    collections::{HashMap, VecDeque},
    rc::Rc,
    sync::RwLock,
};

pub(crate) struct LastInfo {
    pub(crate) ts: std::time::SystemTime,
    pub(crate) dev: Option<Rc<Device>>,
    pub(crate) snaplen: usize,
}

pub struct Session {
    state: HashMap<TypeId, Box<dyn Any + 'static>>,
    virt_packets: Cell<VecDeque<Virtual>>,
    last_info: LastInfo,
}

pub struct Virtual {
    base: BasePDU,
}

impl Default for LastInfo {
    fn default() -> Self {
        Self {
            ts: std::time::SystemTime::UNIX_EPOCH,
            dev: None,
            snaplen: 0xFFFF,
        }
    }
}

impl Session {
    /// Constructs a new, completely empty, Session.
    /// This function does not load any registered tables or dissectors.
    /// This function should be used when creating a custom Session
    /// configuration with manually installed dissector tables and
    /// dissectors.
    pub fn new_from_scratch() -> Self {
        Self {
            state: HashMap::new(),
            virt_packets: Cell::new(VecDeque::new()),
            last_info: LastInfo::default(),
        }
    }

    /// Constructs a new Session, with only dissector tables loaded.
    /// This function does not load any dissectors, only dissector
    /// tables. This function is a convenient alternative to
    /// Session::new_from_scatch(), when the default dissector tables
    /// are desired, but the user wants to customize what dissectors
    /// are loaded.
    pub fn new_with_tables_only() -> Self {
        let mut session = Self::new_from_scratch();
        for setup in TABLE_SETUP.read().unwrap().iter() {
            setup(&mut session);
        }
        session
    }

    /// Constructs a new Session, with all registered dissectors and tables loaded.
    pub fn new() -> Self {
        let mut session = Self::new_with_tables_only();
        for setup in DISSECT_SETUP.read().unwrap().iter() {
            setup(&mut session);
        }
        session
    }

    pub fn register<S: Any>(&mut self, state: S) {
        let _ = self
            .state
            .insert(TypeId::of::<S>(), Box::new(state))
            .map(|_| {
                panic!("Multiple instances of the same type cannot be registered in a Session")
            });
    }

    pub fn get<S: Any>(&self) -> Option<&S> {
        match self.state.get(&TypeId::of::<S>()) {
            Some(s) => s.downcast_ref(),
            None => None,
        }
    }

    pub fn get_mut<S: Any>(&mut self) -> Option<&mut S> {
        match self.state.get_mut(&TypeId::of::<S>()) {
            Some(s) => s.downcast_mut(),
            None => None,
        }
    }

    pub fn load_dissector<T: 'static + DissectorTable, D: 'static + Dissector>(
        &mut self,
        param: T::Param,
        priority: Priority,
        dissector: D,
    ) {
        self.get_mut::<T>()
            .map(|table| table.load(param, priority, dissector))
            .expect("Requested dissector table is not loaded");
    }

    pub fn table_dissect<'a, T: 'static + DissectorTable>(
        &self,
        param: &T::Param,
        buffer: &'a [u8],
        parent: Option<&mut TempPDU<'_>>,
    ) -> DResult<'a, Option<AnyPDU>> {
        self.get::<T>()
            .map(|table| table.dissect(param, buffer, self, parent))
            .unwrap_or(Ok((buffer, None)))
    }

    pub fn table_dissect_or_raw<'a, T: 'static + DissectorTable>(
        &self,
        param: &T::Param,
        buffer: &'a [u8],
        parent: Option<&mut TempPDU<'_>>,
    ) -> DResult<'a, AnyPDU> {
        self.get::<T>()
            .map(|table| table.dissect_or_raw(param, buffer, self, parent))
            .unwrap_or_else(|| {
                Ok((
                    &buffer[buffer.len()..],
                    AnyPDU::new(RawPDU::new(Vec::from(buffer))),
                ))
            })
    }

    pub fn enqueue_virtual_packet<P: PDU>(&self, packet: P) {
        let mut queue = self.virt_packets.take();
        let mut virt = Virtual {
            base: Default::default(),
        };
        virt.set_inner_pdu(packet);
        queue.push_back(virt);
        self.virt_packets.set(queue);
    }

    pub fn next_virtual_packet(&self) -> Option<Virtual> {
        let mut queue = self.virt_packets.take();
        let ret = queue.pop_front();
        self.virt_packets.set(queue);
        ret
    }

    pub(crate) fn last_info(&self) -> &LastInfo {
        &self.last_info
    }

    pub(crate) fn last_info_mut(&mut self) -> &mut LastInfo {
        &mut self.last_info
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl PDU for Virtual {
    fn base_pdu(&self) -> &BasePDU {
        &self.base
    }

    fn base_pdu_mut(&mut self) -> &mut BasePDU {
        &mut self.base
    }

    fn header_len(&self) -> usize {
        0
    }

    fn total_len(&self) -> usize {
        self.inner_pdu().map(|inner| inner.total_len()).unwrap_or(0)
    }

    fn serialize_header<'a, W: Encoder<'a> + ?Sized>(
        &self,
        _encoder: &mut W,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn serialize<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> std::io::Result<()> {
        if let Some(inner) = self.inner_pdu() {
            inner.serialize(encoder)?;
        }
        Ok(())
    }

    fn dump<D: Dump + ?Sized>(&self, _dumper: &mut NodeDumper<D>) -> Result<(), D::Error> {
        Ok(())
    }
}

impl Clone for Virtual {
    fn clone(&self) -> Self {
        Self {
            base: Default::default(),
        }
    }
}

lazy_static! {
    static ref TABLE_SETUP: RwLock<Vec<fn(&mut Session)>> = RwLock::new(Vec::new());
    static ref DISSECT_SETUP: RwLock<Vec<fn(&mut Session)>> = RwLock::new(Vec::new());
}

pub fn _register_dissector(cb: fn(&mut Session)) {
    DISSECT_SETUP.write().unwrap().push(cb);
}

pub fn _register_dissector_table(cb: fn(&mut Session)) {
    TABLE_SETUP.write().unwrap().push(cb);
}

/// Adds a dissector table to be loaded into the default state of a `Session`.
/// This should only be used if it makes sense for the table to be pre-loaded
/// into every `Session` instance constructed with `Session::new()` or
/// `Session::default()`.
#[macro_export]
macro_rules! register_dissector_table {
    ($table:ty) => {
        $crate::concat_idents::concat_idents!(reg_name = __sniffle_registry_, $table {
            #[$crate::ctor::ctor]
            #[allow(non_snake_case)]
            fn reg_name() {
                $crate::_register_dissector_table(|session| {
                    session.register($table::new());
                });
            }
        });
    };
}

/// Adds a dissector to be loaded into the default state of a `Session`.
/// This should only be used if it makes sense for the dissector to be
/// pre-loaded into every `Session` instance constructed with
/// `Session::new()` or `Session::default()`.
#[macro_export]
macro_rules! register_dissector {
    ($name:ident, $table:ty, $param:expr, $pri:expr, $dissector:expr) => {
        $crate::concat_idents::concat_idents!(reg_name = __sniffle_registry_, $table, _, $name {
            #[$crate::ctor::ctor]
            #[allow(non_snake_case)]
            fn reg_name() {
                $crate::_register_dissector(|session| {
                    session.load_dissector::<$table, _>($param, $pri, $dissector);
                });
            }
        });
    };
}
