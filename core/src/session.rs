use super::{
    AnyPdu, BasePdu, DResult, Device, Dissector, DissectorTable, DissectorTableParser, Dump,
    NodeDumper, Pdu, PduExt, Priority, RawPdu, TempPdu,
};
use lazy_static::*;
use sniffle_ende::decode::Decode;
use sniffle_ende::encode::Encoder;
use sniffle_ende::nom::{combinator::map, Parser};
use std::{
    any::{Any, TypeId},
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock};

pub(crate) struct LastInfo {
    pub(crate) ts: std::time::SystemTime,
    pub(crate) dev: Option<Arc<Device>>,
    pub(crate) snaplen: usize,
}

pub struct Session {
    state: HashMap<TypeId, Box<dyn Any + Send + Sync + 'static>>,
    virt_packets: Mutex<VecDeque<Virtual>>,
    last_info: RwLock<LastInfo>,
}

#[derive(Debug)]
pub struct Virtual {
    base: BasePdu,
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
            virt_packets: Mutex::new(VecDeque::new()),
            last_info: RwLock::new(LastInfo::default()),
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
        for setup in TABLE_SETUP.read().iter() {
            setup(&mut session);
        }
        session
    }

    /// Constructs a new Session, with all registered dissectors and tables loaded.
    pub fn new() -> Self {
        let mut session = Self::new_with_tables_only();
        for setup in DISSECT_SETUP.read().iter() {
            setup(&mut session);
        }
        session
    }

    pub fn register<S: Any + Send + Sync + 'static>(&mut self, state: S) {
        let _ = self
            .state
            .insert(TypeId::of::<S>(), Box::new(state))
            .map(|_| {
                panic!("Multiple instances of the same type cannot be registered in a Session")
            });
    }

    pub fn get<S: Any + Send + Sync + 'static>(&self) -> Option<&S> {
        match self.state.get(&TypeId::of::<S>()) {
            Some(s) => s.downcast_ref(),
            None => None,
        }
    }

    pub fn get_mut<S: Any + Send + Sync + 'static>(&mut self) -> Option<&mut S> {
        match self.state.get_mut(&TypeId::of::<S>()) {
            Some(s) => s.downcast_mut(),
            None => None,
        }
    }

    pub fn load_dissector<
        T: DissectorTable + Send + Sync + 'static,
        D: Dissector + Send + Sync + 'static,
    >(
        &mut self,
        param: T::Param,
        priority: Priority,
        dissector: D,
    ) {
        self.get_mut::<T>()
            .map(|table| table.load(param, priority, dissector))
            .expect("Requested dissector table is not loaded");
    }

    pub fn table_dissector<'a, T: DissectorTable + Send + Sync + 'static>(
        &'a self,
        param: &'a T::Param,
        parent: Option<TempPdu<'a>>,
    ) -> DissectorTableParser<'a, T> {
        match self.get::<T>() {
            Some(table) => table.dissector(param, self, parent),
            None => DissectorTableParser::null_parser(param, self, parent),
        }
    }

    pub fn table_dissect<'a, T: DissectorTable + Send + Sync + 'static>(
        &self,
        param: &T::Param,
        buffer: &'a [u8],
        parent: Option<TempPdu<'_>>,
    ) -> DResult<'a, AnyPdu> {
        self.table_dissector::<T>(param, parent).parse(buffer)
    }

    pub fn table_dissect_or_raw<'a, T: DissectorTable + Send + Sync + 'static>(
        &self,
        param: &T::Param,
        buffer: &'a [u8],
        parent: Option<TempPdu<'_>>,
    ) -> DResult<'a, AnyPdu> {
        self.table_dissector::<T>(param, parent)
            .or(map(RawPdu::decode, AnyPdu::new))
            .parse(buffer)
    }

    pub async fn enqueue_virtual_packet<P: Pdu + Send + Sync + 'static>(&self, packet: P) {
        let mut virt = Virtual {
            base: Default::default(),
        };
        virt.set_inner_pdu(packet);
        self.virt_packets.lock().await.push_back(virt);
    }

    pub async fn next_virtual_packet(&self) -> Option<Virtual> {
        self.virt_packets.lock().await.pop_front()
    }

    pub(crate) async fn last_info<R, F: FnOnce(&LastInfo) -> R>(&self, f: F) -> R {
        let guard = self.last_info.read().await;
        f(&*guard)
    }

    pub(crate) async fn last_info_mut<R, F: FnOnce(&mut LastInfo) -> R>(&self, f: F) -> R {
        let mut guard = self.last_info.write().await;
        f(&mut *guard)
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Pdu for Virtual {
    fn base_pdu(&self) -> &BasePdu {
        &self.base
    }

    fn base_pdu_mut(&mut self) -> &mut BasePdu {
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
    static ref TABLE_SETUP: parking_lot::RwLock<Vec<fn(&mut Session)>> =
        parking_lot::RwLock::new(Vec::new());
    static ref DISSECT_SETUP: parking_lot::RwLock<Vec<fn(&mut Session)>> =
        parking_lot::RwLock::new(Vec::new());
}

pub fn _register_dissector(cb: fn(&mut Session)) {
    DISSECT_SETUP.write().push(cb);
}

pub fn _register_dissector_table(cb: fn(&mut Session)) {
    TABLE_SETUP.write().push(cb);
}

/// Adds a dissector table to be loaded into the default state of a `Session`.
/// This should only be used if it makes sense for the table to be pre-loaded
/// into every `Session` instance constructed with `Session::new()` or
/// `Session::default()`.
#[macro_export]
macro_rules! register_dissector_table {
    ($table:ty) => {
        $crate::paste::paste! {
            #[$crate::ctor::ctor]
            #[allow(non_snake_case)]
            fn [<__sniffle_registry_ $table>]() {
                $crate::_register_dissector_table(|session| {
                    session.register($table::new());
                });
            }
        }
    };
}

/// Adds a dissector to be loaded into the default state of a `Session`.
/// This should only be used if it makes sense for the dissector to be
/// pre-loaded into every `Session` instance constructed with
/// `Session::new()` or `Session::default()`.
#[macro_export]
macro_rules! register_dissector {
    ($name:ident, $table:ty, $param:expr, $pri:expr, $dissector:expr) => {
        $crate::paste::paste! {
            #[$crate::ctor::ctor]
            #[allow(non_snake_case)]
            fn [<__sniffle_registry_ $table _ $name>]() {
                $crate::_register_dissector(|session| {
                    session.load_dissector::<$table, _>($param, $pri, $dissector);
                });
            }
        }
    };
}
