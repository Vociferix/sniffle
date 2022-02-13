use super::{AnyPDU, Dissector, DissectorTable, Priority, RawPDU, TempPDU};
use lazy_static::*;
use sniffle_ende::decode::DecodeError;
use sniffle_ende::nom::IResult;
use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::RwLock,
};

pub struct Session {
    state: HashMap<TypeId, Box<dyn Any + 'static>>,
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
    ) -> IResult<&'a [u8], Option<AnyPDU>, DecodeError<'a>> {
        self.get::<T>()
            .map(|table| table.dissect(param, buffer, self, parent))
            .unwrap_or(Ok((buffer, None)))
    }

    pub fn table_dissect_or_raw<'a, T: 'static + DissectorTable>(
        &self,
        param: &T::Param,
        buffer: &'a [u8],
        parent: Option<&mut TempPDU<'_>>,
    ) -> IResult<&'a [u8], AnyPDU, DecodeError<'a>> {
        self.get::<T>()
            .map(|table| table.dissect_or_raw(param, buffer, self, parent))
            .unwrap_or_else(|| {
                Ok((
                    &buffer[buffer.len()..],
                    AnyPDU::new(RawPDU::new(Vec::from(buffer))),
                ))
            })
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
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
                    session.load_dissector::<$table>($param, $pri, $dissector);
                });
            }
        });
    };
}
