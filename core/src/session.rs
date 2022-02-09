use super::{AnyPDU, DissectError, Dissector, DissectorTable, Priority, RawPDU, TempPDU};
use lazy_static::*;
use sniffle_ende::nom::{self, IResult};
use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::RwLock,
};

pub struct Session {
    state: HashMap<TypeId, Box<dyn Any + 'static>>,
}

impl Session {
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
        }
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
    ) -> IResult<&'a [u8], AnyPDU, DissectError> {
        self.get::<T>()
            .map(|table| table.dissect(param, buffer, self, parent))
            .unwrap_or(Err(nom::Err::Error(DissectError::Malformed)))
    }

    pub fn table_dissect_or_raw<'a, T: 'static + DissectorTable>(
        &self,
        param: &T::Param,
        buffer: &'a [u8],
        parent: Option<&mut TempPDU<'_>>,
    ) -> IResult<&'a [u8], AnyPDU, DissectError> {
        self.get::<T>()
            .map(|table| table.dissect_or_raw(param, buffer, self, parent))
            .unwrap_or_else(|| {
                Ok((
                    &buffer[buffer.len()..],
                    AnyPDU::new(RawPDU::new(Vec::from(buffer))),
                ))
            })
    }

    pub fn empty_default() -> Self {
        let mut session = Self::new();
        for setup in STATE_SETUP.read().unwrap().iter() {
            setup(&mut session);
        }
        session
    }

    pub fn link_layer_default() -> Self {
        let mut session = Self::empty_default();
        for setup in LINK_SETUP.read().unwrap().iter() {
            setup(&mut session);
        }
        session
    }

    pub fn network_layer_default() -> Self {
        let mut session = Self::link_layer_default();
        for setup in NET_SETUP.read().unwrap().iter() {
            setup(&mut session);
        }
        session
    }

    pub fn transport_layer_default() -> Self {
        let mut session = Self::network_layer_default();
        for setup in TRANS_SETUP.read().unwrap().iter() {
            setup(&mut session);
        }
        session
    }

    pub fn full_default() -> Self {
        let mut session = Self::transport_layer_default();
        for setup in FULL_SETUP.read().unwrap().iter() {
            setup(&mut session);
        }
        session
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::full_default()
    }
}

lazy_static! {
    static ref STATE_SETUP: RwLock<Vec<fn(&mut Session)>> = RwLock::new(Vec::new());
    static ref LINK_SETUP: RwLock<Vec<fn(&mut Session)>> = RwLock::new(Vec::new());
    static ref NET_SETUP: RwLock<Vec<fn(&mut Session)>> = RwLock::new(Vec::new());
    static ref TRANS_SETUP: RwLock<Vec<fn(&mut Session)>> = RwLock::new(Vec::new());
    static ref FULL_SETUP: RwLock<Vec<fn(&mut Session)>> = RwLock::new(Vec::new());
}

pub fn _register_link_dissector(cb: fn(&mut Session)) {
    LINK_SETUP.write().unwrap().push(cb);
}

pub fn _register_network_dissector(cb: fn(&mut Session)) {
    NET_SETUP.write().unwrap().push(cb);
}

pub fn _register_transport_dissector(cb: fn(&mut Session)) {
    TRANS_SETUP.write().unwrap().push(cb);
}

pub fn _register_dissector(cb: fn(&mut Session)) {
    FULL_SETUP.write().unwrap().push(cb);
}

pub fn _register_session_state(cb: fn(&mut Session)) {
    STATE_SETUP.write().unwrap().push(cb);
}

#[macro_export]
macro_rules! register_dissector_table {
    ($table:ty) => {
        $crate::concat_idents::concat_idents!(reg_name = __sniffle_registry_, $table {
            #[$crate::ctor::ctor]
            #[allow(non_snake_case)]
            fn reg_name() {
                $crate::_register_session_state(|session| {
                    session.register($table::new());
                });
            }
        });
    };
}

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

#[macro_export]
macro_rules! register_link_layer_dissector {
    ($name:ident, $table:ty, $param:expr, $pri:expr, $dissector:expr) => {
        $crate::concat_idents::concat_idents!(reg_name = __sniffle_registry_, $table, _, $name {
            #[$crate::ctor::ctor]
            #[allow(non_snake_case)]
            fn reg_name() {
                $crate::_register_link_dissector(|session| {
                    session.load_dissector::<$table>($param, $pri, $dissector);
                });
            }
        });
    };
}

#[macro_export]
macro_rules! register_network_layer_dissector {
    ($name:ident, $table:ty, $param:expr, $pri:expr, $dissector:expr) => {
        $crate::concat_idents::concat_idents!(reg_name = __sniffle_registry_, $table, _, $name {
            #[$crate::ctor::ctor]
            #[allow(non_snake_case)]
            fn reg_name() {
                $crate::_register_network_dissector(|session| {
                    session.load_dissector::<$table>($param, $pri, $dissector);
                });
            }
        });
    };
}

#[macro_export]
macro_rules! register_transport_layer_dissector {
    ($name:ident, $table:ty, $param:expr, $pri:expr, $dissector:expr) => {
        $crate::concat_idents::concat_idents!(reg_name = __sniffle_registry_, $table, _, $name {
            #[$crate::ctor::ctor]
            #[allow(non_snake_case)]
            fn reg_name() {
                $crate::_register_transport_dissector(|session| {
                    session.load_dissector::<$table>($param, $pri, $dissector);
                });
            }
        });
    };
}
