use super::{dissector_table, register_dissector_table, Pdu, PduExt, PduType};
use lazy_static::*;
#[cfg(feature = "pcaprs")]
pub use pcaprs::ParseLinkTypeError;
use std::collections::HashMap;
#[cfg(feature = "pcaprs")]
use std::fmt;
#[cfg(feature = "pcaprs")]
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct LinkType(pub u16);

lazy_static! {
    static ref LINK_TYPE_PDUS: parking_lot::RwLock<HashMap<PduType, LinkType>> =
        parking_lot::RwLock::new(HashMap::new());
}

macro_rules! link_type {
    ($name:ident) => {
        pub const $name: LinkType = LinkType(link_types::LinkType::$name.0);
    };
}

#[cfg(feature = "pcaprs")]
impl FromStr for LinkType {
    type Err = ParseLinkTypeError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Ok(LinkType(pcaprs::LinkType::from_str(name)?.0))
    }
}

#[cfg(feature = "pcaprs")]
impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        pcaprs::LinkType(self.0).fmt(f)
    }
}

impl LinkType {
    #[cfg(feature = "pcaprs")]
    pub fn name(&self) -> Option<String> {
        pcaprs::LinkType(self.0).name()
    }

    #[cfg(feature = "pcaprs")]
    pub fn description(&self) -> Option<String> {
        pcaprs::LinkType(self.0).description()
    }

    #[cfg(feature = "pcaprs")]
    pub fn description_or_dlt(&self) -> String {
        pcaprs::LinkType(self.0).description_or_dlt()
    }

    pub fn of<P: Pdu>() -> Option<Self> {
        LINK_TYPE_PDUS.read().get(&PduType::of::<P>()).copied()
    }

    pub fn from_pdu<P: Pdu>(pdu: &P) -> Option<Self> {
        LINK_TYPE_PDUS.read().get(&pdu.pdu_type()).copied()
    }

    link_types::for_each_link_type!(link_type);
}

#[cfg(feature = "pcaprs")]
impl From<pcaprs::LinkType> for LinkType {
    fn from(lt: pcaprs::LinkType) -> Self {
        Self(lt.0)
    }
}

#[cfg(feature = "pcaprs")]
impl From<LinkType> for pcaprs::LinkType {
    fn from(lt: LinkType) -> Self {
        Self(lt.0)
    }
}

impl From<link_types::LinkType> for LinkType {
    fn from(lt: link_types::LinkType) -> Self {
        Self(lt.0)
    }
}

impl From<LinkType> for link_types::LinkType {
    fn from(lt: LinkType) -> Self {
        Self(lt.0)
    }
}

dissector_table!(pub LinkTypeTable, LinkType);
register_dissector_table!(LinkTypeTable);

pub fn _register_link_layer_pdu<P: Pdu>(link_type: LinkType) {
    if LINK_TYPE_PDUS
        .write()
        .insert(PduType::of::<P>(), link_type)
        .is_some()
    {
        panic!("A Pdu can only be registered for one link type");
    }
}

#[macro_export]
macro_rules! register_link_layer_pdu {
    ($pdu:ty, $link:expr) => {
        $crate::concat_idents::concat_idents!(reg_name = __sniffle_registry_link_layer_pdu_, $pdu {
            #[$crate::ctor::ctor]
            #[allow(non_snake_case)]
            fn reg_name() {
                $crate::_register_link_layer_pdu::<$pdu>($link);
            }
        });
    };
}
