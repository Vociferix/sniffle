use super::{
    super::{Dump, NodeDumper},
    BasePdu, Pdu, PduExt, PduType,
};
use sniffle_ende::encode::{DynEncoder, Encoder};
use std::any::Any;
use std::convert::AsRef;

pub struct AnyPdu {
    pub(super) pdu: Box<dyn DynPdu + Send + Sync + 'static>,
}

pub trait DynPdu: std::fmt::Debug {
    fn dyn_base_pdu(&self) -> &BasePdu;
    fn dyn_base_pdu_mut(&mut self) -> &mut BasePdu;
    fn dyn_pdu_type(&self) -> PduType;
    fn dyn_header_len(&self) -> usize;
    fn dyn_trailer_len(&self) -> usize;
    fn dyn_total_len(&self) -> usize;
    fn dyn_make_canonical(&mut self);
    fn dyn_serialize_header(&self, encoder: &mut DynEncoder<'_>) -> std::io::Result<()>;
    fn dyn_serialize_trailer(&self, encoder: &mut DynEncoder<'_>) -> std::io::Result<()>;
    fn dyn_serialize(&self, encoder: &mut DynEncoder<'_>) -> std::io::Result<()>;
    fn dyn_dump(
        &self,
        dumper: &mut NodeDumper<'_, dyn Dump<Error = Box<dyn Any + Send + Sync + 'static>> + '_>,
    ) -> Result<(), Box<dyn Any + Send + Sync + 'static>>;
    fn dyn_debug(&self) -> &(dyn std::fmt::Debug + Send + Sync + 'static);
    fn dyn_clone(&self) -> Box<dyn DynPdu + Send + Sync + 'static>;
}

impl<P: Pdu> DynPdu for P {
    fn dyn_base_pdu(&self) -> &BasePdu {
        self.base_pdu()
    }

    fn dyn_base_pdu_mut(&mut self) -> &mut BasePdu {
        self.base_pdu_mut()
    }

    fn dyn_pdu_type(&self) -> PduType {
        self.pdu_type()
    }

    fn dyn_header_len(&self) -> usize {
        self.header_len()
    }

    fn dyn_trailer_len(&self) -> usize {
        self.trailer_len()
    }

    fn dyn_total_len(&self) -> usize {
        self.total_len()
    }

    fn dyn_make_canonical(&mut self) {
        self.make_canonical();
    }

    fn dyn_serialize_header(&self, encoder: &mut DynEncoder<'_>) -> std::io::Result<()> {
        self.serialize_header(encoder)
    }

    fn dyn_serialize_trailer(&self, encoder: &mut DynEncoder<'_>) -> std::io::Result<()> {
        self.serialize_trailer(encoder)
    }

    fn dyn_serialize(&self, encoder: &mut DynEncoder<'_>) -> std::io::Result<()> {
        self.serialize(encoder)
    }

    fn dyn_dump(
        &self,
        dumper: &mut NodeDumper<'_, dyn Dump<Error = Box<dyn Any + Send + Sync + 'static>> + '_>,
    ) -> Result<(), Box<dyn Any + Send + Sync + 'static>> {
        self.dump(dumper)
    }

    fn dyn_debug(&self) -> &(dyn std::fmt::Debug + Send + Sync + 'static) {
        self
    }

    fn dyn_clone(&self) -> Box<dyn DynPdu + Send + Sync + 'static> {
        Box::new(self.clone())
    }
}

impl Clone for AnyPdu {
    fn clone(&self) -> Self {
        Self {
            pdu: self.pdu.dyn_clone(),
        }
    }
}

impl Pdu for AnyPdu {
    fn base_pdu(&self) -> &BasePdu {
        self.pdu.dyn_base_pdu()
    }

    fn base_pdu_mut(&mut self) -> &mut BasePdu {
        self.pdu.dyn_base_pdu_mut()
    }

    unsafe fn unsafe_pdu_type(&self) -> PduType {
        self.pdu.dyn_pdu_type()
    }

    fn header_len(&self) -> usize {
        self.pdu.dyn_header_len()
    }

    fn trailer_len(&self) -> usize {
        self.pdu.dyn_trailer_len()
    }

    fn total_len(&self) -> usize {
        self.pdu.dyn_total_len()
    }

    fn make_canonical(&mut self) {
        self.pdu.dyn_make_canonical();
    }

    unsafe fn unsafe_into_any_pdu(self) -> AnyPdu {
        self
    }

    unsafe fn unsafe_downcast<P: Pdu>(self) -> Result<P, Self> {
        let is_type = self.is::<P>();
        if is_type {
            let ptr = Box::into_raw(self.pdu);
            Ok(*Box::from_raw(ptr as *mut P))
        } else {
            Err(self)
        }
    }

    unsafe fn unsafe_downcast_ref<P: Pdu>(&self) -> Option<&P> {
        if self.is::<P>() {
            let ptr = self.pdu.as_ref() as *const dyn DynPdu as *const P;
            Some(&*ptr)
        } else {
            None
        }
    }

    unsafe fn unsafe_downcast_mut<P: Pdu>(&mut self) -> Option<&mut P> {
        let is_type = self.is::<P>();
        if is_type {
            let ptr = self.pdu.as_mut() as *mut dyn DynPdu as *mut P;
            Some(&mut *ptr)
        } else {
            None
        }
    }

    fn serialize_header<'a, W: Encoder<'a> + ?Sized>(
        &self,
        encoder: &mut W,
    ) -> std::io::Result<()> {
        self.pdu.dyn_serialize_header(encoder.as_dyn_mut())
    }

    fn serialize_trailer<'a, W: Encoder<'a> + ?Sized>(
        &self,
        encoder: &mut W,
    ) -> std::io::Result<()> {
        self.pdu.dyn_serialize_trailer(encoder.as_dyn_mut())
    }

    fn serialize<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> std::io::Result<()> {
        self.pdu.dyn_serialize(encoder.as_dyn_mut())
    }

    fn dump<D: Dump + ?Sized>(&self, dumper: &mut NodeDumper<'_, D>) -> Result<(), D::Error> {
        dumper.as_dyn_dumper(|dumper| self.pdu.dyn_dump(dumper))
    }
}

impl AnyPdu {
    pub fn new<P: Pdu>(pdu: P) -> AnyPdu {
        PduExt::into_any_pdu(pdu)
    }
}

impl std::fmt::Debug for AnyPdu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AnyPdu").field(self.pdu.dyn_debug()).finish()
    }
}
