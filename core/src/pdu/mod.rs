use super::{Dump, NodeDumper};
use sniffle_ende::encode::Encoder;
use std::any::Any;

mod any_pdu;
mod temp_pdu;

pub use any_pdu::AnyPDU;
pub(self) use any_pdu::DynPDU;
pub use temp_pdu::TempPDU;

pub type PDUType = std::any::TypeId;

#[derive(Default)]
pub struct BasePDU {
    parent: Option<AnyPDU>,
    inner: Option<AnyPDU>,
}

pub trait PDU: 'static + Any + Clone + std::fmt::Debug + Send + Sync {
    fn base_pdu(&self) -> &BasePDU;
    fn base_pdu_mut(&mut self) -> &mut BasePDU;

    #[doc(hidden)]
    unsafe fn unsafe_pdu_type(&self) -> PDUType {
        self.type_id()
    }

    fn header_len(&self) -> usize;

    fn trailer_len(&self) -> usize {
        0
    }

    fn total_len(&self) -> usize {
        self.header_len()
            + match self.base_pdu().inner {
                Some(ref pdu) => pdu.total_len(),
                None => 0,
            }
            + self.trailer_len()
    }

    fn serialize_header<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W)
        -> std::io::Result<()>;

    fn serialize_trailer<'a, W: Encoder<'a> + ?Sized>(
        &self,
        _encoder: &mut W,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn serialize<'a, W: Encoder<'a> + ?Sized>(&self, encoder: &mut W) -> std::io::Result<()> {
        self.serialize_header(encoder)?;
        self.base_pdu()
            .inner
            .as_ref()
            .map(|inner| inner.serialize(encoder))
            .unwrap_or(Ok(()))?;
        self.serialize_trailer(encoder)
    }

    fn dump<D: Dump + ?Sized>(&self, dumper: &mut NodeDumper<'_, D>) -> Result<(), D::Error>;

    /// Modifies the PDU to make the packet valid.
    /// This function should perform operations like updating checksums and
    /// other operations to conform to protocol standards.
    fn make_canonical(&mut self) {}

    #[doc(hidden)]
    unsafe fn unsafe_into_any_pdu(self) -> AnyPDU {
        AnyPDU {
            pdu: Box::new(self),
        }
    }

    #[doc(hidden)]
    unsafe fn unsafe_downcast<P: PDU>(self) -> Result<P, Self> {
        let is_type = self.is::<P>();
        if is_type {
            let mut s = self;
            let pdu = std::ptr::read(std::mem::transmute::<&mut Self, &mut P>(&mut s));
            std::mem::forget(s);
            Ok(pdu)
        } else {
            Err(self)
        }
    }

    #[doc(hidden)]
    unsafe fn unsafe_downcast_ref<P: PDU>(&self) -> Option<&P> {
        if self.is::<P>() {
            Some(std::mem::transmute::<&Self, &P>(self))
        } else {
            None
        }
    }

    #[doc(hidden)]
    unsafe fn unsafe_downcast_mut<P: PDU>(&mut self) -> Option<&mut P> {
        let is_type = self.is::<P>();
        if is_type {
            Some(std::mem::transmute::<&mut Self, &mut P>(self))
        } else {
            None
        }
    }
}

pub trait PDUExt: PDU {
    fn pdu_type(&self) -> PDUType {
        unsafe { self.unsafe_pdu_type() }
    }

    fn is<P: PDU>(&self) -> bool {
        self.pdu_type() == PDUType::of::<P>()
    }

    fn parent_pdu(&self) -> Option<&AnyPDU> {
        self.base_pdu().parent.as_ref()
    }

    fn inner_pdu(&self) -> Option<&AnyPDU> {
        self.base_pdu().inner.as_ref()
    }

    fn inner_pdu_mut(&mut self) -> Option<&mut AnyPDU> {
        self.base_pdu_mut().inner.as_mut()
    }

    fn replace_inner_pdu<P: PDU>(&mut self, new_inner: Option<P>) -> Option<AnyPDU> {
        let parent = unsafe { fake_any_pdu(self) };
        std::mem::replace(
            &mut self.base_pdu_mut().inner,
            new_inner.map(move |mut pdu| {
                pdu.base_pdu_mut().parent = Some(parent);
                PDUExt::into_any_pdu(pdu)
            }),
        )
    }

    fn take_inner_pdu(&mut self) -> Option<AnyPDU> {
        std::mem::replace(&mut self.base_pdu_mut().inner, None).map(|mut pdu| {
            if let Some(pdu) = std::mem::replace(&mut pdu.base_pdu_mut().parent, None) {
                let _ = Box::into_raw(pdu.pdu);
            }
            pdu
        })
    }

    fn set_inner_pdu<P: PDU>(&mut self, pdu: P) {
        let mut pdu = pdu;
        pdu.base_pdu_mut().parent = Some(unsafe { fake_any_pdu(self) });
        self.base_pdu_mut().inner = Some(PDUExt::into_any_pdu(pdu));
    }

    fn find<P: PDU>(&self) -> Option<&P> {
        match self.downcast_ref::<P>() {
            Some(pdu) => Some(pdu),
            None => match self.inner_pdu() {
                Some(pdu) => pdu.find::<P>(),
                None => None,
            },
        }
    }

    fn find_mut<P: PDU>(&mut self) -> Option<&mut P> {
        let is_type = self.is::<P>();
        if is_type {
            self.downcast_mut::<P>()
        } else {
            match self.inner_pdu_mut() {
                Some(pdu) => pdu.find_mut::<P>(),
                None => None,
            }
        }
    }

    fn into_any_pdu(self) -> AnyPDU {
        unsafe { self.unsafe_into_any_pdu() }
    }

    fn downcast<P: PDU>(self) -> Result<P, Self> {
        unsafe { self.unsafe_downcast::<P>() }
    }

    fn downcast_ref<P: PDU>(&self) -> Option<&P> {
        unsafe { self.unsafe_downcast_ref::<P>() }
    }

    fn downcast_mut<P: PDU>(&mut self) -> Option<&mut P> {
        unsafe { self.unsafe_downcast_mut::<P>() }
    }

    fn make_all_canonical(&mut self) {
        self.make_canonical();
        if let Some(inner) = self.inner_pdu_mut() {
            inner.make_all_canonical();
        }
    }
}

impl<P: PDU> PDUExt for P {}

impl Drop for BasePDU {
    fn drop(&mut self) {
        if let Some(pdu) = std::mem::replace(&mut self.parent, None) {
            let _ = Box::into_raw(pdu.pdu);
        }
        let _ = std::mem::replace(&mut self.inner, None);
    }
}

impl std::fmt::Debug for BasePDU {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasePDU")
            .field("inner", &self.inner)
            .finish()
    }
}

impl Clone for BasePDU {
    fn clone(&self) -> Self {
        BasePDU {
            parent: None,
            inner: self.inner.clone(),
        }
    }
}

pub(self) unsafe fn fake_any_pdu<P: PDU>(pdu: &mut P) -> AnyPDU {
    AnyPDU {
        pdu: Box::from_raw(pdu as *mut P as *mut (dyn DynPDU + Send + Sync)),
    }
}
