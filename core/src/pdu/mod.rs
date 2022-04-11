use super::{Dump, NodeDumper};
use sniffle_ende::encode::Encoder;
use std::any::Any;

mod any_pdu;
mod temp_pdu;

pub use any_pdu::AnyPdu;
pub(self) use any_pdu::DynPdu;
pub use temp_pdu::TempPdu;

pub type PduType = std::any::TypeId;

#[derive(Default)]
pub struct BasePdu {
    parent: Option<AnyPdu>,
    inner: Option<AnyPdu>,
}

pub trait Pdu: 'static + Any + Clone + std::fmt::Debug + Send + Sync {
    fn base_pdu(&self) -> &BasePdu;
    fn base_pdu_mut(&mut self) -> &mut BasePdu;

    #[doc(hidden)]
    unsafe fn unsafe_pdu_type(&self) -> PduType {
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

    /// Modifies the Pdu to make the packet valid.
    /// This function should perform operations like updating checksums and
    /// other operations to conform to protocol standards.
    fn make_canonical(&mut self) {}

    #[doc(hidden)]
    unsafe fn unsafe_into_any_pdu(self) -> AnyPdu {
        AnyPdu {
            pdu: Box::new(self),
        }
    }

    #[doc(hidden)]
    unsafe fn unsafe_downcast<P: Pdu>(self) -> Result<P, Self> {
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
    unsafe fn unsafe_downcast_ref<P: Pdu>(&self) -> Option<&P> {
        if self.is::<P>() {
            Some(std::mem::transmute::<&Self, &P>(self))
        } else {
            None
        }
    }

    #[doc(hidden)]
    unsafe fn unsafe_downcast_mut<P: Pdu>(&mut self) -> Option<&mut P> {
        let is_type = self.is::<P>();
        if is_type {
            Some(std::mem::transmute::<&mut Self, &mut P>(self))
        } else {
            None
        }
    }
}

pub trait PduExt: Pdu {
    fn pdu_type(&self) -> PduType {
        unsafe { self.unsafe_pdu_type() }
    }

    fn is<P: Pdu>(&self) -> bool {
        self.pdu_type() == PduType::of::<P>()
    }

    fn parent_pdu(&self) -> Option<&AnyPdu> {
        self.base_pdu().parent.as_ref()
    }

    fn inner_pdu(&self) -> Option<&AnyPdu> {
        self.base_pdu().inner.as_ref()
    }

    fn inner_pdu_mut(&mut self) -> Option<&mut AnyPdu> {
        self.base_pdu_mut().inner.as_mut()
    }

    fn replace_inner_pdu<P: Pdu>(&mut self, new_inner: Option<P>) -> Option<AnyPdu> {
        let parent = unsafe { fake_any_pdu(self) };
        std::mem::replace(
            &mut self.base_pdu_mut().inner,
            new_inner.map(move |mut pdu| {
                pdu.base_pdu_mut().parent = Some(parent);
                PduExt::into_any_pdu(pdu)
            }),
        )
    }

    fn take_inner_pdu(&mut self) -> Option<AnyPdu> {
        std::mem::replace(&mut self.base_pdu_mut().inner, None).map(|mut pdu| {
            if let Some(pdu) = std::mem::replace(&mut pdu.base_pdu_mut().parent, None) {
                let _ = Box::into_raw(pdu.pdu);
            }
            pdu
        })
    }

    fn set_inner_pdu<P: Pdu>(&mut self, pdu: P) {
        let mut pdu = pdu;
        pdu.base_pdu_mut().parent = Some(unsafe { fake_any_pdu(self) });
        self.base_pdu_mut().inner = Some(PduExt::into_any_pdu(pdu));
    }

    fn find<P: Pdu>(&self) -> Option<&P> {
        match self.downcast_ref::<P>() {
            Some(pdu) => Some(pdu),
            None => match self.inner_pdu() {
                Some(pdu) => pdu.find::<P>(),
                None => None,
            },
        }
    }

    fn find_mut<P: Pdu>(&mut self) -> Option<&mut P> {
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

    fn into_any_pdu(self) -> AnyPdu {
        unsafe { self.unsafe_into_any_pdu() }
    }

    fn downcast<P: Pdu>(self) -> Result<P, Self> {
        unsafe { self.unsafe_downcast::<P>() }
    }

    fn downcast_ref<P: Pdu>(&self) -> Option<&P> {
        unsafe { self.unsafe_downcast_ref::<P>() }
    }

    fn downcast_mut<P: Pdu>(&mut self) -> Option<&mut P> {
        unsafe { self.unsafe_downcast_mut::<P>() }
    }

    fn make_all_canonical(&mut self) {
        if let Some(inner) = self.inner_pdu_mut() {
            inner.make_all_canonical();
        }
        self.make_canonical();
    }
}

impl<P: Pdu> PduExt for P {}

impl Drop for BasePdu {
    fn drop(&mut self) {
        if let Some(pdu) = std::mem::replace(&mut self.parent, None) {
            let _ = Box::into_raw(pdu.pdu);
        }
        let _ = std::mem::replace(&mut self.inner, None);
    }
}

impl std::fmt::Debug for BasePdu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasePdu")
            .field("inner", &self.inner)
            .finish()
    }
}

impl Clone for BasePdu {
    fn clone(&self) -> Self {
        BasePdu {
            parent: None,
            inner: self.inner.clone(),
        }
    }
}

pub(self) unsafe fn fake_any_pdu<P: Pdu>(pdu: &mut P) -> AnyPdu {
    AnyPdu {
        pdu: Box::from_raw(pdu as *mut P as *mut (dyn DynPdu + Send + Sync)),
    }
}
