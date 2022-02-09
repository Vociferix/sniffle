use super::{DissectError, Session};
use sniffle_ende::{
    encode::{DynEncoder, Encoder},
    nom::IResult,
};
use std::any::Any;

pub type PDUType = std::any::TypeId;

pub struct BasePDU {
    parent: Option<AnyPDU>,
    inner: Option<AnyPDU>,
}

pub struct AnyPDU {
    pdu: Box<dyn DynPDU>,
}

pub struct TempPDU<'a> {
    pdu: Option<AnyPDU>,
    _marker: std::marker::PhantomData<&'a dyn DynPDU>,
}

impl<'a> TempPDU<'a> {
    pub fn new<P: PDU>(pdu: &'a mut P) -> Self {
        Self {
            pdu: Some(unsafe { fake_any_pdu(pdu) }),
            _marker: std::marker::PhantomData,
        }
    }

    fn pdu_mut(&mut self) -> &mut AnyPDU {
        self.pdu
            .as_mut()
            .expect("internal sniffle error: TempPDU should never be null")
    }

    pub fn push_inner<'b, P: PDU>(&mut self, pdu: &'b mut P) -> TempPDU<'b> {
        self.pop_inner();
        pdu.base_pdu_mut().parent = self.pdu.as_mut().map(|pdu| unsafe { fake_any_pdu(pdu) });
        let _ = std::mem::replace(
            &mut self.pdu_mut().base_pdu_mut().inner,
            Some(unsafe { fake_any_pdu(pdu) }),
        );
        TempPDU::new(pdu)
    }

    pub fn pop_inner(&mut self) {
        match std::mem::replace(&mut self.pdu_mut().base_pdu_mut().inner, None) {
            Some(mut pdu) => {
                match std::mem::replace(&mut pdu.base_pdu_mut().parent, None) {
                    Some(parent) => {
                        let _ = Box::into_raw(parent.pdu);
                    }
                    None => {}
                }
                let _ = Box::into_raw(pdu.pdu);
            }
            None => {}
        }
    }
}

impl<'a> std::ops::Deref for TempPDU<'a> {
    type Target = AnyPDU;

    fn deref(&self) -> &Self::Target {
        self.pdu
            .as_ref()
            .expect("internal sniffle error: TempPDU should never be null")
    }
}

impl<'a> Drop for TempPDU<'a> {
    fn drop(&mut self) {
        match self.pdu_mut().take_inner_pdu() {
            Some(pdu) => {
                let _ = Box::into_raw(pdu.pdu);
            }
            None => {}
        }
        match std::mem::replace(&mut self.pdu, None) {
            Some(pdu) => {
                let _ = Box::into_raw(pdu.pdu);
            }
            None => {}
        }
    }
}

impl Drop for BasePDU {
    fn drop(&mut self) {
        match std::mem::replace(&mut self.parent, None) {
            Some(pdu) => {
                let _ = Box::into_raw(pdu.pdu);
            }
            None => {}
        }
        let _ = std::mem::replace(&mut self.inner, None);
    }
}

impl Default for BasePDU {
    fn default() -> Self {
        Self {
            parent: None,
            inner: None,
        }
    }
}

unsafe fn fake_any_pdu<P: PDU>(pdu: &mut P) -> AnyPDU {
    AnyPDU {
        pdu: Box::from_raw(pdu as *mut P as *mut dyn DynPDU),
    }
}

pub trait PDU: 'static + Any + Clone {
    fn base_pdu(&self) -> &BasePDU;
    fn base_pdu_mut(&mut self) -> &mut BasePDU;

    fn pdu_type(&self) -> PDUType {
        self.type_id()
    }

    fn is<P: PDU>(&self) -> bool {
        self.pdu_type() == PDUType::of::<P>()
    }

    fn dissect<'a>(
        _buf: &'a [u8],
        _session: &Session,
        _parent: Option<&mut TempPDU<'_>>,
    ) -> IResult<&'a [u8], Self, DissectError> {
        Err(sniffle_ende::nom::Err::Failure(DissectError::NotSupported))
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

    fn deep_clone(&self) -> Self {
        let mut ret = self.clone();
        self.inner_pdu()
            .map(|inner| ret.set_inner_pdu(inner.deep_clone()));
        ret
    }

    fn serialize_header<W: Encoder + ?Sized>(&self, encoder: &mut W) -> std::io::Result<()>;

    fn serialize_trailer<W: Encoder + ?Sized>(&self, _encoder: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn serialize<W: Encoder + ?Sized>(&self, encoder: &mut W) -> std::io::Result<()> {
        self.serialize_header(encoder)?;
        self.inner_pdu()
            .map(|inner| inner.serialize(encoder))
            .unwrap_or(Ok(()))?;
        self.serialize_trailer(encoder)
    }

    fn into_any_pdu(self) -> AnyPDU {
        AnyPDU {
            pdu: Box::new(self),
        }
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
                PDU::into_any_pdu(pdu)
            }),
        )
    }

    fn take_inner_pdu(&mut self) -> Option<AnyPDU> {
        match std::mem::replace(&mut self.base_pdu_mut().inner, None) {
            Some(mut pdu) => {
                match std::mem::replace(&mut pdu.base_pdu_mut().parent, None) {
                    Some(pdu) => {
                        let _ = Box::into_raw(pdu.pdu);
                    }
                    None => {}
                }
                Some(pdu)
            }
            None => None,
        }
    }

    fn set_inner_pdu<P: PDU>(&mut self, pdu: P) {
        let mut pdu = pdu;
        pdu.base_pdu_mut().parent = Some(unsafe { fake_any_pdu(self) });
        self.base_pdu_mut().inner = Some(PDU::into_any_pdu(pdu));
    }

    fn downcast<P: PDU>(self) -> Result<P, Self> {
        let is_type = self.is::<P>();
        if is_type {
            unsafe {
                let mut s = self;
                let pdu = std::mem::replace(
                    std::mem::transmute::<&mut Self, &mut P>(&mut s),
                    std::mem::MaybeUninit::uninit().assume_init(),
                );
                std::mem::forget(s);
                Ok(pdu)
            }
        } else {
            Err(self)
        }
    }

    fn downcast_ref<P: PDU>(&self) -> Option<&P> {
        if self.is::<P>() {
            unsafe { Some(std::mem::transmute::<&Self, &P>(self)) }
        } else {
            None
        }
    }

    fn downcast_mut<P: PDU>(&mut self) -> Option<&mut P> {
        let is_type = self.is::<P>();
        if is_type {
            unsafe { Some(std::mem::transmute::<&mut Self, &mut P>(self)) }
        } else {
            None
        }
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
}

trait DynPDU {
    fn dyn_base_pdu(&self) -> &BasePDU;
    fn dyn_base_pdu_mut(&mut self) -> &mut BasePDU;
    fn dyn_pdu_type(&self) -> PDUType;
    fn dyn_header_len(&self) -> usize;
    fn dyn_trailer_len(&self) -> usize;
    fn dyn_total_len(&self) -> usize;
    fn dyn_serialize_header(&self, encoder: &mut DynEncoder) -> std::io::Result<()>;
    fn dyn_serialize_trailer(&self, encoder: &mut DynEncoder) -> std::io::Result<()>;
    fn dyn_clone(&self) -> Box<dyn DynPDU + 'static>;
}

impl<P: PDU> DynPDU for P {
    fn dyn_base_pdu(&self) -> &BasePDU {
        self.base_pdu()
    }

    fn dyn_base_pdu_mut(&mut self) -> &mut BasePDU {
        self.base_pdu_mut()
    }

    fn dyn_pdu_type(&self) -> PDUType {
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

    fn dyn_serialize_header(&self, encoder: &mut DynEncoder) -> std::io::Result<()> {
        self.serialize_header(encoder)
    }

    fn dyn_serialize_trailer(&self, encoder: &mut DynEncoder) -> std::io::Result<()> {
        self.serialize_trailer(encoder)
    }

    fn dyn_clone(&self) -> Box<dyn DynPDU + 'static> {
        Box::new(self.clone())
    }
}

impl Clone for AnyPDU {
    fn clone(&self) -> Self {
        Self {
            pdu: self.pdu.dyn_clone(),
        }
    }
}

impl PDU for AnyPDU {
    fn base_pdu(&self) -> &BasePDU {
        self.pdu.dyn_base_pdu()
    }

    fn base_pdu_mut(&mut self) -> &mut BasePDU {
        self.pdu.dyn_base_pdu_mut()
    }

    fn pdu_type(&self) -> PDUType {
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

    fn into_any_pdu(self) -> AnyPDU {
        self
    }

    fn downcast<P: PDU>(self) -> Result<P, Self> {
        let is_type = self.is::<P>();
        if is_type {
            let ptr = Box::into_raw(self.pdu);
            unsafe { Ok(*Box::from_raw(ptr as *mut P)) }
        } else {
            Err(self)
        }
    }

    fn downcast_ref<P: PDU>(&self) -> Option<&P> {
        if self.is::<P>() {
            unsafe {
                let ptr = self.pdu.as_ref() as *const dyn DynPDU as *const P;
                Some(&*ptr)
            }
        } else {
            None
        }
    }

    fn downcast_mut<P: PDU>(&mut self) -> Option<&mut P> {
        let is_type = self.is::<P>();
        if is_type {
            unsafe {
                let ptr = self.pdu.as_mut() as *mut dyn DynPDU as *mut P;
                Some(&mut *ptr)
            }
        } else {
            None
        }
    }

    fn serialize_header<W: Encoder + ?Sized>(&self, encoder: &mut W) -> std::io::Result<()> {
        self.pdu.dyn_serialize_header(encoder.as_dyn_mut())
    }

    fn serialize_trailer<W: Encoder + ?Sized>(&self, encoder: &mut W) -> std::io::Result<()> {
        self.pdu.dyn_serialize_trailer(encoder.as_dyn_mut())
    }
}

impl AnyPDU {
    pub fn new<P: PDU>(pdu: P) -> AnyPDU {
        PDU::into_any_pdu(pdu)
    }
}
