use super::{AnyPDU, DynPDU, PDUExt, PDU};
use std::marker::PhantomData;

pub struct TempPDU<'a> {
    pdu: Option<AnyPDU>,
    parent: Option<&'a TempPDU<'a>>,
    _marker: PhantomData<&'a (dyn DynPDU + Send + Sync + 'static)>,
}

impl<'a> TempPDU<'a> {
    pub fn new<'b, 'c, P: PDU>(pdu: &'a P, parent: &'b Option<TempPDU<'c>>) -> Self
    where
        'b: 'a,
        'c: 'a,
    {
        let pdu: &'a (dyn DynPDU + Send + Sync + 'static) = pdu;
        let pdu: *const (dyn DynPDU + Send + Sync + 'static) = pdu;
        Self {
            pdu: Some(unsafe {
                AnyPDU {
                    pdu: Box::from_raw(std::mem::transmute(pdu)),
                }
            }),
            parent: parent.as_ref(),
            _marker: PhantomData,
        }
    }

    pub fn append<'b, 'c, P: PDU>(&'b self, pdu: &'c P) -> TempPDU<'c>
    where
        'a: 'c,
        'b: 'c,
    {
        let pdu: &'c (dyn DynPDU + Send + Sync + 'static) = pdu;
        let pdu: *const (dyn DynPDU + Send + Sync + 'static) = pdu;
        TempPDU {
            pdu: Some(unsafe {
                AnyPDU {
                    pdu: Box::from_raw(std::mem::transmute(pdu)),
                }
            }),
            parent: Some(self),
            _marker: PhantomData,
        }
    }

    pub fn parent(&self) -> Option<&'a TempPDU<'a>> {
        self.parent
    }

    pub fn pdu(&self) -> &AnyPDU {
        self.pdu.as_ref().unwrap()
    }

    pub fn find_pdu<P: PDU>(&self) -> Option<&P> {
        match self.pdu.as_ref().unwrap().downcast_ref::<P>() {
            Some(pdu) => Some(pdu),
            None => match self.parent {
                Some(parent) => parent.find_pdu::<P>(),
                None => None,
            },
        }
    }

    pub fn find_temp_pdu<P: PDU>(&self) -> Option<&TempPDU<'a>> {
        if self.pdu.as_ref().unwrap().is::<P>() {
            Some(self)
        } else {
            match self.parent {
                Some(parent) => parent.find_temp_pdu::<P>(),
                None => None,
            }
        }
    }
}

impl<'a> Clone for TempPDU<'a> {
    fn clone(&self) -> Self {
        let pdu: &(dyn DynPDU + Send + Sync + 'static) = &*self.pdu.as_ref().unwrap().pdu;
        let pdu: *const (dyn DynPDU + Send + Sync + 'static) = pdu;
        Self {
            pdu: Some(unsafe {
                AnyPDU {
                    pdu: Box::from_raw(std::mem::transmute(pdu)),
                }
            }),
            parent: self.parent,
            _marker: PhantomData,
        }
    }
}

impl<'a> Drop for TempPDU<'a> {
    fn drop(&mut self) {
        if let Some(pdu) = self.pdu.take() {
            let _ = Box::into_raw(pdu.pdu);
        }
    }
}
