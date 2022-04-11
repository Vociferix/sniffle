use super::{AnyPdu, DynPdu, Pdu, PduExt};
use std::marker::PhantomData;

pub struct TempPdu<'a> {
    pdu: Option<AnyPdu>,
    parent: Option<&'a TempPdu<'a>>,
    _marker: PhantomData<&'a (dyn DynPdu + Send + Sync + 'static)>,
}

impl<'a> TempPdu<'a> {
    pub fn new<'b, 'c, P: Pdu>(pdu: &'a P, parent: &'b Option<TempPdu<'c>>) -> Self
    where
        'b: 'a,
        'c: 'a,
    {
        let pdu: &'a (dyn DynPdu + Send + Sync + 'static) = pdu;
        let pdu: *const (dyn DynPdu + Send + Sync + 'static) = pdu;
        Self {
            pdu: Some(unsafe {
                AnyPdu {
                    pdu: Box::from_raw(std::mem::transmute(pdu)),
                }
            }),
            parent: parent.as_ref(),
            _marker: PhantomData,
        }
    }

    pub fn append<'b, 'c, P: Pdu>(&'b self, pdu: &'c P) -> TempPdu<'c>
    where
        'a: 'c,
        'b: 'c,
    {
        let pdu: &'c (dyn DynPdu + Send + Sync + 'static) = pdu;
        let pdu: *const (dyn DynPdu + Send + Sync + 'static) = pdu;
        TempPdu {
            pdu: Some(unsafe {
                AnyPdu {
                    pdu: Box::from_raw(std::mem::transmute(pdu)),
                }
            }),
            parent: Some(self),
            _marker: PhantomData,
        }
    }

    pub fn parent(&self) -> Option<&'a TempPdu<'a>> {
        self.parent
    }

    pub fn pdu(&self) -> &AnyPdu {
        self.pdu.as_ref().unwrap()
    }

    pub fn find_pdu<P: Pdu>(&self) -> Option<&P> {
        match self.pdu.as_ref().unwrap().downcast_ref::<P>() {
            Some(pdu) => Some(pdu),
            None => match self.parent {
                Some(parent) => parent.find_pdu::<P>(),
                None => None,
            },
        }
    }

    pub fn find_temp_pdu<P: Pdu>(&self) -> Option<&TempPdu<'a>> {
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

impl<'a> Clone for TempPdu<'a> {
    fn clone(&self) -> Self {
        let pdu: &(dyn DynPdu + Send + Sync + 'static) = &*self.pdu.as_ref().unwrap().pdu;
        let pdu: *const (dyn DynPdu + Send + Sync + 'static) = pdu;
        Self {
            pdu: Some(unsafe {
                AnyPdu {
                    pdu: Box::from_raw(std::mem::transmute(pdu)),
                }
            }),
            parent: self.parent,
            _marker: PhantomData,
        }
    }
}

impl<'a> Drop for TempPdu<'a> {
    fn drop(&mut self) {
        if let Some(pdu) = self.pdu.take() {
            let _ = Box::into_raw(pdu.pdu);
        }
    }
}
