use super::{fake_any_pdu, AnyPDU, DynPDU, PDUExt, PDU};

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

    pub fn new_with_parent<P: PDU>(parent: Option<&mut TempPDU<'_>>, pdu: &'a mut P) -> Self {
        match parent {
            Some(parent) => parent.push_inner(pdu),
            None => Self::new(pdu),
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
        if let Some(mut pdu) = std::mem::replace(&mut self.pdu_mut().base_pdu_mut().inner, None) {
            if let Some(parent) = std::mem::replace(&mut pdu.base_pdu_mut().parent, None) {
                let _ = Box::into_raw(parent.pdu);
            }
            let _ = Box::into_raw(pdu.pdu);
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
        if let Some(pdu) = self.pdu_mut().take_inner_pdu() {
            let _ = Box::into_raw(pdu.pdu);
        }
        if let Some(pdu) = std::mem::replace(&mut self.pdu, None) {
            let _ = Box::into_raw(pdu.pdu);
        }
    }
}
