use super::{AnyPDU, RawPDU, Session, TempPDU, PDU};
use sniffle_ende::decode::Decode;
use sniffle_ende::nom::{self, combinator::map, Parser};
use std::marker::PhantomData;

#[derive(Debug, Clone, Copy)]
pub struct Priority(pub i32);

pub use sniffle_ende::decode::DResult;
pub use sniffle_ende::decode::DecodeError as DissectError;

pub trait Dissect: PDU {
    fn dissect<'a>(
        buf: &'a [u8],
        session: &Session,
        parent: Option<TempPDU<'_>>,
    ) -> DResult<'a, Self>;

    fn dissector<'a>(session: &'a Session, parent: Option<TempPDU<'a>>) -> DissectParser<'a, Self> {
        DissectParser {
            session,
            parent,
            _marker: PhantomData,
        }
    }
}

pub struct DissectParser<'a, D: Dissect> {
    session: &'a Session,
    parent: Option<TempPDU<'a>>,
    _marker: PhantomData<fn(D) -> D>,
}

pub trait Dissector {
    type Out: PDU;

    fn dissect<'a>(
        &self,
        buffer: &'a [u8],
        session: &Session,
        parent: Option<TempPDU<'_>>,
    ) -> DResult<'a, Self::Out>;
}

pub struct AnyDissector(Box<dyn Dissector<Out = AnyPDU> + Send + Sync + 'static>);

pub struct DissectorTableParser<'a, T: DissectorTable> {
    table: Option<&'a T>,
    param: &'a T::Param,
    session: &'a Session,
    parent: Option<TempPDU<'a>>,
}

pub trait DissectorTable: Default {
    type Param;

    fn load<D: Dissector + Send + Sync + 'static>(
        &mut self,
        param: Self::Param,
        priority: Priority,
        dissector: D,
    );

    fn find(&self, param: &Self::Param) -> Option<&[AnyDissector]>;

    fn dissector<'a>(
        &'a self,
        param: &'a Self::Param,
        session: &'a Session,
        parent: Option<TempPDU<'a>>,
    ) -> DissectorTableParser<'a, Self> {
        DissectorTableParser {
            table: Some(self),
            param,
            session,
            parent,
        }
    }

    fn dissect<'a>(
        &self,
        param: &Self::Param,
        buffer: &'a [u8],
        session: &Session,
        parent: Option<TempPDU<'_>>,
    ) -> DResult<'a, AnyPDU> {
        self.dissector(param, session, parent).parse(buffer)
    }

    fn dissect_or_raw<'a>(
        &self,
        param: &Self::Param,
        buffer: &'a [u8],
        session: &Session,
        parent: Option<TempPDU<'_>>,
    ) -> DResult<'a, AnyPDU> {
        self.dissector(param, session, parent)
            .or(map(RawPDU::decode, AnyPDU::new))
            .parse(buffer)
    }
}

impl<'a, 'b, D: Dissect> Parser<&'a [u8], D, DissectError<'a>> for DissectParser<'b, D> {
    fn parse(&mut self, input: &'a [u8]) -> DResult<'a, D> {
        D::dissect(input, self.session, self.parent.clone())
    }
}

impl<'a, 'b, T: DissectorTable> Parser<&'a [u8], AnyPDU, DissectError<'a>>
    for DissectorTableParser<'b, T>
{
    fn parse(&mut self, input: &'a [u8]) -> DResult<'a, AnyPDU> {
        if let Some(table) = self.table {
            for dissector in table.find(self.param).unwrap_or(&[]) {
                match Dissector::dissect(dissector, input, self.session, self.parent.clone()) {
                    Ok((buf, pdu)) => {
                        return Ok((buf, pdu));
                    }
                    Err(nom::Err::Failure(e)) => {
                        return Err(nom::Err::Failure(e));
                    }
                    _ => {}
                }
            }
        }
        Err(nom::Err::Error(DissectError::Malformed))
    }
}

impl<'a, T: DissectorTable> DissectorTableParser<'a, T> {
    pub fn null_parser(
        param: &'a T::Param,
        session: &'a Session,
        parent: Option<TempPDU<'a>>,
    ) -> Self {
        Self {
            table: None,
            param,
            session,
            parent,
        }
    }
}

impl Dissector for AnyDissector {
    type Out = AnyPDU;

    fn dissect<'a>(
        &self,
        buffer: &'a [u8],
        session: &Session,
        parent: Option<TempPDU<'_>>,
    ) -> DResult<'a, Self::Out> {
        self.0.dissect(buffer, session, parent)
    }
}

impl<F, P> Dissector for F
where
    P: PDU,
    F: for<'a> Fn(&'a [u8], &Session, Option<TempPDU<'_>>) -> DResult<'a, P>,
{
    type Out = P;

    fn dissect<'a>(
        &self,
        buffer: &'a [u8],
        session: &Session,
        parent: Option<TempPDU<'_>>,
    ) -> DResult<'a, Self::Out> {
        self(buffer, session, parent)
    }
}

struct DissectorAdapter<D: Dissector>(D);

impl<D: Dissector> Dissector for DissectorAdapter<D> {
    type Out = AnyPDU;

    fn dissect<'a>(
        &self,
        buffer: &'a [u8],
        session: &Session,
        parent: Option<TempPDU<'_>>,
    ) -> DResult<'a, Self::Out> {
        self.0
            .dissect(buffer, session, parent)
            .map(|(rem, pdu)| (rem, AnyPDU::new(pdu)))
    }
}

impl AnyDissector {
    pub fn new<D: Dissector + Send + Sync + 'static>(dissector: D) -> Self {
        Self(Box::new(DissectorAdapter(dissector)))
    }
}

#[macro_export]
macro_rules! dissector_table {
    ($name:ident) => {
        dissector_table!(__priv_decl, $name, ());
        dissector_table!(__impl, $name, ());
    };
    (pub $name:ident) => {
        dissector_table!(__pub_decl, $name, ());
        dissector_table!(__impl, $name, ());
    };
    ($name:ident, $param:ty) => {
        dissector_table!(__priv_decl, $name, $param);
        dissector_table!(__impl, $name, $param);
    };
    (pub $name:ident, $param:ty) => {
        dissector_table!(__pub_decl, $name, $param);
        dissector_table!(__impl, $name, $param);
    };

    (__priv_decl, $name:ident, ()) => {
        struct $name(
            ::std::vec::Vec<$crate::Priority>,
            ::std::vec::Vec<$crate::AnyDissector>,
        );
    };
    (__pub_decl, $name:ident, ()) => {
        pub struct $name(
            ::std::vec::Vec<$crate::Priority>,
            ::std::vec::Vec<$crate::AnyDissector>,
        );
    };
    (__priv_decl, $name:ident, $param:ty) => {
        struct $name(
            ::std::collections::HashMap<
                $param,
                (
                    ::std::vec::Vec<$crate::Priority>,
                    ::std::vec::Vec<$crate::AnyDissector>,
                ),
            >,
        );
    };
    (__pub_decl, $name:ident, $param:ty) => {
        pub struct $name(
            ::std::collections::HashMap<
                $param,
                (
                    ::std::vec::Vec<$crate::Priority>,
                    ::std::vec::Vec<$crate::AnyDissector>,
                ),
            >,
        );
    };
    (__impl, $name:ident, ()) => {
        impl $name {
            pub fn new() -> Self {
                Self(::std::vec::Vec::new(), ::std::vec::Vec::new())
            }
        }

        impl ::std::default::Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $crate::DissectorTable for $name {
            type Param = ();

            fn load<D: $crate::Dissector + Send + Sync + 'static>(
                &mut self,
                _param: Self::Param,
                priority: $crate::Priority,
                dissector: D,
            ) {
                let dissector = $crate::AnyDissector::new(dissector);
                let pos = self
                    .0
                    .binary_search_by(|item| priority.0.cmp(&item.0))
                    .unwrap_or_else(|e| e);
                self.0.insert(pos, priority);
                self.1.insert(pos, dissector);
            }

            fn find(&self, _param: &Self::Param) -> Option<&[$crate::AnyDissector]> {
                Some(&self.1[..])
            }
        }
    };
    (__impl, $name:ident, $param:ty) => {
        impl $name {
            pub fn new() -> Self {
                Self(::std::collections::HashMap::new())
            }
        }

        impl ::std::default::Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $crate::DissectorTable for $name {
            type Param = $param;

            fn load<D: $crate::Dissector + Send + Sync + 'static>(
                &mut self,
                param: Self::Param,
                priority: $crate::Priority,
                dissector: D,
            ) {
                let dissector = $crate::AnyDissector::new(dissector);
                let table = self
                    .0
                    .entry(param)
                    .or_insert((::std::vec::Vec::new(), ::std::vec::Vec::new()));
                let pos = table
                    .0
                    .binary_search_by(|item| priority.0.cmp(&item.0))
                    .unwrap_or_else(|e| e);
                table.0.insert(pos, priority);
                table.1.insert(pos, dissector);
            }

            fn find(&self, param: &Self::Param) -> Option<&[$crate::AnyDissector]> {
                match self.0.get(param) {
                    Some(table) => Some(&table.1[..]),
                    None => None,
                }
            }
        }
    };
}
