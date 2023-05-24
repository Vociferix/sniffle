use crate::{MacAddress, Subnet};
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::fmt::{self, Display};

pub trait Oui: Borrow<MacAddress> {
    fn oui(&self) -> Option<&'static Assignment> {
        let addr: &MacAddress = self.borrow();
        match Assignment::DATABASE.binary_search_by(|entry| {
            if &entry.range().base_addr() > addr {
                Ordering::Greater
            } else if entry.range().contains(addr) {
                Ordering::Equal
            } else {
                Ordering::Less
            }
        }) {
            Ok(pos) => Some(&Assignment::DATABASE[pos]),
            Err(_) => None,
        }
    }
}

impl<T: Borrow<MacAddress> + ?Sized> Oui for T {}

/// An assignment of a range of MAC addresses to a manufacturer
#[derive(Debug)]
pub struct Assignment {
    range: Subnet<MacAddress>,
    abbrv: &'static str,
    name: &'static str,
}

impl Assignment {
    /// Database of OUI assignments according to IEEE
    ///
    /// This list is sorted in ascending address order.
    pub const DATABASE: &'static [Self] = ASSIGNMENTS;

    /// Returns the range of addresses associated with this assignment
    pub fn range(&self) -> &Subnet<MacAddress> {
        &self.range
    }

    /// Returns an abbreviation of the manufacturer's name
    pub fn abbrv(&self) -> &'static str {
        self.abbrv
    }

    /// Returns the full manufacturer's name
    pub fn name(&self) -> &'static str {
        self.name
    }
}

include!(concat!(env!("OUT_DIR"), "/oui_assignments.rs"));

/// A MacAddress wrapper to format the address using OUI assignment information.
pub struct Fmt<'a>(&'a MacAddress, Option<&'static Assignment>);

/// Wraps a MacAddress to format the address using OUI assignment information.
///
/// If the address has no associated OUI assignment, the address is formatted
/// normally.
///
/// NOTE: Looking up the OUI assignment runs in `O(log(n))` time, where `n` is
/// the length of `oui::Assignment::DATABASE`.
///
/// ## Example:
/// ```
/// # use sniffle_address::{mac, oui, Oui};
/// let addr = mac!("00:00:00:12:34:56");
/// let string = format!("{}", oui::fmt(&addr));
/// assert_eq!(string, "Xerox_12:34:56");
/// ```
pub fn fmt(addr: &MacAddress) -> Fmt<'_> {
    Fmt(addr, addr.oui())
}

/// Wraps a MacAddress to format the address using OUI assignment information.
///
/// If the `oui_info` is `None`, the address is formatted normally.
///
/// ## Example:
/// ```
/// # use sniffle_address::{mac, oui, Oui};
/// let addr = mac!("00:00:00:12:34:56");
/// let oui_info = addr.oui();
/// let string = format!("{}", oui::fmt_with(&addr, oui_info));
/// assert_eq!(string, "Xerox_12:34:56");
/// ```
pub fn fmt_with<'a>(addr: &'a MacAddress, oui_info: Option<&'static Assignment>) -> Fmt<'a> {
    Fmt(addr, oui_info)
}

impl<'a> Display for Fmt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ent) = self.1 {
            let len = ent.range().prefix_len();
            if len == 36 {
                write!(
                    f,
                    "{}_{:x}:{:02x}",
                    ent.abbrv(),
                    self.0[4] & 0x0F,
                    self.0[5]
                )?;
            } else if len == 32 {
                write!(f, "{}_{:02x}:{:02x}", ent.abbrv(), self.0[4], self.0[5])?;
            } else if len == 28 {
                write!(
                    f,
                    "{}_{:x}:{:02x}:{:02x}",
                    ent.abbrv(),
                    self.0[3] & 0x0F,
                    self.0[4],
                    self.0[5]
                )?;
            } else {
                write!(
                    f,
                    "{}_{:02x}:{:02x}:{:02x}",
                    ent.abbrv(),
                    self.0[3],
                    self.0[4],
                    self.0[5]
                )?;
            }
            Ok(())
        } else {
            Display::fmt(&self.0, f)
        }
    }
}
