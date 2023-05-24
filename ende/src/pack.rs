use sniffle_uint::*;

/// Derive the [`Pack`] trait on a struct.
///
/// A struct consisting of unsigned integers (either primitive or from the
/// [`sniffle::uint`](sniffle_uint) crate) and with total effective size less
/// than 64 bits (or 128 with the `u128` feature enabled) can derive [`Pack`].
/// Fields will be packed into an unsigned integer in the order that they are
/// defined in the struct, from most to least significant.
///
/// ## Example
/// ```
/// # use sniffle_ende::pack::{Pack, Unpack};
/// # use sniffle_uint::*;
/// #[derive(Pack, Debug, PartialEq, Eq)]
/// struct BitFields {
///     a: U3,
///     b: u8,
///     c: U5,
/// }
///
/// let unpacked = BitFields {
///     a: 0b010.into_masked(),
///     b: 0b01101010,
///     c: 0b11100.into_masked(),
/// };
///
/// let packed = unpacked.pack();
/// assert_eq!(packed, 0b_010_01101010_11100u16);
///
/// let unpacked: BitFields = packed.unpack();
/// assert_eq!(unpacked, BitFields {
///     a: 0b010.into_masked(),
///     b: 0b01101010,
///     c: 0b11100.into_masked(),
/// });
/// ```
pub use sniffle_ende_derive::Pack;

/// A trait that defines how to pack and unpack fields of `struct` or tuple.
///
/// Fields each have an effective bit width that may or may not be a multiple of
/// 8. For example the type [`sniffle::uint::U3`](sniffle_uint::U3) is
/// effectively a 3-bit integer. As such, when packed an unpacked, only 3 bits
/// are used. This allows types that implement [`Pack`] to represent bit fields,
/// although indirectly.
///
/// For example, the tuple `(U3, U6, U7)` is a normal rust tuple with 3 fields
/// with at least byte alignment and size, but it also implements [`Pack`], which
/// allows for simple and infallible conversion to and from `u16`, since the 3
/// fields total to 16 effective bits.
///
/// [`Pack`] also interoperates with the [`decode`](crate::decode) and
/// [`encode`](crate::encode) modules. If the packed type implements
/// [`Decode`](crate::decode::Decode),
/// [`DecodeBe`](crate::decode::DecodeBe),
/// [`DecodeLe`](crate::decode::DecodeLe),
/// [`Encode`](crate::encode::Encode),
/// [`EncodeBe`](crate::encode::EncodeBe), or
/// [`EncodeLe`](crate::encode::EncodeLe),
/// the implementing type will also implement those traits. Again using the tuple
/// `(U3, U6, U7)` as an example, the tuple type implements
/// [`DecodeBe`](crate::decode::DecodeBe),
/// [`DecodeLe`](crate::decode::DecodeLe),
/// [`EncodeBe`](crate::encode::EncodeBe), and
/// [`EncodeLe`](crate::encode::EncodeLe) because `u16` implements those
/// traits. The encoded tuple will be 16-bits, equivalent to packing the values
/// into a `u16`. Note that the fields of the tuple are encoded and decoded in
/// order, regardless of endianness. Endianness affects how the packed type (the
/// `u16`) is encoded and decoded, but from there the fields are extracted from
/// the `u16` from MSB to LSB order.
///
/// # Limitations
/// [`Pack`] is designed only to convert between product types (`structs` and
/// tuples) and unsigned integers. As a consequence the provided basic
/// implementations only allow for packing of up to 64 bits, or 128 bits with
/// the `u128` feature enabled.
///
/// Additionally, the [`encode`](crate::encode) and [`decode`](crate::decode)
/// modules are not bit aware - only byte aware. The consequence is that not
/// all arbitrary types implementing [`Pack`] can be encoded or decoded.
/// Instead, only types that have an exact byte width can be encoded and
/// decoded. Rephrased, the number of `bits` in the `Pack::Packed` type must
/// satisfy `bits % 8 == 0` to be able to be encoded and decoded.
pub trait Pack {
    /// Target packed type
    type Packed;

    /// Converts the implementing type into a packed representation. See also
    /// [`Unpack::pack_from`].
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::pack::Pack;
    /// # use sniffle_uint::{IntoMasked, U3, U6, U7};
    /// let unpacked: (U3, U6, U7) = (
    ///     0b010.into_masked(),
    ///     0b100100.into_masked(),
    ///     0b0110101.into_masked(),
    /// );
    /// let packed = unpacked.pack();
    /// assert_eq!(packed, 0b_010_100100_0110101);
    /// ```
    fn pack(self) -> Self::Packed;

    /// Converts the packed representation into the implementing type. See
    /// also [`Unpack::unpack`].
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::pack::Pack;
    /// # use sniffle_uint::{IntoMasked, U3, U6, U7};
    /// let packed = 0b_010_100100_0110101_u16;
    /// let unpacked = <(U3, U6, U7)>::unpack_from(packed);
    /// assert_eq!(unpacked, (
    ///     0b010.into_masked(),
    ///     0b100100.into_masked(),
    ///     0b0110101.into_masked(),
    /// ));
    /// ```
    fn unpack_from(packed: Self::Packed) -> Self;
}

/// Helper trait to [`Pack`] similar to the [`Into`](std::convert::Into) trait.
///
/// [`Unpack`] is the reverse of [`Pack`] and is automatically implemented for
/// all `Pack::Packed` types.
pub trait Unpack<T: Pack<Packed = Self>>: Sized {
    /// The reverse of [`Pack::unpack_from`].
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::pack::Unpack;
    /// # use sniffle_uint::{U3, U6, U7, IntoMasked};
    /// let unpacked: (U3, U6, U7) = (
    ///     0b010.into_masked(),
    ///     0b100100.into_masked(),
    ///     0b0110101.into_masked(),
    /// );
    /// let packed = u16::pack_from(unpacked);
    /// assert_eq!(packed, 0b_010_100100_0110101);
    /// ```
    fn pack_from(unpacked: T) -> Self {
        unpacked.pack()
    }

    /// The reverse of [`Pack::pack`].
    ///
    /// ## Example
    /// ```
    /// # use sniffle_ende::pack::Unpack;
    /// # use sniffle_uint::{U3, U6, U7, IntoMasked};
    /// let packed = 0b_010_100100_0110101_u16;
    /// let unpacked: (U3, U6, U7) = packed.unpack();
    /// assert_eq!(unpacked, (
    ///     0b010.into_masked(),
    ///     0b100100.into_masked(),
    ///     0b0110101.into_masked(),
    /// ));
    /// ```
    fn unpack(self) -> T {
        T::unpack_from(self)
    }
}

impl<T, P> Unpack<T> for P where T: Pack<Packed = P> {}

impl<T> Pack for (T,) {
    type Packed = T;

    fn pack(self) -> Self::Packed {
        self.0
    }

    fn unpack_from(packed: Self::Packed) -> Self {
        (packed,)
    }
}

macro_rules! bitpack_impl {
    (($t1:ident, $v1:ident), $(($tn:ident, $vn:ident)),+) => {
        impl<$t1, $($tn),+> Pack for ($t1, $($tn),+)
            where ($($tn),+): Pack,
                  ($t1, <($($tn),+) as Pack>::Packed): Pack,
        {
            type Packed = <($t1, <($($tn),+) as Pack>::Packed) as Pack>::Packed;

            fn pack(self) -> Self::Packed {
                let ($v1, $($vn),+) = self;
                ($v1, ($($vn),+).pack()).pack()
            }

            fn unpack_from(packed: Self::Packed) -> Self {
                let ($v1, tmp) = <($t1, <($($tn),+) as Pack>::Packed)>::unpack_from(packed);
                let ($($vn),+) = <($($tn),+) as Pack>::unpack_from(tmp);
                ($v1, $($vn),+)
            }
        }
    };
}

macro_rules! bitpack_impl_all {
    (($t1:ident, $v1:ident), ($t2:ident, $v2:ident)) => { };
    (($t1:ident, $v1:ident), ($t2:ident, $v2:ident), $(($tn:ident, $vn:ident)),+) => {
        bitpack_impl!(($t1, $v1), ($t2, $v2), $(($tn, $vn)),+);
        bitpack_impl_all!(($t2, $v2), $(($tn, $vn)),+);
    }
}

#[cfg(feature = "u128")]
bitpack_impl_all!(
    (T1, v1),
    (T2, v2),
    (T3, v3),
    (T4, v4),
    (T5, v5),
    (T6, v6),
    (T7, v7),
    (T8, v8),
    (T9, v9),
    (T10, v10),
    (T11, v11),
    (T12, v12),
    (T13, v13),
    (T14, v14),
    (T15, v15),
    (T16, v16),
    (T17, v17),
    (T18, v18),
    (T19, v19),
    (T20, v20),
    (T21, v21),
    (T22, v22),
    (T23, v23),
    (T24, v24),
    (T25, v25),
    (T26, v26),
    (T27, v27),
    (T28, v28),
    (T29, v29),
    (T30, v30),
    (T31, v31),
    (T32, v32),
    (T33, v33),
    (T34, v34),
    (T35, v35),
    (T36, v36),
    (T37, v37),
    (T38, v38),
    (T39, v39),
    (T40, v40),
    (T41, v41),
    (T42, v42),
    (T43, v43),
    (T44, v44),
    (T45, v45),
    (T46, v46),
    (T47, v47),
    (T48, v48),
    (T49, v49),
    (T50, v50),
    (T51, v51),
    (T52, v52),
    (T53, v53),
    (T54, v54),
    (T55, v55),
    (T56, v56),
    (T57, v57),
    (T58, v58),
    (T59, v59),
    (T60, v60),
    (T61, v61),
    (T62, v62),
    (T63, v63),
    (T64, v64),
    (T65, v65),
    (T66, v66),
    (T67, v67),
    (T68, v68),
    (T69, v69),
    (T70, v70),
    (T71, v71),
    (T72, v72),
    (T73, v73),
    (T74, v74),
    (T75, v75),
    (T76, v76),
    (T77, v77),
    (T78, v78),
    (T79, v79),
    (T80, v80),
    (T81, v81),
    (T82, v82),
    (T83, v83),
    (T84, v84),
    (T85, v85),
    (T86, v86),
    (T87, v87),
    (T88, v88),
    (T89, v89),
    (T90, v90),
    (T91, v91),
    (T92, v92),
    (T93, v93),
    (T94, v94),
    (T95, v95),
    (T96, v96),
    (T97, v97),
    (T98, v98),
    (T99, v99),
    (T100, v100),
    (T101, v101),
    (T102, v102),
    (T103, v103),
    (T104, v104),
    (T105, v105),
    (T106, v106),
    (T107, v107),
    (T108, v108),
    (T109, v109),
    (T110, v110),
    (T111, v111),
    (T112, v112),
    (T113, v113),
    (T114, v114),
    (T115, v115),
    (T116, v116),
    (T117, v117),
    (T118, v118),
    (T119, v119),
    (T120, v120),
    (T121, v121),
    (T122, v122),
    (T123, v123),
    (T124, v124),
    (T125, v125),
    (T126, v126),
    (T127, v127),
    (T128, v128)
);

#[cfg(not(feature = "u128"))]
bitpack_impl_all!(
    (T1, v1),
    (T2, v2),
    (T3, v3),
    (T4, v4),
    (T5, v5),
    (T6, v6),
    (T7, v7),
    (T8, v8),
    (T9, v9),
    (T10, v10),
    (T11, v11),
    (T12, v12),
    (T13, v13),
    (T14, v14),
    (T15, v15),
    (T16, v16),
    (T17, v17),
    (T18, v18),
    (T19, v19),
    (T20, v20),
    (T21, v21),
    (T22, v22),
    (T23, v23),
    (T24, v24),
    (T25, v25),
    (T26, v26),
    (T27, v27),
    (T28, v28),
    (T29, v29),
    (T30, v30),
    (T31, v31),
    (T32, v32),
    (T33, v33),
    (T34, v34),
    (T35, v35),
    (T36, v36),
    (T37, v37),
    (T38, v38),
    (T39, v39),
    (T40, v40),
    (T41, v41),
    (T42, v42),
    (T43, v43),
    (T44, v44),
    (T45, v45),
    (T46, v46),
    (T47, v47),
    (T48, v48),
    (T49, v49),
    (T50, v50),
    (T51, v51),
    (T52, v52),
    (T53, v53),
    (T54, v54),
    (T55, v55),
    (T56, v56),
    (T57, v57),
    (T58, v58),
    (T59, v59),
    (T60, v60),
    (T61, v61),
    (T62, v62),
    (T63, v63),
    (T64, v64)
);

macro_rules! impl_bitpack {
    (($l:ty, $r:ty) -> $o:ty) => {
        impl Pack for ($l, $r) {
            type Packed = $o;

            fn pack(self) -> Self::Packed {
                (<$o>::from(self.0) << <$r>::BITS) | <$o>::from(self.1)
            }

            fn unpack_from(packed: Self::Packed) -> Self {
                let l = (packed >> <$r>::BITS) & <$o>::from(<$l>::MAX);
                let r = packed & <$o>::from(<$r>::MAX);
                (l.try_into().unwrap(), r.try_into().unwrap())
            }
        }
    };
    (($l1:ty, $r1:ty) -> $o1:ty, $(($ln:ty, $rn:ty) -> $on:ty),+) => {
        impl_bitpack!(($l1, $r1) -> $o1);
        impl_bitpack!($(($ln, $rn) -> $on),+);
    };
}

macro_rules! impl_all_bitpack_impl {
    (($l:ty), ($r:ty), ($o:ty)) => {
        impl_bitpack!(($l, $r) -> $o);
    };
    (($l:ty), ($r1:ty, $($rn:ty),+), ($o:ty)) => {
        impl_bitpack!(($l, $r1) -> $o);
    };
    (($l:ty), ($r:ty), ($o1:ty, $($on:ty),+)) => {
        impl_bitpack!(($l, $r) -> $o1);
    };
    (($l:ty), ($r1:ty, $($rn:ty),+), ($o1:ty, $($on:ty),+)) => {
        impl_bitpack!(($l, $r1) -> $o1);
        impl_all_bitpack_impl!(($l), ($($rn),+), ($($on),+));
    };
}

macro_rules! impl_all_bitpack {
    (($l1:ty), ($($rn:ty),+)) => { };
    (($l1:ty, $($ln:ty),+), ($($rn:ty),+)) => {
        impl_all_bitpack_impl!(($l1), ($($rn),+), ($($ln),+));
        impl_all_bitpack!(($($ln),+), ($($rn),+));
    };
    ($($t:ty),+) => { impl_all_bitpack!(($($t),+), ($($t),+)); };
}

#[cfg(feature = "u128")]
impl_all_bitpack!(
    U1, U2, U3, U4, U5, U6, U7, u8, U9, U10, U11, U12, U13, U14, U15, u16, U17, U18, U19, U20, U21,
    U22, U23, U24, U25, U26, U27, U28, U29, U30, U31, u32, U33, U34, U35, U36, U37, U38, U39, U40,
    U41, U42, U43, U44, U45, U46, U47, U48, U49, U50, U51, U52, U53, U54, U55, U56, U57, U58, U59,
    U60, U61, U62, U63, u64, U65, U66, U67, U68, U69, U70, U71, U72, U73, U74, U75, U76, U77, U78,
    U79, U80, U81, U82, U83, U84, U85, U86, U87, U88, U89, U90, U91, U92, U93, U94, U95, U96, U97,
    U98, U99, U100, U101, U102, U103, U104, U105, U106, U107, U108, U109, U110, U111, U112, U113,
    U114, U115, U116, U117, U118, U119, U120, U121, U122, U123, U124, U125, U126, U127, u128
);

#[cfg(not(feature = "u128"))]
impl_all_bitpack!(
    U1, U2, U3, U4, U5, U6, U7, u8, U9, U10, U11, U12, U13, U14, U15, u16, U17, U18, U19, U20, U21,
    U22, U23, U24, U25, U26, U27, U28, U29, U30, U31, u32, U33, U34, U35, U36, U37, U38, U39, U40,
    U41, U42, U43, U44, U45, U46, U47, U48, U49, U50, U51, U52, U53, U54, U55, U56, U57, U58, U59,
    U60, U61, U62, U63, u64
);
