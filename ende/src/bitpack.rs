use sniffle_uint::*;

/// A trait that defines how to pack and unpack uints.
///
/// Implementing BitPack allows types to be used with the `pack` and `unpack` macros.
pub trait BitPack {
    type Packed;

    fn pack(self) -> Self::Packed;
    fn unpack(packed: Self::Packed) -> Self;
}

impl<T> BitPack for (T,) {
    type Packed = T;

    fn pack(self) -> Self::Packed {
        self.0
    }

    fn unpack(packed: Self::Packed) -> Self {
        (packed,)
    }
}

macro_rules! bitpack_impl {
    (($t1:ident, $v1:ident), $(($tn:ident, $vn:ident)),+) => {
        impl<$t1, $($tn),+> BitPack for ($t1, $($tn),+)
            where ($($tn),+): BitPack,
                  ($t1, <($($tn),+) as BitPack>::Packed): BitPack,
        {
            type Packed = <($t1, <($($tn),+) as BitPack>::Packed) as BitPack>::Packed;

            fn pack(self) -> Self::Packed {
                let ($v1, $($vn),+) = self;
                ($v1, ($($vn),+).pack()).pack()
            }

            fn unpack(packed: Self::Packed) -> Self {
                let ($v1, tmp) = <($t1, <($($tn),+) as BitPack>::Packed)>::unpack(packed);
                let ($($vn),+) = <($($tn),+) as BitPack>::unpack(tmp);
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
        impl BitPack for ($l, $r) {
            type Packed = $o;

            fn pack(self) -> Self::Packed {
                (<$o>::from(self.0) << <$r>::BITS) | <$o>::from(self.1)
            }

            fn unpack(packed: Self::Packed) -> Self {
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
