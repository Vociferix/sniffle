#![doc = include_str!("../README.md")]

use std::hash::Hash;

/// A 16-bit value representing a link type, otherwise known as a DLT.
#[derive(Debug, Clone, Copy, Hash)]
#[repr(transparent)]
pub struct LinkType(pub u16);

macro_rules! link_type {
    ($name:ident, $val:literal) => {
        pub const $name: LinkType = LinkType($val);
    };
}

/// Expands the passed macro with the identifer for each defined link type constant.
///
/// This utility takes another macro as its argument and passes the identifier for
/// each constant defined on LinkType, which are all the well defined link types.
/// This is useful for generating rust code for each named link type.
///
/// The provided macro is expanded repeatedly, as:
/// ```
/// # macro_rules! my_macro { ($l:ident) => { }; }
/// // link_types::for_each_link_type!(my_macro); expands to:
/// my_macro!(NULL);
/// my_macro!(ETHERNET);
/// my_macro!(AX25);
/// // etc...
/// ```
#[macro_export]
macro_rules! for_each_link_type {
    ($macro:ident) => {
        $macro!(NULL);
        $macro!(ETHERNET);
        $macro!(AX25);
        $macro!(IEEE802_5);
        $macro!(ARCNET_BSD);
        $macro!(SLIP);
        $macro!(PPP);
        $macro!(FDDI);
        $macro!(PPP_HDLC);
        $macro!(PPP_ETHER);
        $macro!(ATM_RFC1483);
        $macro!(RAW);
        $macro!(C_HDLC);
        $macro!(IEEE802_11);
        $macro!(FRELAY);
        $macro!(LOOP);
        $macro!(LINUX_SLL);
        $macro!(LTALK);
        $macro!(PFLOG);
        $macro!(IEEE802_11_PRISM);
        $macro!(IP_OVER_FC);
        $macro!(SUNATM);
        $macro!(IEEE802_11_RADIOTAP);
        $macro!(ARCNET_LINUX);
        $macro!(APPLE_IP_OVER_IEEE1394);
        $macro!(MTP2_WITH_PHDR);
        $macro!(MTP2);
        $macro!(MTP3);
        $macro!(SCCP);
        $macro!(DOCSIS);
        $macro!(LINUX_IRDA);
        $macro!(USER0);
        $macro!(USER1);
        $macro!(USER2);
        $macro!(USER3);
        $macro!(USER4);
        $macro!(USER5);
        $macro!(USER6);
        $macro!(USER7);
        $macro!(USER8);
        $macro!(USER9);
        $macro!(USER10);
        $macro!(USER11);
        $macro!(USER12);
        $macro!(USER13);
        $macro!(USER14);
        $macro!(USER15);
        $macro!(IEEE802_11_AVS);
        $macro!(BACNET_MS_TP);
        $macro!(PPP_PPPD);
        $macro!(GPRS_LLC);
        $macro!(GPF_T);
        $macro!(GPF_F);
        $macro!(LINUX_LAPD);
        $macro!(MFR);
        $macro!(BLUETOOTH_HCI_H4);
        $macro!(USB_LINUX);
        $macro!(PPI);
        $macro!(IEEE802_15_4_WITHFCS);
        $macro!(SITA);
        $macro!(ERF);
        $macro!(BLUETOOTH_HCI_H4_WITH_PHDR);
        $macro!(AX25_KISS);
        $macro!(LAPD);
        $macro!(PPP_WITH_DIR);
        $macro!(C_HDLC_WITH_DIR);
        $macro!(FRELAY_WITH_DIR);
        $macro!(LAPB_WITH_DIR);
        $macro!(IPMB_LINUX);
        $macro!(IEEE802_15_4_NONASK_PHY);
        $macro!(USB_LINUX_MMAPPED);
        $macro!(FC_2);
        $macro!(FC_2_WITH_FRAME_DELIMS);
        $macro!(IPNET);
        $macro!(CAN_SOCKETCAN);
        $macro!(IPV4);
        $macro!(IPV6);
        $macro!(IEEE802_15_4_NO_FCS);
        $macro!(DBUS);
        $macro!(DVB_CI);
        $macro!(MUX27010);
        $macro!(STANAG_5066_D_PDU);
        $macro!(NFLOG);
        $macro!(NETANALYZER);
        $macro!(NETANALYZER_TRANSPARENT);
        $macro!(IPOIB);
        $macro!(MPEG_2_TS);
        $macro!(NG40);
        $macro!(NFC_LLCP);
        $macro!(INFINIBAND);
        $macro!(SCTP);
        $macro!(USBPCAP);
        $macro!(RTAC_SERIAL);
        $macro!(BLUETOOTH_LE_LL);
        $macro!(NETLINK);
        $macro!(BLUETOOTH_LINUX_MONITOR);
        $macro!(BLUETOOTH_BREDR_BB);
        $macro!(BLUETOOTH_LE_LL_WITH_PHDR);
        $macro!(PROFIBUS_DL);
        $macro!(PKTAP);
        $macro!(EPON);
        $macro!(IPMI_HPM_2);
        $macro!(ZWAVE_R1_R2);
        $macro!(ZWAVE_R3);
        $macro!(WATTSTOPPER_DLM);
        $macro!(ISO_14443);
        $macro!(RDS);
        $macro!(USB_DARWIN);
        $macro!(SDLC);
        $macro!(LORATAP);
        $macro!(VSOCK);
        $macro!(NORDIC_BLE);
        $macro!(DOCSIS31_XRA31);
        $macro!(ETHERNET_MPACKET);
        $macro!(DISPLAYPORT_AUX);
        $macro!(LINUX_SLL2);
        $macro!(OPENVIZSLA);
        $macro!(EBHSCR);
        $macro!(VPP_DISPATCH);
        $macro!(DSA_TAG_BRCM);
        $macro!(DSA_TAG_BRCM_PREPEND);
        $macro!(IEEE802_15_4_TAP);
        $macro!(DSA_TAG_DSA);
        $macro!(DSA_TAG_EDSA);
        $macro!(ELEE);
        $macro!(Z_WAVE_SERIAL);
        $macro!(USB_2_0);
        $macro!(ATSC_ALP);
    };
}

impl LinkType {
    // http://www.tcpdump.org/linktypes.html
    link_type!(NULL, 0);
    link_type!(ETHERNET, 1);
    link_type!(AX25, 3);
    link_type!(IEEE802_5, 6);
    link_type!(ARCNET_BSD, 7);
    link_type!(SLIP, 8);
    link_type!(PPP, 9);
    link_type!(FDDI, 10);
    link_type!(PPP_HDLC, 50);
    link_type!(PPP_ETHER, 51);
    link_type!(ATM_RFC1483, 100);
    link_type!(RAW, 101);
    link_type!(C_HDLC, 104);
    link_type!(IEEE802_11, 105);
    link_type!(FRELAY, 107);
    link_type!(LOOP, 108);
    link_type!(LINUX_SLL, 113);
    link_type!(LTALK, 114);
    link_type!(PFLOG, 117);
    link_type!(IEEE802_11_PRISM, 119);
    link_type!(IP_OVER_FC, 122);
    link_type!(SUNATM, 123);
    link_type!(IEEE802_11_RADIOTAP, 127);
    link_type!(ARCNET_LINUX, 129);
    link_type!(APPLE_IP_OVER_IEEE1394, 138);
    link_type!(MTP2_WITH_PHDR, 139);
    link_type!(MTP2, 140);
    link_type!(MTP3, 141);
    link_type!(SCCP, 142);
    link_type!(DOCSIS, 143);
    link_type!(LINUX_IRDA, 144);
    link_type!(USER0, 147);
    link_type!(USER1, 148);
    link_type!(USER2, 149);
    link_type!(USER3, 150);
    link_type!(USER4, 151);
    link_type!(USER5, 152);
    link_type!(USER6, 153);
    link_type!(USER7, 154);
    link_type!(USER8, 155);
    link_type!(USER9, 156);
    link_type!(USER10, 157);
    link_type!(USER11, 158);
    link_type!(USER12, 159);
    link_type!(USER13, 160);
    link_type!(USER14, 161);
    link_type!(USER15, 162);
    link_type!(IEEE802_11_AVS, 163);
    link_type!(BACNET_MS_TP, 165);
    link_type!(PPP_PPPD, 166);
    link_type!(GPRS_LLC, 169);
    link_type!(GPF_T, 170);
    link_type!(GPF_F, 171);
    link_type!(LINUX_LAPD, 177);
    link_type!(MFR, 182);
    link_type!(BLUETOOTH_HCI_H4, 187);
    link_type!(USB_LINUX, 189);
    link_type!(PPI, 192);
    link_type!(IEEE802_15_4_WITHFCS, 195);
    link_type!(SITA, 196);
    link_type!(ERF, 197);
    link_type!(BLUETOOTH_HCI_H4_WITH_PHDR, 201);
    link_type!(AX25_KISS, 202);
    link_type!(LAPD, 203);
    link_type!(PPP_WITH_DIR, 204);
    link_type!(C_HDLC_WITH_DIR, 205);
    link_type!(FRELAY_WITH_DIR, 206);
    link_type!(LAPB_WITH_DIR, 207);
    link_type!(IPMB_LINUX, 209);
    link_type!(IEEE802_15_4_NONASK_PHY, 215);
    link_type!(USB_LINUX_MMAPPED, 220);
    link_type!(FC_2, 224);
    link_type!(FC_2_WITH_FRAME_DELIMS, 225);
    link_type!(IPNET, 226);
    link_type!(CAN_SOCKETCAN, 227);
    link_type!(IPV4, 228);
    link_type!(IPV6, 229);
    link_type!(IEEE802_15_4_NO_FCS, 230);
    link_type!(DBUS, 231);
    link_type!(DVB_CI, 235);
    link_type!(MUX27010, 236);
    link_type!(STANAG_5066_D_PDU, 237);
    link_type!(NFLOG, 239);
    link_type!(NETANALYZER, 240);
    link_type!(NETANALYZER_TRANSPARENT, 241);
    link_type!(IPOIB, 242);
    link_type!(MPEG_2_TS, 243);
    link_type!(NG40, 244);
    link_type!(NFC_LLCP, 245);
    link_type!(INFINIBAND, 247);
    link_type!(SCTP, 248);
    link_type!(USBPCAP, 249);
    link_type!(RTAC_SERIAL, 250);
    link_type!(BLUETOOTH_LE_LL, 251);
    link_type!(NETLINK, 253);
    link_type!(BLUETOOTH_LINUX_MONITOR, 254);
    link_type!(BLUETOOTH_BREDR_BB, 255);
    link_type!(BLUETOOTH_LE_LL_WITH_PHDR, 256);
    link_type!(PROFIBUS_DL, 257);
    link_type!(PKTAP, 258);
    link_type!(EPON, 259);
    link_type!(IPMI_HPM_2, 260);
    link_type!(ZWAVE_R1_R2, 261);
    link_type!(ZWAVE_R3, 262);
    link_type!(WATTSTOPPER_DLM, 263);
    link_type!(ISO_14443, 264);
    link_type!(RDS, 265);
    link_type!(USB_DARWIN, 266);
    link_type!(SDLC, 268);
    link_type!(LORATAP, 270);
    link_type!(VSOCK, 271);
    link_type!(NORDIC_BLE, 272);
    link_type!(DOCSIS31_XRA31, 273);
    link_type!(ETHERNET_MPACKET, 274);
    link_type!(DISPLAYPORT_AUX, 275);
    link_type!(LINUX_SLL2, 276);
    link_type!(OPENVIZSLA, 278);
    link_type!(EBHSCR, 279);
    link_type!(VPP_DISPATCH, 280);
    link_type!(DSA_TAG_BRCM, 281);
    link_type!(DSA_TAG_BRCM_PREPEND, 282);
    link_type!(IEEE802_15_4_TAP, 283);
    link_type!(DSA_TAG_DSA, 284);
    link_type!(DSA_TAG_EDSA, 285);
    link_type!(ELEE, 286);
    link_type!(Z_WAVE_SERIAL, 287);
    link_type!(USB_2_0, 288);
    link_type!(ATSC_ALP, 289);
}

impl PartialEq for LinkType {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for LinkType {}
