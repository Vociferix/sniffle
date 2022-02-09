#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

pub use libc::FILE;
#[cfg(not(windows))]
pub use libc::{sockaddr, suseconds_t, time_t, timeval};
#[cfg(windows)]
pub use winapi::shared::ws2def::SOCKADDR as sockaddr;
#[cfg(windows)]
pub use winapi::um::winnt::HANDLE;
#[cfg(windows)]
pub use winapi::um::winsock2::{timeval, SOCKET};

#[cfg(windows)]
pub type time_t = winapi::ctypes::c_long;
#[cfg(windows)]
pub type suseconds_t = winapi::ctypes::c_long;

pub const PCAP_ERRBUF_SIZE: usize = 256;
pub const PCAP_WARNING: libc::c_int = 1;
pub const PCAP_WARNING_PROMISC_NOTSUP: libc::c_int = 2;
pub const PCAP_WARNING_TSTAMP_TYPE_NOTSUP: libc::c_int = 3;
pub const PCAP_ERROR: libc::c_int = -1;
pub const PCAP_ERROR_BREAK: libc::c_int = -2;
pub const PCAP_ERROR_NOT_ACTIVATED: libc::c_int = -3;
pub const PCAP_ERROR_ACTIVATED: libc::c_int = -4;
pub const PCAP_ERROR_NO_SUCH_DEVICE: libc::c_int = -5;
pub const PCAP_ERROR_RFMON_NOTSUP: libc::c_int = -6;
pub const PCAP_ERROR_NOT_RFMON: libc::c_int = -7;
pub const PCAP_ERROR_PERM_DENIED: libc::c_int = -8;
pub const PCAP_ERROR_IFACE_NOT_UP: libc::c_int = -9;
pub const PCAP_ERROR_CANTSET_TSTAMP_TYPE: libc::c_int = -10;
pub const PCAP_ERROR_PROMISC_PERM_DENIED: libc::c_int = -11;
pub const PCAP_ERROR_TSTAMP_PRECISION_NOTSUP: libc::c_int = -12;
pub const PCAP_NETMASK_UNKNOWN: u32 = 0xFFFFFFFF;
pub const PCAP_IF_LOOPBACK: u32 = 0x00000001;
pub const PCAP_IF_UP: u32 = 0x00000002;
pub const PCAP_IF_RUNNING: u32 = 0x00000004;
pub const PCAP_IF_WIRELESS: u32 = 0x00000008;
pub const PCAP_IF_CONNECTION_STATUS: u32 = 0x00000030;
pub const PCAP_IF_CONNECTION_STATUS_UNKNOWN: u32 = 0x00000000;
pub const PCAP_IF_CONNECTION_STATUS_CONNECTED: u32 = 0x00000010;
pub const PCAP_IF_CONNECTION_STATUS_DISCONNECTED: u32 = 0x00000020;
pub const PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE: u32 = 0x00000030;
pub const PCAP_TSTAMP_HOST: libc::c_int = 0;
pub const PCAP_TSTAMP_HOST_LOWPREC: libc::c_int = 1;
pub const PCAP_TSTAMP_HOST_HIPREC: libc::c_int = 2;
pub const PCAP_TSTAMP_ADAPTER: libc::c_int = 3;
pub const PCAP_TSTAMP_ADAPTER_UNSYNCED: libc::c_int = 4;
pub const PCAP_TSTAMP_PRECISION_MICRO: libc::c_uint = 0;
pub const PCAP_TSTAMP_PRECISION_NANO: libc::c_uint = 1;
pub const PCAP_BUF_SIZE: usize = 1024;
pub const PCAP_SRC_FILE: libc::c_int = 2;
pub const PCAP_SRC_IFLOCAL: libc::c_int = 3;
pub const PCAP_SRC_IFREMOTE: libc::c_int = 4;
pub const PCAP_SRC_FILE_STRING: &[u8] = b"file://";
pub const PCAP_SRC_IF_STRING: &[u8] = b"rpcap://";
pub const PCAP_OPENFLAG_PROMISCUOUS: libc::c_int = 0x00000001;
pub const PCAP_OPENFLAG_DATATX_UDP: libc::c_int = 0x00000002;
pub const PCAP_OPENFLAG_NOCAPTURE_RPCAP: libc::c_int = 0x00000004;
pub const PCAP_OPENFLAG_NOCAPTURE_LOCAL: libc::c_int = 0x00000008;
pub const PCAP_OPENFLAG_MAX_RESPONSIVENESS: libc::c_int = 0x00000010;
pub const PCAP_D_INOUT: libc::c_int = 0;
pub const PCAP_D_IN: libc::c_int = 1;
pub const PCAP_D_OUT: libc::c_int = 2;
pub const PCAP_SAMP_NOSAMP: libc::c_int = 0;
pub const PCAP_SAMP_1_EVERY_N: libc::c_int = 1;
pub const PCAP_SAMP_FIRST_AFTER_N_MS: libc::c_int = 2;
pub const RPCAP_HOST_LIST_SIZE: usize = 1024;

#[cfg(windows)]
pub const MODE_CAPT: libc::c_int = 0;
#[cfg(windows)]
pub const MODE_STAT: libc::c_int = 1;
#[cfg(windows)]
pub const MODE_MON: libc::c_int = 2;

#[cfg(not(windows))]
pub type SOCKET = libc::c_int;

pub type pcap_direction_t = libc::c_int;

pub type pcap_handler = Option<
    unsafe extern "C" fn(
        arg1: *mut libc::c_uchar,
        arg2: *const pcap_pkthdr,
        arg3: *const libc::c_uchar,
    ),
>;

#[repr(C)]
#[derive(Debug)]
pub struct pcap {
    _unused: [u8; 0],
}
pub type pcap_t = pcap;

#[repr(C)]
#[derive(Debug)]
pub struct pcap_dumper {
    _unused: [u8; 0],
}
pub type pcap_dumper_t = pcap_dumper;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct bpf_insn {
    pub code: libc::c_ushort,
    pub jt: libc::c_uchar,
    pub jf: libc::c_uchar,
    pub k: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct bpf_program {
    pub bf_len: libc::c_uint,
    pub bf_insns: *mut bpf_insn,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct pcap_file_header {
    pub magic: u32,
    pub version_major: libc::c_ushort,
    pub version_minor: libc::c_ushort,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub linktype: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct pcap_pkthdr {
    pub ts: timeval,
    pub caplen: u32,
    pub len: u32,
}

#[cfg(not(windows))]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct pcap_stat {
    pub ps_recv: libc::c_uint,
    pub ps_drop: libc::c_uint,
    pub ps_ifdrop: libc::c_uint,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct pcap_stat {
    pub ps_recv: libc::c_uint,
    pub ps_drop: libc::c_uint,
    pub ps_ifdrop: libc::c_uint,
    pub ps_capt: libc::c_uint,
    pub ps_sent: libc::c_uint,
    pub ps_netdrop: libc::c_uint,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct pcap_if {
    pub next: *mut pcap_if,
    pub name: *mut libc::c_char,
    pub description: *mut libc::c_char,
    pub addresses: *mut pcap_addr,
    pub flags: u32,
}
pub type pcap_if_t = pcap_if;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct pcap_addr {
    pub next: *mut pcap_addr,
    pub addr: *mut sockaddr,
    pub netmask: *mut sockaddr,
    pub broadaddr: *mut sockaddr,
    pub dstaddr: *mut sockaddr,
}
pub type pcap_addr_t = pcap_addr;

#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct pcap_send_queue {
    pub maxlen: libc::c_uint,
    pub len: libc::c_uint,
    pub buffer: *mut libc::c_char,
}

#[cfg(windows)]
#[repr(transparent)]
pub struct _AirpcapHandle(libc::c_void);
#[cfg(windows)]
pub type PAirpcapHandle = *mut _AirpcapHandle;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct pcap_rmtauth {
    pub type_: libc::c_int,
    pub username: *const libc::c_char,
    pub password: *const libc::c_char,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct pcap_samp {
    pub method: libc::c_int,
    pub value: libc::c_int,
}

extern "C" {
    pub fn pcap_lookupdev(errbuf: *mut libc::c_char) -> *mut libc::c_char;
    pub fn pcap_lookupnet(
        device: *const libc::c_char,
        netp: *mut u32,
        maskp: *mut u32,
        errbuf: *mut libc::c_char,
    ) -> libc::c_int;
    pub fn pcap_create(source: *const libc::c_char, errbuf: *mut libc::c_char) -> *mut pcap_t;
    pub fn pcap_set_snaplen(p: *mut pcap_t, snaplen: libc::c_int) -> libc::c_int;
    pub fn pcap_set_promisc(p: *mut pcap_t, promisc: libc::c_int) -> libc::c_int;
    pub fn pcap_can_set_rfmon(p: *mut pcap_t) -> libc::c_int;
    pub fn pcap_set_rfmon(p: *mut pcap_t, rfmon: libc::c_int) -> libc::c_int;
    pub fn pcap_set_timeout(p: *mut pcap_t, to_ms: libc::c_int) -> libc::c_int;
    pub fn pcap_set_tstamp_type(p: *mut pcap_t, tstamp_type: libc::c_int) -> libc::c_int;
    pub fn pcap_set_immediate_mode(p: *mut pcap_t, immediate_mode: libc::c_int) -> libc::c_int;
    pub fn pcap_set_buffer_size(p: *mut pcap_t, buffer_size: libc::c_int) -> libc::c_int;
    pub fn pcap_set_tstamp_precision(p: *mut pcap_t, tstamp_precision: libc::c_int) -> libc::c_int;
    pub fn pcap_get_tstamp_precision(p: *mut pcap_t) -> libc::c_int;
    pub fn pcap_activate(p: *mut pcap_t) -> libc::c_int;
    pub fn pcap_list_tstamp_types(
        p: *mut pcap_t,
        tstamp_types: *mut *mut libc::c_int,
    ) -> libc::c_int;
    pub fn pcap_free_tstamp_types(tstamp_types: *mut libc::c_int);
    pub fn pcap_tstamp_type_name_to_val(name: *const libc::c_char) -> libc::c_int;
    pub fn pcap_tstamp_type_val_to_name(tstamp_type: libc::c_int) -> *const libc::c_char;
    pub fn pcap_tstamp_type_val_to_description(tstamp_type: libc::c_int) -> *const libc::c_char;

    #[cfg(target_os = "linux")]
    pub fn pcap_set_protocol_linux(p: *mut pcap_t, proto: libc::c_int) -> libc::c_int;

    pub fn pcap_open_live(
        device: *const libc::c_char,
        snaplen: libc::c_int,
        promisc: libc::c_int,
        to_ms: libc::c_int,
        errbuf: *mut libc::c_char,
    ) -> *mut pcap_t;
    pub fn pcap_open_dead(linktype: libc::c_int, snaplen: libc::c_int) -> *mut pcap_t;
    pub fn pcap_open_dead_with_tstamp_precision(
        linktype: libc::c_int,
        snaplen: libc::c_int,
        precision: libc::c_uint,
    ) -> *mut pcap_t;
    pub fn pcap_open_offline_with_tstamp_precision(
        fname: *const libc::c_char,
        precision: libc::c_uint,
        errbuf: *mut libc::c_char,
    ) -> *mut pcap_t;
    pub fn pcap_open_offline(fname: *const libc::c_char, errbuf: *mut libc::c_char) -> *mut pcap_t;

    #[cfg(windows)]
    pub fn pcap_hopen_offline_with_tstamp_precision(
        h: HANDLE,
        precision: libc::c_int,
        errbuf: *mut libc::c_char,
    ) -> *mut pcap_t;
    #[cfg(windows)]
    pub fn pcap_hopen_offline(h: HANDLE, errbuf: *mut libc::c_char) -> *mut pcap_t;

    #[cfg(not(windows))]
    pub fn pcap_fopen_offline_with_tstamp_precision(
        f: *mut FILE,
        precision: libc::c_int,
        errbuf: *mut libc::c_char,
    ) -> *mut pcap_t;
    #[cfg(not(windows))]
    pub fn pcap_fopen_offline(f: *mut FILE, errbuf: libc::c_char) -> *mut pcap_t;

    pub fn pcap_close(p: *mut pcap_t);
    pub fn pcap_loop(
        p: *mut pcap_t,
        cnt: libc::c_int,
        callback: pcap_handler,
        user: *mut libc::c_uchar,
    ) -> libc::c_int;
    pub fn pcap_dispatch(
        p: *mut pcap_t,
        cnt: libc::c_int,
        callback: pcap_handler,
        user: *mut libc::c_uchar,
    ) -> libc::c_int;
    pub fn pcap_next(p: *mut pcap_t, h: *mut pcap_pkthdr) -> *const libc::c_uchar;
    pub fn pcap_next_ex(
        p: *mut pcap_t,
        pkt_header: *mut *mut pcap_pkthdr,
        pkt_data: *mut *const libc::c_uchar,
    ) -> libc::c_int;
    pub fn pcap_breakloop(p: *mut pcap_t);
    pub fn pcap_stats(p: *mut pcap_t, ps: *mut pcap_stat) -> libc::c_int;
    pub fn pcap_setfilter(p: *mut pcap_t, fp: *mut bpf_program) -> libc::c_int;
    pub fn pcap_setdirection(p: *mut pcap_t, d: pcap_direction_t) -> libc::c_int;
    pub fn pcap_getnonblock(p: *mut pcap_t, errbuf: *mut libc::c_char) -> libc::c_int;
    pub fn pcap_setnonblock(
        p: *mut pcap_t,
        nonblock: libc::c_int,
        errbuf: *mut libc::c_char,
    ) -> libc::c_int;
    pub fn pcap_inject(p: *mut pcap_t, buf: *const libc::c_void, size: usize) -> libc::c_int;
    pub fn pcap_sendpacket(
        p: *mut pcap_t,
        buf: *const libc::c_uchar,
        size: libc::c_int,
    ) -> libc::c_int;
    pub fn pcap_statustostr(error: libc::c_int) -> *const libc::c_char;
    pub fn pcap_strerror(error: libc::c_int) -> *const libc::c_char;
    pub fn pcap_geterr(p: *mut pcap_t) -> *mut libc::c_char;
    pub fn pcap_perror(p: *mut pcap_t, msg: *const libc::c_char);
    pub fn pcap_compile(
        p: *mut pcap_t,
        fp: *mut bpf_program,
        prog_str: *const libc::c_char,
        optimize: libc::c_int,
        netmask: u32,
    ) -> libc::c_int;
    pub fn pcap_compile_nopcap(
        snaplen: libc::c_int,
        linktype: libc::c_int,
        fp: *mut bpf_program,
        prog_str: *const libc::c_char,
        optimize: libc::c_int,
        netmask: u32,
    ) -> libc::c_int;
    pub fn pcap_freecode(fp: *mut bpf_program);
    pub fn pcap_offline_filter(
        fp: *const bpf_program,
        h: *const pcap_pkthdr,
        pkt: *const libc::c_uchar,
    ) -> libc::c_int;
    pub fn pcap_datalink(p: *mut pcap_t) -> libc::c_int;
    pub fn pcap_datalink_ext(p: *mut pcap_t) -> libc::c_int;
    pub fn pcap_list_datalinks(p: *mut pcap_t, dlt_buf: *mut *mut libc::c_int) -> libc::c_int;
    pub fn pcap_set_datalink(p: *mut pcap_t, dlt: libc::c_int) -> libc::c_int;
    pub fn pcap_free_datalinks(dlt_list: *mut libc::c_int);
    pub fn pcap_datalink_name_to_val(name: *const libc::c_char) -> libc::c_int;
    pub fn pcap_datalink_val_to_name(dlt: libc::c_int) -> *const libc::c_char;
    pub fn pcap_datalink_val_to_description(dlt: libc::c_int) -> *const libc::c_char;
    pub fn pcap_datalink_val_to_description_or_dlt(dlt: libc::c_int) -> *const libc::c_char;
    pub fn pcap_snapshot(p: *mut pcap_t) -> libc::c_int;
    pub fn pcap_is_swapped(p: *mut pcap_t) -> libc::c_int;
    pub fn pcap_major_version(p: *mut pcap_t) -> libc::c_int;
    pub fn pcap_minor_version(p: *mut pcap_t) -> libc::c_int;
    pub fn pcap_bufsize(p: *mut pcap_t) -> libc::c_int;
    pub fn pcap_file(p: *mut pcap_t) -> *mut FILE;
    pub fn pcap_fileno(p: *mut pcap_t) -> libc::c_int;

    #[cfg(windows)]
    pub fn pcap_wsockinit();

    pub fn pcap_dump_open(p: *mut pcap_t, fname: *const libc::c_char) -> *mut pcap_dumper_t;

    #[cfg(windows)]
    pub fn pcap_dump_hopen(p: *mut pcap_t, h: HANDLE) -> *mut pcap_dumper_t;

    #[cfg(not(windows))]
    pub fn pcap_dump_fopen(p: *mut pcap_t, f: *mut FILE) -> *mut pcap_dumper_t;

    pub fn pcap_dump_open_append(p: *mut pcap_t, fname: *const libc::c_char) -> *mut pcap_dumper_t;
    pub fn pcap_dump_file(p: *mut pcap_dumper_t) -> *mut FILE;
    pub fn pcap_dump_ftell(p: *mut pcap_dumper_t) -> libc::c_long;
    pub fn pcap_dump_ftell64(p: *mut pcap_dumper_t) -> i64;
    pub fn pcap_dump_flush(p: *mut pcap_dumper_t) -> libc::c_int;
    pub fn pcap_dump_close(p: *mut pcap_dumper_t);
    pub fn pcap_dump(user: *mut libc::c_uchar, h: *mut pcap_pkthdr, sp: *mut libc::c_uchar);
    pub fn pcap_findalldevs(
        alldevsp: *mut *mut pcap_if_t,
        errbuf: *mut libc::c_char,
    ) -> libc::c_int;
    pub fn pcap_freealldevs(alldevs: *mut pcap_if_t);
    pub fn pcap_lib_version() -> *const libc::c_char;

    #[cfg(all(not(target_os = "netbsd"), not(taget_os = "qnx")))]
    pub fn bpf_filter(
        pc: *const bpf_insn,
        pkt: *const libc::c_uchar,
        dlt: libc::c_int,
        hdrlen: libc::c_int,
    ) -> libc::c_uint;
    pub fn bpf_validate(fcode: *const bpf_insn, flen: libc::c_int) -> libc::c_int;
    pub fn bpf_image(fcode: *const bpf_insn, flen: libc::c_int) -> *mut libc::c_char;
    pub fn bpf_dump(fcode: *const bpf_program, option: libc::c_int);

    #[cfg(windows)]
    pub fn pcap_setbuff(p: *mut pcap_t, dim: libc::c_int) -> libc::c_int;
    #[cfg(windows)]
    pub fn pcap_setmode(p: *mut pcap_t, mode: libc::c_int) -> libc::c_int;
    #[cfg(windows)]
    pub fn pcap_setmintocopy(p: *mut pcap_t, size: libc::c_int) -> libc::c_int;
    #[cfg(windows)]
    pub fn pcap_getevent(p: *mut pcap_t) -> HANDLE;
    #[cfg(windows)]
    pub fn pcap_oid_get_request(
        p: *mut pcap_t,
        oid: u32,
        data: *mut libc::c_void,
        lenp: *mut usize,
    ) -> libc::c_int;
    #[cfg(windows)]
    pub fn pcap_oid_set_request(
        p: *mut pcap_t,
        oid: u32,
        data: *const libc::c_void,
        lenp: *mut usize,
    ) -> libc::c_int;
    #[cfg(windows)]
    pub fn pcap_sendqueue_alloc(memsize: libc::c_uint) -> *mut pcap_send_queue;
    #[cfg(windows)]
    pub fn pcap_sendqueue_destroy(queue: *mut pcap_send_queue);
    #[cfg(windows)]
    pub fn pcap_sendqueue_queue(
        queue: *mut pcap_send_queue,
        pkt_header: *const pcap_pkthdr,
        pkt_data: *const libc::c_uchar,
    ) -> libc::c_int;
    #[cfg(windows)]
    pub fn pcap_sendqueue_transmit(
        p: *mut pcap_t,
        queue: *mut pcap_send_queue,
        sync: libc::c_int,
    ) -> libc::c_uint;
    #[cfg(windows)]
    pub fn pcap_stats_ex(p: *mut pcap_t, pcap_stat_size: *mut libc::c_int) -> *mut pcap_stat;
    #[cfg(windows)]
    pub fn pcap_setuserbuffer(p: *mut pcap_t, size: libc::c_int) -> libc::c_int;
    #[cfg(windows)]
    pub fn pcap_live_dump(
        p: *mut pcap_t,
        filename: *mut libc::c_char,
        maxsize: libc::c_int,
        maxpacks: libc::c_int,
    ) -> libc::c_int;
    #[cfg(windows)]
    pub fn pcap_live_dump_ended(p: *mut pcap_t, sync: libc::c_int) -> libc::c_int;
    #[cfg(windows)]
    pub fn pcap_start_oem(err_str: *mut libc::c_char, flags: libc::c_int) -> libc::c_int;
    #[cfg(windows)]
    pub fn pcap_get_airpcap_handle(p: *mut pcap_t) -> PAirpcapHandle;

    #[cfg(not(windows))]
    pub fn pcap_get_selectable_fd(p: *mut pcap_t) -> libc::c_int;
    #[cfg(not(windows))]
    pub fn pcap_get_required_select_timeout(p: *mut pcap_t) -> *mut timeval;

    pub fn pcap_open(
        source: *const libc::c_char,
        snaplen: libc::c_int,
        flags: libc::c_int,
        read_timeout: libc::c_int,
        auth: *mut pcap_rmtauth,
        errbuf: *mut libc::c_char,
    ) -> *mut pcap_t;
    pub fn pcap_createsrcstr(
        source: *mut libc::c_char,
        type_: libc::c_int,
        host: *const libc::c_char,
        port: *const libc::c_char,
        name: *const libc::c_char,
        errbuf: *mut libc::c_char,
    ) -> libc::c_int;
    pub fn pcap_parsesrcstr(
        source: *const libc::c_char,
        type_: libc::c_int,
        host: *mut libc::c_char,
        port: *mut libc::c_char,
        name: *mut libc::c_char,
        errbuf: *mut libc::c_char,
    ) -> libc::c_int;
    pub fn pcap_findalldevs_ex(
        source: *const libc::c_char,
        auth: *mut pcap_rmtauth,
        alldevs: *mut *mut pcap_if_t,
        errbuf: *mut libc::c_char,
    ) -> libc::c_int;
    pub fn pcap_setsampling(p: *mut pcap_t) -> *mut pcap_samp;
    pub fn pcap_remoteact_accept(
        address: *const libc::c_char,
        port: *const libc::c_char,
        hostlist: *const libc::c_char,
        connectinghost: *mut libc::c_char,
        auth: *mut pcap_rmtauth,
        errbuf: *mut libc::c_char,
    ) -> SOCKET;
    pub fn pcap_remoteact_list(
        hostlist: *mut libc::c_char,
        sep: libc::c_char,
        size: libc::c_int,
        errbuf: *mut libc::c_char,
    ) -> libc::c_int;
    pub fn pcap_remoteact_close(
        host: *const libc::c_char,
        errbuf: *mut libc::c_char,
    ) -> libc::c_int;
    pub fn pcap_remoteact_cleanup();
}

use std::fmt;

impl fmt::Debug for pcap_pkthdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pcap_pkthdr {{ ts: timeval {{ tv_sec: {}, tv_usec: {} }}, caplen: {}, len: {} }}",
            self.ts.tv_sec, self.ts.tv_usec, self.caplen, self.len
        )
    }
}

impl Default for bpf_program {
    fn default() -> Self {
        Self {
            bf_len: libc::c_uint::default(),
            bf_insns: std::ptr::null_mut(),
        }
    }
}

impl Default for pcap_pkthdr {
    fn default() -> Self {
        Self {
            ts: timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: u32::default(),
            len: u32::default(),
        }
    }
}

impl Default for pcap_if {
    fn default() -> Self {
        Self {
            next: std::ptr::null_mut(),
            name: std::ptr::null_mut(),
            description: std::ptr::null_mut(),
            addresses: std::ptr::null_mut(),
            flags: 0,
        }
    }
}

impl Default for pcap_addr {
    fn default() -> Self {
        Self {
            next: std::ptr::null_mut(),
            addr: std::ptr::null_mut(),
            netmask: std::ptr::null_mut(),
            broadaddr: std::ptr::null_mut(),
            dstaddr: std::ptr::null_mut(),
        }
    }
}

#[cfg(windows)]
impl Default for pcap_send_queue {
    fn default() -> Self {
        Self {
            maxlen: libc::c_uint::default(),
            len: libc::c_uint::default(),
            buffer: std::ptr::null_mut(),
        }
    }
}

impl Default for pcap_rmtauth {
    fn default() -> Self {
        Self {
            type_: libc::c_int::default(),
            username: std::ptr::null(),
            password: std::ptr::null(),
        }
    }
}
