pub unsafe fn make_string(s: *const libc::c_char) -> String {
    use std::ffi::CStr;
    if s == std::ptr::null() {
        String::new()
    } else {
        String::from(CStr::from_ptr(s).to_string_lossy())
    }
}
