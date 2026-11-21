// Tests may define macros: only ffi/src, ffi/guard/src, ffi/jni/src and ffi/capi/src refuse them
// (lead decision M5-35; M6 item B4).
macro_rules! assert_status {
    ($out:expr, $want:expr) => {
        assert_eq!($out[0], $want)
    };
}
