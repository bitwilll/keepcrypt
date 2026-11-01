// Tests may define macros: only ffi/src, ffi/guard/src and ffi/jni/src refuse them (lead decision
// M5-35).
macro_rules! assert_status {
    ($out:expr, $want:expr) => {
        assert_eq!($out[0], $want)
    };
}
