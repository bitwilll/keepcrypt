macro_rules! assert_status {
    ($out:expr, $want:expr) => {
        assert_eq!($out[0], $want)
    };
}
