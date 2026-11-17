macro_rules! assert_halted {
    ($out:expr) => {
        assert_eq!($out[0], STATUS_HALTED)
    };
}
