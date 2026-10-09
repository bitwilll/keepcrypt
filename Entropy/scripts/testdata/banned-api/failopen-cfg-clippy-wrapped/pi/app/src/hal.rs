// rustfmt puts each predicate of a long cfg on its own line.
#[cfg(any(
    clippy,
    feature = "bring-up-build-with-a-feature-name-long-enough-that-rustfmt-wraps-it"
))]
pub fn self_test() {}
