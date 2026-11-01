// No macro_rules! or #[macro_export] in the safe layer; a comment and a string naming them are no
// hit.
const NOTE: &str = "macro_rules! and #[macro_export] stay out of this crate";
