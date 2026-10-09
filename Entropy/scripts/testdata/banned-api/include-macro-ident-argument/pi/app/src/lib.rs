// A macro that takes an ident: $m!($p) expands to the include macro.
macro_rules! call { ($m:ident, $p:literal) => { $m!($p); } }
call!(include, "../../docs/snippets/nonce.rs");
