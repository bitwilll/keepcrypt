// rustfmt puts each argument on its own line; a raw ident names the same macro.
macro_rules! call { ($m:ident, $p:literal) => { $m!($p); } }
call!(
    r#include,
    "../../docs/snippets/nonce.rs"
);
