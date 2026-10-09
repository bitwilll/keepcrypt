// A macro that takes a path and adds the "!" itself.
macro_rules! pull { ($m:path) => { $m!("../../docs/snippets/nonce.rs"); } }
pull!(std::include);
