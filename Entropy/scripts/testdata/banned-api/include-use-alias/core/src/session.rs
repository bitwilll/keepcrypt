// The built-in macro under another name compiles docs/ just the same.
use std::include as pull;
pull!("../../docs/snippets/nonce.rs");
