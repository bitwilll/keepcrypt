// rustfmt splits a long use group one item per line; a raw name is still a name.
use core::{
    include as r#pull,
    mem,
};
r#pull!("../../docs/snippets/nonce.rs");
