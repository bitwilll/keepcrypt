// rustfmt puts a long cfg_attr one item per line; the path line is the hit.
#[cfg_attr(
    feature = "test-sources",
    path = "../../docs/snippets/pool.rs"
)]
mod pool_impl;
