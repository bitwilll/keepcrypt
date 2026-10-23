// One call at a time: the FFI spawns no threads, and no JoinHandles exist.
// Literals are no call site and no export, and a lifetime opens no char literal.
const NOTE: &str = "no catch_unwind, #[no_mangle] or extern \"C\" fn here";
const QUOTE: char = '"';
fn first<'a>(page: &'a [u8]) -> &'a [u8] { page }
