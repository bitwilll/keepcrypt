// keepcrypt-capi is M6's (Q73): its lib.rs is no boundary in M5, so an export here is a hit.
#[unsafe(no_mangle)] pub extern "C" fn kc_call(op: u32) -> i32 { keepcrypt_guard::guarded(op, &[]).len() as i32 }
