// The integration tests call keepcrypt_capi::kc_call by its Rust path: no extern block, no export.
let n = keepcrypt_capi::kc_max_out();
